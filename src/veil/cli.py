"""`veil` command-line entry point.

`main` hardens the process, dispatches the command and maps every failure to an exit code
(ADR-0027) with a value-free message. Unexpected exceptions show their class name only.
"""

import argparse
import dataclasses
import os
import re
import sys
import time
from collections.abc import Sequence
from pathlib import Path

import veil
from veil import hardening, paths, ui
from veil.errors import Aborted, VeilError
from veil.exitcodes import ExitCode


class _VersionAction(argparse.Action):
    """Like argparse's "version", but only looks the version up when --version is given."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        ui.out(f"veil {veil.__version__}")
        parser.exit()


_REPR = r"""(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")"""


class _Parser(argparse.ArgumentParser):
    """argparse, minus echoing what was typed: a stray argument can be personal text
    (`veil translate "<your name>"`), and errors land in terminals and logs (sweep 2026-10-26).
    Subcommand parsers inherit this class."""

    def error(self, message: str):
        message = re.sub(
            r"unrecognized arguments: .*", "unrecognized arguments (not shown)", message, flags=re.S
        )
        # argparse quotes the value with repr(): '…', or "…" when it holds an apostrophe.
        message = re.sub(rf"invalid choice: {_REPR}", "invalid choice", message)
        message = re.sub(rf"invalid (\S+) value: {_REPR}", r"invalid \1 value", message)
        message = re.sub(
            r"ambiguous option: .*? could match",
            "ambiguous option, could match",
            message,
            flags=re.S,
        )
        self.print_usage(sys.stderr)
        self.exit(int(ExitCode.USAGE), f"{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="veil",
        description="Translate personal information into a consistent fake persona.",
    )
    parser.add_argument("--version", action=_VersionAction, help="show the version and exit")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    for name, help_text in (
        ("translate", "real → fake: translate text from stdin (or --file) to stdout"),
        ("reverse", "HUMAN-ONLY: fake → real (the output contains your real details)"),
        ("audit", "report real details in text by position and field path (exit 1 if any)"),
    ):
        text_cmd = commands.add_parser(name, help=help_text)
        text_cmd.add_argument("--file", type=Path, help="read this file instead of stdin")

    clip = commands.add_parser("clip", help="sanitize or restore the clipboard (plain text only)")
    clip_commands = clip.add_subparsers(dest="clip_command", metavar="SUBCOMMAND")
    for name, help_text in (
        ("sanitize", "real → fake: the clipboard, in place, as plain text only"),
        ("from-selection", "real → fake: the highlighted text (PRIMARY) into the clipboard"),
        ("restore", "HUMAN-ONLY: fake → real in the clipboard (it then holds your real details)"),
        ("paste", "sanitize the clipboard, then paste it into the focused window (Alt+V)"),
    ):
        clip_cmd = clip_commands.add_parser(name, help=help_text)
        clip_cmd.add_argument(
            "--no-notify",
            action="store_true",
            help="no desktop notification (stderr only); a sensitive detail is then asked "
            "about in the terminal, or denied without one",
        )

    on = commands.add_parser("on", help="veil ON: every copy is sanitized (Meta+Alt+K)")
    off = commands.add_parser(
        "off",
        help="HUMAN-ONLY: veil OFF: copy and paste are normal (asks you to type 'off')",
    )
    toggle = commands.add_parser(
        "toggle", help="ON if off; OFF if on (HUMAN-ONLY: asks for confirmation)"
    )
    for cmd in (off, toggle):
        cmd.add_argument(
            "--from-hotkey",
            action="store_true",
            help="confirm switching OFF with one click in a notification instead of the "
            "terminal (for the hotkey); no click within 30 s = veil stays ON",
        )
    for cmd in (on, toggle):
        cmd.add_argument(
            "--for",
            dest="duration",
            type=_duration,
            metavar="DURATION",
            help="switch OFF by itself after this long (e.g. 30m, 2h; up to 24h)",
        )
    commands.add_parser("status", help="ON or OFF (exit 0 = on, 3 = off)")
    timer = commands.add_parser("kill-switch-timer")  # run by systemd timers; not listed
    timer.add_argument("event", choices=("expire", "remind", "stopped", "check"))

    shortcuts = commands.add_parser(
        "install-shortcuts",
        help="set up the KDE Plasma hotkeys (Meta+Alt+V/C/E/K, Alt+V, Alt+Shift+V) as System "
        "Settings would",
    )
    shortcuts.add_argument(
        "--key",
        action="append",
        default=[],
        metavar="NAME=KEYS",
        help="use another key, e.g. --key restore=Meta+Alt+X (names: sanitize, from-selection, "
        "restore, toggle, paste, paste-terminal; repeatable)",
    )
    mode = shortcuts.add_mutually_exclusive_group()
    mode.add_argument("--remove", action="store_true", help="remove veil's hotkeys again")
    mode.add_argument(
        "--print", action="store_true", help="only print the manual steps; change nothing"
    )
    mode.add_argument(
        "--status",
        action="store_true",
        help="show what is installed and which key KDE really has (read-only)",
    )

    paste = clip_commands.choices["paste"]
    paste.add_argument(
        "--terminal", action="store_true", help="paste with Ctrl+Shift+V (terminals)"
    )
    # Run by the copy watcher after every clipboard change (veil ON; ADR-0031): not listed.
    clip_commands.choices["sanitize"].add_argument(
        "--auto", action="store_true", help=argparse.SUPPRESS
    )
    clip_commands.add_parser("watch")  # the veil-watch service's command; not listed

    persona = commands.add_parser("persona", help="manage your persona")
    persona_commands = persona.add_subparsers(dest="persona_command", metavar="SUBCOMMAND")
    check = persona_commands.add_parser(
        "check",
        help="validate a persona (reports field paths only, never values)",
    )
    check.add_argument(
        "--file", type=Path, help="check a plaintext persona YAML file instead of the encrypted one"
    )
    check.add_argument("--strict", action="store_true", help="treat warnings as errors")
    check.add_argument("--format", choices=("text", "json"), default="text")

    imp = persona_commands.add_parser(
        "import",
        help="validate and encrypt a persona file (the file itself is left in place)",
    )
    imp.add_argument("file", type=Path, help="the plaintext persona YAML file")
    imp.add_argument(
        "--replace", action="store_true", help="overwrite an existing encrypted persona"
    )
    imp.add_argument(
        "--key-backend",
        # v0.1 offers the desktop keyring only (board Q4). Passphrase mode exists in the code and
        # is tested, but needs a GUI prompt before it can work with hotkeys (ADR-0025 amendment).
        choices=("keyring",),
        help="where to keep the key on first import (v0.1: keyring only)",
    )
    imp.add_argument(
        "--shred",
        action="store_true",
        help="afterwards overwrite and delete the plaintext file (asks you to type 'shred')",
    )

    persona_commands.add_parser(
        "status", help="safe diagnostics: store, key, runtime dir, swap (no values)"
    )

    edit = persona_commands.add_parser(
        "edit",
        help="HUMAN-ONLY: edit the encrypted persona in a hardened editor (shows real values)",
    )
    edit.add_argument(
        "--allow-unknown-editor",
        action="store_true",
        help="allow an editor veil cannot harden (it may leave copies outside the session)",
    )
    drafts = edit.add_mutually_exclusive_group()
    drafts.add_argument(
        "--resume-draft",
        action="store_true",
        help="continue the encrypted draft of an unsaved edit",
    )
    drafts.add_argument(
        "--discard-draft", action="store_true", help="delete the encrypted draft, then edit"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    report = hardening.apply()
    if not report.complete:
        # Never silent. Not enforced: decrypting commands still run (a warning only); refusing
        # them is TODO-later (sweep 2026-10-26 found the old comment claimed otherwise).
        ui.err(
            "veil: warning: process hardening incomplete "
            f"(umask={report.umask_set}, core_dumps_off={report.core_dumps_disabled}, "
            f"non_dumpable={report.non_dumpable})"
        )
    try:
        return run(argv)
    except VeilError as error:
        ui.report_error(error)
        return int(error.exit_code)
    except KeyboardInterrupt:
        ui.err("veil: interrupted")
        return int(ExitCode.INTERRUPTED)
    except Exception as exc:  # noqa: BLE001 - last line of defence: never print exception text
        ui.report_internal_error(type(exc))
        return int(ExitCode.INTERNAL)


def run(argv: Sequence[str] | None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in ("translate", "reverse", "audit"):
        return _text_command(args)
    if args.command == "install-shortcuts":
        return _shortcuts_command(args)
    if args.command in ("on", "off", "toggle", "status", "kill-switch-timer"):
        return _switch_command(args)
    if args.command == "clip" and args.clip_command:
        return _clip_command(args)
    if args.command == "clip":
        parser.parse_args(["clip", "--help"])
    if args.command == "persona" and args.persona_command == "check":
        return _persona_check(args)
    if args.command == "persona" and args.persona_command == "import":
        return _persona_import(args)
    if args.command == "persona" and args.persona_command == "status":
        return _persona_status()
    if args.command == "persona" and args.persona_command == "edit":
        return _persona_edit(args)
    if args.command == "persona":
        parser.parse_args(["persona", "--help"])
    parser.print_help()
    return int(ExitCode.OK)


def _persona_check(args: argparse.Namespace) -> int:
    # Imported lazily: keeps `veil --version` and the hotkey path fast.
    from veil.persona.check import check_file, check_store

    if args.file is not None:
        return check_file(args.file, strict=args.strict, fmt=args.format)
    keystore, store = _stores()
    return check_store(
        keystore, store, ask_passphrase=_ask_passphrase, strict=args.strict, fmt=args.format
    )


def _persona_import(args: argparse.Namespace) -> int:
    from veil.crypto.keystore import KeyBackend
    from veil.persona.importer import SHRED_WORD, Prompts, import_persona

    keystore, store = _stores()
    prompts = Prompts(
        passphrase=_ask_passphrase,
        new_passphrase=lambda: ui.new_secret("New passphrase for the veil key"),
        confirm_shred=lambda: ui.confirm_typed(
            "Overwrite and delete the plaintext persona file?", SHRED_WORD
        ),
    )
    result = import_persona(
        args.file,
        keystore=keystore,
        store=store,
        prompts=prompts,
        replace=args.replace,
        backend=KeyBackend(args.key_backend) if args.key_backend else None,
        shred=args.shred,
    )
    key = f"; new key stored ({result.created_key.value})" if result.created_key else ""
    action = "replaced" if result.replaced else "imported"
    ui.out(f"veil: persona {action} and encrypted ({result.warnings} warning(s)){key}")
    _prewarm(keystore, store)
    return int(ExitCode.OK)


def _persona_status() -> int:
    from veil.persona.status import persona_status

    keystore, store = _stores()
    return persona_status(keystore, store)


def _persona_edit(args: argparse.Namespace) -> int:
    from veil.persona.edit import edit_persona

    keystore, store = _stores()
    result = edit_persona(
        keystore=keystore,
        store=store,
        ask_passphrase=_ask_passphrase,
        allow_unknown_editor=args.allow_unknown_editor,
        resume_draft=args.resume_draft,
        discard_draft=args.discard_draft,
    )
    if result.saved:
        ui.out(f"veil: persona saved and encrypted ({result.warnings} warning(s))")
        _prewarm(keystore, store)
    return int(ExitCode.OK)


def _prewarm(keystore, store) -> None:
    """Build the lexicon cache now (ADR-0029), so the next translate is warm.

    Best effort and silent: the store lock is already released, nothing is printed, and any
    failure (locked wallet, passphrase mode without a prompt, full disk) just leaves the cache
    to be built on the next translate.
    """
    from veil.engine.load import load_engine

    try:
        load_engine(keystore, store)
    except Exception:  # noqa: BLE001 - an optimization must never turn a success into a failure
        return


def _text_command(args: argparse.Namespace) -> int:
    from veil import textcmd
    from veil.engine.load import load_engine

    def load():
        keystore, store = _stores()
        return load_engine(keystore, store, ask_passphrase=_ask_passphrase)

    command = {"translate": textcmd.translate, "reverse": textcmd.reverse, "audit": textcmd.audit}
    return command[args.command](load, args.file)


def _duration(text: str):
    from veil.killswitch import parse_duration

    try:
        return parse_duration(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _switch_command(args: argparse.Namespace) -> int:
    """veil ON / OFF (ADR-0031): ON = the copy watcher sanitizes every copy. Switching OFF is a
    human decision: a typed 'off' at a terminal, or one click from the hotkey."""
    from veil import killswitch
    from veil.clip import notify

    config, now = paths.config_dir(), killswitch.utc_now()
    watcher = killswitch.detect_watcher()
    reading = killswitch.read(config, watcher)
    if reading.problem:
        ui.err(f"veil: warning: {reading.problem}")
    if args.command == "status":
        ui.out(killswitch.status_line(reading, now))
        return int(ExitCode.OK if reading.is_on(now) else ExitCode.OFF)
    timers = killswitch.detect_timers()
    if args.command == "kill-switch-timer":
        message = killswitch.on_timer(args.event, config, watcher, timers, now)
        if message is not None:
            notify.detect().notify(message)
        return int(ExitCode.OK)
    turn_on = args.command == "on" or (args.command == "toggle" and not reading.watching)
    if turn_on:
        switch, scheduled = killswitch.switch_on(
            config, watcher, timers, now, getattr(args, "duration", None)
        )
        ui.out(killswitch.status_line(killswitch.Reading(switch, True), now))
        if not scheduled:
            ui.err(
                "veil: warning: couldn't schedule the end-time timer; the first copy after the "
                "end time switches veil OFF"
            )
        notify.detect().notify(killswitch.on_message(switch, now))
        return int(ExitCode.OK)
    if not reading.watching and not reading.switch.on:
        ui.out("veil: OFF (it already was)")
        return int(ExitCode.OK)
    if args.from_hotkey:
        # A click in a notification: a person at the desktop (ADR-0018). An agent running this
        # only pops up the question; it can't click it.
        choose = killswitch.detect_chooser()
        if choose is None:
            raise Aborted("can't ask for confirmation (notify-send is missing); veil stays ON")
        if not killswitch.confirm_by_notification(choose):
            raise Aborted("not switched off (Switch OFF wasn't clicked); veil stays ON")
    elif not ui.confirm_typed("Switch veil OFF? Copies won't be sanitized any more.", "off"):
        raise Aborted("not switched off (confirmation not given); veil stays ON")
    killswitch.switch_off(config, watcher, timers)
    ui.out("veil: OFF, copy and paste are normal")
    notify.detect().notify(killswitch.off_message())
    return int(ExitCode.OK)


def _shortcuts_command(args: argparse.Namespace) -> int:
    """KDE Plasma 6 hotkeys (spec §4.1, ADR-0023 amendment 3)."""
    from veil import shortcuts

    overrides = {}
    for item in args.key:
        name, sep, keys = item.partition("=")
        if not sep or not keys.strip():
            raise VeilError(
                "--key needs NAME=KEYS, e.g. restore=Meta+Alt+E", exit_code=ExitCode.USAGE
            )
        overrides[name.strip()] = keys
    try:
        chosen = shortcuts.with_keys(overrides)
    except (ValueError, KeyError) as exc:
        raise VeilError(f"--key: {exc}", exit_code=ExitCode.USAGE) from None
    if args.print:
        for line in shortcuts.manual_steps(chosen=chosen):
            ui.out(line)
        return int(ExitCode.OK)
    bus = shortcuts.JeepneyShortcuts() if os.environ.get("DBUS_SESSION_BUS_ADDRESS") else None
    try:
        if bus is not None and not _bus_running(bus):
            bus.close()
            bus = None
        if args.status:
            rows = shortcuts.status(bus)
            for row in rows:
                live = ", ".join(row.live_keys) or "none"
                state = "ok" if row.ok else "NOT WORKING"
                ui.out(
                    f"  {row.shortcut.name:<15} file: {row.file_keys or 'missing':<11} "
                    f"KDE: {live:<11} {state}"
                )
            if bus is None:
                ui.err("veil: KDE's shortcut service isn't reachable; only files were checked")
            return int(ExitCode.OK if all(r.ok for r in rows) else ExitCode.FINDINGS)
        rebuild = shortcuts.kbuildsycoca()
        if args.remove:
            shortcuts.remove(bus, rebuild)
            ui.out("veil: hotkeys removed")
            return int(ExitCode.OK)
        if bus is None:
            ui.err(
                "veil: KDE's shortcut service isn't running (not a Plasma session?). "
                "Set them up by hand:"
            )
            for line in shortcuts.manual_steps(chosen=chosen):
                ui.err(line)
            return int(ExitCode.UNSAFE_ENVIRONMENT)
        reports = shortcuts.install(bus, rebuild, chosen=chosen)
    finally:
        if bus is not None:
            bus.close()
    for report in reports:
        ui.out(f"  {report.shortcut.keys:<11} {report.result.value:<18} {report.shortcut.title}")
    missing = [r for r in reports if r.result is not shortcuts.Result.INSTALLED]
    if missing:
        ui.err(
            f"veil: {len(missing)} hotkey(s) not set up. Choose another key with "
            "`veil install-shortcuts --key NAME=KEYS` (e.g. --key restore=Meta+Alt+E), "
            "or add them by hand (`veil install-shortcuts --print`)."
        )
        return int(ExitCode.FINDINGS)
    return int(ExitCode.OK)


def _bus_running(bus) -> bool:
    try:
        return bus.running()
    except Exception:  # noqa: BLE001 - no usable session bus
        return False


def _clip_command(args: argparse.Namespace) -> int:
    started = time.monotonic()  # ≈ the hotkey press (paste waits for its keys to be up)
    from veil.clip import commands, history, messages, notify, watch
    from veil.clip.io import detect
    from veil.engine.load import load_engine
    from veil.timing import STAGES

    if args.clip_command == "watch":
        watch.run()  # replaces this process with wl-paste --watch
        return int(ExitCode.OK)  # only when execv is faked (tests)

    def load():
        keystore, store = _stores()
        return load_engine(keystore, store, ask_passphrase=_ask_passphrase)

    auto = args.clip_command == "sanitize" and args.auto
    if auto:
        watch.drain_stdin()
    board = None
    try:
        board = detect()
        if args.clip_command == "restore":
            outcome = commands.restore(board, load)
        elif args.clip_command == "from-selection":
            outcome = commands.from_selection(board, load, _asker(args.no_notify), history.detect())
        else:  # sanitize, paste
            # No history rebuild inside watcher runs: its re-adds are clipboard changes that
            # would wake the watcher again. Picking an entry from the history while veil is ON
            # is itself a copy, so it gets sanitized anyway (sweep 2026-10-26).
            forget = None if auto else history.detect()
            outcome = commands.sanitize(board, load, _asker(args.no_notify), forget, auto=auto)
    except (Exception, KeyboardInterrupt) as error:
        # Fail closed (M2.5, spec §4.4), then let `main` report the error and pick the exit code.
        scrub = None if args.clip_command == "restore" else commands.fail_closed(board)
        ui.err(messages.error_line(scrub))
        if not args.no_notify:
            notify.detect().notify(messages.error_notification(messages.error_detail(error), scrub))
        raise
    if args.clip_command == "paste":
        from veil.clip import paste

        if paste.should_paste(outcome):
            outcome = dataclasses.replace(
                outcome,
                pasted=paste.inject(
                    paste.chord(args.terminal), config=paths.config_dir(), started=started
                ),
            )
    for line in messages.stderr_lines(outcome):
        ui.err(line)
    if not args.no_notify and messages.worth_notifying(outcome, auto=auto):
        notify.detect().notify(messages.notification(outcome))
    if auto:
        _end_if_due(args.no_notify)
    STAGES.report()
    return int(ExitCode.OK)


def _end_if_due(no_notify: bool) -> None:
    """After a watcher run: if the ON time the user chose is up, switch OFF and say so. The copy
    that triggered this run was still sanitized. The watcher service is stopped last: stopping
    it ends this process too."""
    from veil import killswitch
    from veil.clip import notify

    config = paths.config_dir()
    switch, _ = killswitch.read_switch(config)
    if not switch.expired(killswitch.utc_now()):
        return
    killswitch.write(config, killswitch.OFF)
    killswitch.detect_timers().cancel()
    ui.err("veil: OFF (its time is up); copy and paste are normal")
    if not no_notify:
        notify.detect().notify(killswitch.off_message(expired=True))
    killswitch.detect_watcher().stop()


def _asker(no_notify: bool):
    """How to ask before sending a sensitive detail (ADR-0012). No way to ask means Deny."""
    from veil.clip import ask

    if not no_notify:
        return ask.detect()
    if ui.stdin_is_tty() and ui.stdout_is_tty():
        return ask.TerminalAsker()
    return ask.deny_all


def _stores():
    from veil.crypto.keystore import KeyStore
    from veil.persona.store import PersonaStore

    config = paths.config_dir()
    return KeyStore(config), PersonaStore(config)


def _ask_passphrase() -> str:
    return ui.prompt_secret("Passphrase for the veil key")
