"""`veil` command-line entry point.

`main` hardens the process, dispatches the command and maps every failure to an exit code
(ADR-0027) with a value-free message. Unexpected exceptions show their class name only.
"""

import argparse
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
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
    ):
        clip_cmd = clip_commands.add_parser(name, help=help_text)
        clip_cmd.add_argument(
            "--no-notify",
            action="store_true",
            help="no desktop notification (stderr only); a sensitive detail is then asked "
            "about in the terminal, or denied without one",
        )

    commands.add_parser("on", help="switch veil back ON (the kill switch)")
    off = commands.add_parser(
        "off",
        help="HUMAN-ONLY: switch veil OFF; clipboard hotkeys stop sanitizing "
        "(asks you to type 'off')",
    )
    toggle = commands.add_parser(
        "toggle", help="HUMAN-ONLY: OFF if on (asks you to type 'off'), ON if off"
    )
    for cmd in (off, toggle):
        cmd.add_argument(
            "--for",
            dest="duration",
            type=_duration,
            metavar="DURATION",
            help="switch back ON automatically after this long (e.g. 30m, 2h; up to 24h)",
        )
    commands.add_parser("status", help="ON or OFF (exit 0 = on, 3 = off)")
    timer = commands.add_parser("kill-switch-timer")  # run by systemd timers; not listed
    timer.add_argument("event", choices=("expire", "remind"))

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
        # Never silent. Commands that decrypt the persona (T9+) will refuse to run in this state.
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
    """The kill switch (ADR-0018). OFF only ever by a human at a terminal (typed 'off')."""
    from veil import killswitch
    from veil.clip import notify

    config, now = paths.config_dir(), killswitch.utc_now()
    reading = killswitch.read(config)
    if reading.problem:
        ui.err(f"veil: warning: {reading.problem}")
    if args.command == "status":
        ui.out(killswitch.status_line(reading, now))
        return int(ExitCode.OFF if reading.switch.is_off(now) else ExitCode.OK)
    timers = killswitch.detect_timers()
    if args.command == "kill-switch-timer":
        message = killswitch.on_timer(args.event, config, timers, now)
        if message is not None:
            notify.detect().notify(message)
        return int(ExitCode.OK)
    turn_off = args.command == "off" or (
        args.command == "toggle" and not reading.switch.is_off(now)
    )
    if not turn_off:
        was_off = reading.switch.is_off(now)
        killswitch.switch_on(config, timers)
        ui.out("veil: ON" if was_off or reading.problem else "veil: ON (it already was)")
        if was_off:
            notify.detect().notify(killswitch.on_message())
        return int(ExitCode.OK)
    if not ui.confirm_typed(
        "Switch veil OFF? Clipboard hotkeys will stop sanitizing copied text.", "off"
    ):
        raise Aborted("not switched off (confirmation not given); veil stays ON")
    switch, scheduled = killswitch.switch_off(config, timers, now, args.duration)
    ui.out(killswitch.status_line(killswitch.Reading(switch), now))
    if not scheduled:
        ui.err(
            "veil: warning: couldn't schedule the reminder/expiry notifications "
            "(systemd user timers); veil still switches back ON on time when it's next used"
        )
    notify.detect().notify(killswitch.off_message(switch, now))
    return int(ExitCode.OK)


def _clip_command(args: argparse.Namespace) -> int:
    from veil.clip import commands, history, messages, notify
    from veil.clip.io import detect
    from veil.engine.load import load_engine
    from veil.timing import STAGES

    def load():
        keystore, store = _stores()
        return load_engine(keystore, store, ask_passphrase=_ask_passphrase)

    off = _switched_off()
    if off:
        action = {
            "sanitize": commands.Action.SANITIZE,
            "from-selection": commands.Action.FROM_SELECTION,
        }
        outcome = commands.Outcome(
            action.get(args.clip_command, commands.Action.RESTORE), commands.Skip.OFF
        )
        for line in messages.stderr_lines(outcome):
            ui.err(line)
        if not args.no_notify:
            notify.detect().notify(messages.notification(outcome))
        return int(ExitCode.OK)
    board = None
    try:
        board = detect()
        if args.clip_command == "restore":
            outcome = commands.restore(board, load)
        else:
            forward = {"sanitize": commands.sanitize, "from-selection": commands.from_selection}
            outcome = forward[args.clip_command](
                board, load, _asker(args.no_notify), history.detect()
            )
    except (Exception, KeyboardInterrupt) as error:
        # Fail closed (M2.5, spec §4.4), then let `main` report the error and pick the exit code.
        scrub = None if args.clip_command == "restore" else commands.fail_closed(board)
        ui.err(messages.error_line(scrub))
        if not args.no_notify:
            notify.detect().notify(messages.error_notification(messages.error_detail(error), scrub))
        raise
    for line in messages.stderr_lines(outcome):
        ui.err(line)
    if not args.no_notify:
        notify.detect().notify(messages.notification(outcome))
    STAGES.report()
    return int(ExitCode.OK)


def _switched_off() -> bool:
    """The kill switch, for the clip commands. An unreadable state file means ON (warned)."""
    from veil import killswitch

    reading = killswitch.read(paths.config_dir())
    if reading.problem:
        ui.err(f"veil: warning: {reading.problem}")
    return reading.switch.is_off(killswitch.utc_now())


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
