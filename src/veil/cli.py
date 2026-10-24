"""`veil` command-line entry point.

`main` hardens the process, dispatches the command and maps every failure to an exit code
(ADR-0027) with a value-free message. Unexpected exceptions show their class name only.
"""

import argparse
from collections.abc import Sequence
from pathlib import Path

from veil import __version__, hardening, paths, ui
from veil.errors import VeilError
from veil.exitcodes import ExitCode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veil",
        description="Translate personal information into a consistent fake persona.",
    )
    parser.add_argument("--version", action="version", version=f"veil {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

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
        choices=("keyring", "file"),
        help="where to keep the key on first import (default: keyring)",
    )
    imp.add_argument(
        "--shred",
        action="store_true",
        help="afterwards overwrite and delete the plaintext file (asks you to type 'shred')",
    )

    persona_commands.add_parser(
        "status", help="safe diagnostics: store, key, runtime dir, swap (no values)"
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
    if args.command == "persona" and args.persona_command == "check":
        return _persona_check(args)
    if args.command == "persona" and args.persona_command == "import":
        return _persona_import(args)
    if args.command == "persona" and args.persona_command == "status":
        return _persona_status()
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
    return int(ExitCode.OK)


def _persona_status() -> int:
    from veil.persona.status import persona_status

    keystore, store = _stores()
    return persona_status(keystore, store)


def _stores():
    from veil.crypto.keystore import KeyStore
    from veil.persona.store import PersonaStore

    config = paths.config_dir()
    return KeyStore(config), PersonaStore(config)


def _ask_passphrase() -> str:
    return ui.prompt_secret("Passphrase for the veil key")
