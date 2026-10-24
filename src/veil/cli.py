"""`veil` command-line entry point.

`main` hardens the process, dispatches the command and maps every failure to an exit code
(ADR-0027) with a value-free message. Unexpected exceptions show their class name only.
"""

import argparse
from collections.abc import Sequence
from pathlib import Path

from veil import __version__, hardening, ui
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
    check.add_argument("--file", type=Path, help="a plaintext persona YAML file to check")
    check.add_argument("--strict", action="store_true", help="treat warnings as errors")
    check.add_argument("--format", choices=("text", "json"), default="text")
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
    if args.command == "persona":
        parser.parse_args(["persona", "--help"])
    parser.print_help()
    return int(ExitCode.OK)


def _persona_check(args: argparse.Namespace) -> int:
    from veil.persona.check import check_file  # imported lazily: keeps `veil --version` fast

    if args.file is None:
        raise VeilError(
            "no encrypted persona store yet; use --file PATH (store support arrives in T11)",
            exit_code=ExitCode.USAGE,
        )
    return check_file(args.file, strict=args.strict, fmt=args.format)
