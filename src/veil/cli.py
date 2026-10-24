"""`veil` command-line entry point.

`main` hardens the process, dispatches the command and maps every failure to an exit code
(ADR-0027) with a value-free message. Unexpected exceptions show their class name only.
"""

import argparse
from collections.abc import Sequence

from veil import __version__, hardening, ui
from veil.errors import VeilError
from veil.exitcodes import ExitCode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veil",
        description="Translate personal information into a consistent fake persona.",
    )
    parser.add_argument("--version", action="version", version=f"veil {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    hardening.apply()
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
    parser.parse_args(argv)
    parser.print_help()
    return int(ExitCode.OK)
