"""`veil` command-line entry point."""

import argparse
from collections.abc import Sequence

from veil import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veil",
        description="Translate personal information into a consistent fake persona.",
    )
    parser.add_argument("--version", action="version", version=f"veil {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
