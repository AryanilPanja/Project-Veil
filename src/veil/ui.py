"""The only module allowed to write to the terminal (ADR-0027).

Messages must contain field paths, codes and counts only, never persona values.
"""

import sys


def out(message: str) -> None:
    print(message)


def err(message: str) -> None:
    print(message, file=sys.stderr)
