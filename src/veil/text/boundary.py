"""Word-boundary rule shared by the validator and the matcher (ADR-0026).

A form occurring in a text is *bounded* on a side when any of these holds:
  1. the form's edge character on that side is "other" (punctuation, space, symbol);
  2. there is no neighbour (start or end of the text);
  3. the neighbour's class (letter / digit / other) differs from the edge character's class;
  4. both are letters of different scripts (Latin next to Bengali);
  5. there is a lower→Upper case transition across the edge (`janeResume`, `myJane`).

Combining marks (Unicode M*) count as letters, so Indic vowel signs never split a word.
Digit next to digit is never a boundary: `2021` does not occur bounded inside `20217`.
"""

import unicodedata
from enum import Enum


class CharClass(Enum):
    LETTER = "letter"
    DIGIT = "digit"
    OTHER = "other"


def char_class(ch: str) -> CharClass:
    category = unicodedata.category(ch)
    if category[0] in ("L", "M"):
        return CharClass.LETTER
    if category[0] == "N":
        return CharClass.DIGIT
    return CharClass.OTHER


def script(ch: str) -> str:
    """Heuristic script name: the first word of the Unicode name (LATIN, BENGALI, …)."""
    name = unicodedata.name(ch, "")
    return name.split(" ", 1)[0] if name else "UNKNOWN"


def is_bounded(text: str, start: int, end: int) -> bool:
    """Is text[start:end] bounded on both sides? Indices are into `text` (NFKC, original case)."""
    if not 0 <= start < end <= len(text):
        return False
    left = text[start - 1] if start > 0 else None
    right = text[end] if end < len(text) else None
    return _side_ok(edge=text[start], neighbour=left, neighbour_is_left=True) and _side_ok(
        edge=text[end - 1], neighbour=right, neighbour_is_left=False
    )


def _side_ok(*, edge: str, neighbour: str | None, neighbour_is_left: bool) -> bool:
    if neighbour is None:
        return True
    edge_class = char_class(edge)
    if edge_class is CharClass.OTHER:
        return True
    if char_class(neighbour) is not edge_class:
        return True
    if edge_class is CharClass.DIGIT:
        return False
    if script(neighbour) != script(edge):
        return True
    lower, upper = (neighbour, edge) if neighbour_is_left else (edge, neighbour)
    return lower.islower() and upper.isupper()
