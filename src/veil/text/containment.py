"""Find bounded, case-insensitive occurrences of one form inside other text.

Matching runs on the folded text (canon rules) while boundaries are judged on the original
NFKC text, so case transitions like `janeResume` stay visible. M0 uses the naive index; M1 adds an
Aho-Corasick index and keeps this one as the test oracle.
"""

import functools
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from veil.text.boundary import is_bounded
from veil.text.normalize import canon, fold_with_map, nfkc


@dataclass(frozen=True)
class Span:
    """A match: text[start:end] of the NFKC form of the haystack."""

    start: int
    end: int


class PreparedText:
    """A haystack prepared once for repeated searches."""

    __slots__ = ("folded", "origin", "text")

    def __init__(self, raw: str) -> None:
        self.text = nfkc(raw)
        self.folded, self.origin = fold_with_map(self.text)

    @classmethod
    def from_normalized(cls, text: str) -> "PreparedText":
        """Prepare text that is already normalized by the caller (offsets stay as given)."""
        prepared = cls.__new__(cls)
        prepared.text = text
        prepared.folded, prepared.origin = fold_with_map(text)
        return prepared


@functools.lru_cache(maxsize=16384)
def prepared(text: str) -> PreparedText:
    """A cached PreparedText: validation and lexicon building prepare the same forms many times.

    PreparedText is never mutated after construction, so sharing instances is safe.
    """
    return PreparedText(text)


def find_bounded(needle: str, haystack: str | PreparedText) -> list[Span]:
    """All bounded occurrences of `needle` in `haystack`, in order (they may overlap)."""
    target = canon(needle)
    if not target:
        return []
    hay = haystack if isinstance(haystack, PreparedText) else prepared(haystack)
    spans: list[Span] = []
    pos = hay.folded.find(target)
    while pos != -1:
        span = to_original(hay, pos, pos + len(target))
        if span is not None and is_bounded(hay.text, span.start, span.end):
            spans.append(span)
        pos = hay.folded.find(target, pos + 1)
    return spans


def contains_bounded(needle: str, haystack: str | PreparedText) -> bool:
    return bool(find_bounded(needle, haystack))


def to_original(hay: PreparedText, fstart: int, fend: int) -> Span | None:
    """Map a folded match back to original characters; reject matches that split a character.

    A match must start at the first folded char of its source character and end at the last
    one (e.g. needle "s" must not match half of "ß" → "ss").
    """
    origin = hay.origin
    first, last = origin[fstart], origin[fend - 1]
    if fstart > 0 and origin[fstart - 1] == first:
        return None
    if fend < len(origin) and origin[fend] == last:
        return None
    return Span(first, last + 1)


class ContainmentIndex(Protocol):
    def containing(self, needle: str) -> list[int]:
        """Indices of the haystacks that contain `needle` bounded."""
        ...


class NaiveIndex:
    """Checks every haystack. Fine for persona-sized inputs; the oracle for faster indexes."""

    def __init__(self, haystacks: Sequence[str]) -> None:
        self._prepared = [PreparedText(h) for h in haystacks]

    def containing(self, needle: str) -> list[int]:
        return [i for i, hay in enumerate(self._prepared) if contains_bounded(needle, hay)]
