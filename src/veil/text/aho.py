"""Aho-Corasick pattern index (M1.3): every bounded occurrence of many patterns in one pass.

Same semantics as calling M0's `find_bounded(pattern, text)` once per pattern (the test oracle):
- patterns and text are compared in canon form (NFKC, invisible format characters dropped,
  casefolded, whitespace runs collapsed);
- a hit must cover whole source characters (no matching half of "ß" → "ss");
- a hit must be bounded on both sides (ADR-0026), judged on the NFKC text.

Spans are offsets into the NFKC text, like M0's. Hits are returned for every pattern, including
overlapping ones; choosing among them (leftmost-longest, context guards) is the matcher's job.
"""

from collections.abc import Sequence
from dataclasses import dataclass

import ahocorasick

from veil.text.boundary import is_bounded
from veil.text.containment import PreparedText, prepared, to_original
from veil.text.normalize import canon


@dataclass(frozen=True, slots=True, order=True)
class Hit:
    start: int  # NFKC offsets
    end: int
    pattern: int  # index into the patterns given to PatternIndex


class PatternIndex:
    """Build once from patterns; `find` any number of texts."""

    def __init__(self, patterns: Sequence[str]) -> None:
        self.size = len(patterns)
        keys: dict[str, list[int]] = {}
        for i, pattern in enumerate(patterns):
            key = canon(pattern)
            if key:
                keys.setdefault(key, []).append(i)
        self._automaton: ahocorasick.Automaton | None = None
        if keys:
            automaton = ahocorasick.Automaton(ahocorasick.STORE_ANY, ahocorasick.KEY_STRING)
            for key, ids in keys.items():
                automaton.add_word(key, (len(key), tuple(ids)))
            automaton.make_automaton()
            self._automaton = automaton

    def __repr__(self) -> str:
        return f"PatternIndex(patterns={self.size})"

    def find(self, text: str | PreparedText) -> list[Hit]:
        """All bounded hits, sorted by (start, end, pattern)."""
        if self._automaton is None:
            return []
        hay = text if isinstance(text, PreparedText) else prepared(text)
        if not hay.folded:
            return []
        hits: list[Hit] = []
        for last, (length, ids) in self._automaton.iter(hay.folded):
            span = to_original(hay, last - length + 1, last + 1)
            if span is None or not is_bounded(hay.text, span.start, span.end):
                continue
            hits.extend(Hit(span.start, span.end, i) for i in ids)
        hits.sort()
        return hits


def containment_pairs(needles: Sequence[str], haystacks: Sequence[str]) -> dict[int, list[int]]:
    """For each needle index, the (sorted) haystack indices that contain it bounded.

    Equivalent to `NaiveIndex(haystacks).containing(needle)` for every needle, in one pass per
    haystack instead of one pass per needle-haystack pair.
    """
    index = PatternIndex(needles)
    found: dict[int, set[int]] = {}
    for j, haystack in enumerate(haystacks):
        for hit in index.find(haystack):
            found.setdefault(hit.pattern, set()).add(j)
    return {i: sorted(js) for i, js in found.items()}
