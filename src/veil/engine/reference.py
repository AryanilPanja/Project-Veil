"""Reference translator: slow, obviously correct, and the test oracle for the real matcher.

Semantics (spec v0.2 §5.3), deliberately naive:
- candidates: every bounded occurrence of every form (M0 `find_bounded`, case-insensitive);
- a form whose entity has `contexts` counts only if a context keyword occurs (bounded) within
  the entity's window, measured in length-independent units (context.py);
- a candidate overlapping an occurrence of a `never_translate` (forward) or `never_reverse`
  (reverse) phrase is skipped ("Thakur" inside "Anurag Thakur" stays);
- a candidate that would split a base character from its combining marks is skipped;
- leftmost-longest: sort by (start, -length) and take non-overlapping candidates greedily;
- each match is replaced by `variant.fake_for(matched text)` (keeps the case pattern).

Works on the NFKC form of the input and returns NFKC text. The production matcher (M1.4) maps
spans back to the raw input instead, so it never normalizes untouched text.
"""

import unicodedata
from dataclasses import dataclass

from veil.engine.context import Distances, context_near, overlaps_any
from veil.engine.lexicon import Form, Lexicon
from veil.text.containment import PreparedText, find_bounded


@dataclass(frozen=True, slots=True)
class Match:
    start: int
    end: int
    form: Form


def forward(text: str, lexicon: Lexicon) -> str:
    return _apply(text, lexicon.forward, lexicon.never_translate)


def reverse(text: str, lexicon: Lexicon) -> str:
    return _apply(text, lexicon.reverse, lexicon.never_reverse | lexicon.never_translate)


def matches(text: str, forms: tuple[Form, ...], skip: frozenset[str]) -> tuple[str, list[Match]]:
    """(the NFKC text, chosen matches in order)."""
    prepared = PreparedText(text)
    protected = [(s.start, s.end) for phrase in skip for s in find_bounded(phrase, prepared)]
    candidates: list[Match] = []
    for form in forms:
        for span in find_bounded(form.variant.real, prepared):
            if overlaps_any(span.start, span.end, protected):
                continue
            if _splits_cluster(prepared.text, span.start, span.end):
                continue  # never edit half of a base character + combining marks
            candidates.append(Match(span.start, span.end, form))
    candidates.sort(key=lambda m: (m.start, -(m.end - m.start)))
    # Context guards, measured in units over the spans the unguarded forms replace.
    unguarded: list[tuple[int, int]] = []
    cursor = 0
    for m in candidates:
        if not m.form.entity.contexts and m.start >= cursor:
            unguarded.append((m.start, m.end))
            cursor = m.end
    distances = Distances(len(prepared.text), unguarded)
    found: dict[str, list] = {}
    candidates = [
        m
        for m in candidates
        if context_near(prepared, m.start, m.end, m.form.entity, distances, found)
    ]
    chosen: list[Match] = []
    cursor = 0
    for m in candidates:
        if m.start >= cursor:
            chosen.append(m)
            cursor = m.end
    return prepared.text, chosen


def _apply(text: str, forms: tuple[Form, ...], skip: frozenset[str]) -> str:
    normalized, chosen = matches(text, forms, skip)
    out: list[str] = []
    cursor = 0
    for m in chosen:
        out.append(normalized[cursor : m.start])
        out.append(m.form.variant.fake_for(normalized[m.start : m.end]))
        cursor = m.end
    out.append(normalized[cursor:])
    return "".join(out)


def _splits_cluster(text: str, start: int, end: int) -> bool:
    starts_on_mark = start < len(text) and unicodedata.combining(text[start]) != 0
    mark_follows = end < len(text) and unicodedata.combining(text[end]) != 0
    return starts_on_mark or mark_follows
