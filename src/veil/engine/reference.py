"""Reference translator: slow, obviously correct, and the test oracle for the real matcher.

Semantics (spec v0.2 §5.3), deliberately naive:
- candidates: every bounded occurrence of every form (M0 `find_bounded`, case-insensitive);
- a form whose entity has `contexts` counts only if a context keyword occurs within
  CONTEXT_WINDOW characters;
- a candidate whose text is a `never_translate` token is skipped;
- leftmost-longest: sort by (start, -length) and take non-overlapping candidates greedily;
- each match is replaced by `variant.fake_for(matched text)` (keeps the case pattern).

Works on the NFKC form of the input and returns NFKC text. The production matcher (M1.4) maps
spans back to the raw input instead, so it never normalizes untouched text.
"""

from dataclasses import dataclass

from veil.engine.lexicon import Form, Lexicon
from veil.text.containment import PreparedText, find_bounded
from veil.text.normalize import canon

CONTEXT_WINDOW = 200


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
    candidates: list[Match] = []
    for form in forms:
        for span in find_bounded(form.variant.real, prepared):
            found = prepared.text[span.start : span.end]
            if canon(found) in skip:
                continue
            if form.entity.contexts and not _context_near(
                prepared.text, span.start, span.end, form
            ):
                continue
            candidates.append(Match(span.start, span.end, form))
    candidates.sort(key=lambda m: (m.start, -(m.end - m.start)))
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


def _context_near(text: str, start: int, end: int, form: Form) -> bool:
    window = canon(text[max(0, start - CONTEXT_WINDOW) : end + CONTEXT_WINDOW])
    return any(canon(c) and canon(c) in window for c in form.entity.contexts)
