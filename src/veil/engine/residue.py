"""Fake-residue warning (M2.7, agent2 review §2.3): pieces of fake names that reverse can't restore.

A model writing about "Alex Smith" invents forms the lexicon never declared: "Alex" glued into
`alex_test_db` or `alexsmith99`, a shortening ("Smit"), an initial ("A. Smith" → "A. Doe" after
reverse). Reverse leaves them as they are, so fake names creep into real files. This module
counts such leftovers in the fake-side text, per entity kind; it never reports which ones (the
caller shows counts and kinds only, never text).

Only person names count (the owner's and other people's): their words of 4+ letters. Spans
reverse replaces and never_reverse / never_translate phrases are not leftovers. In what remains,
a word is a leftover when it:
- equals a fake name word (reverse skipped it: a context guard, or glued with `_`);
- starts with one ("alexsmith", "alex99");
- is a shortening of one, 4+ letters ("Smit" of "Smith"), letters only;
And an initial right before a replaced name ("A. Smith") is a leftover when its letter starts a
fake name word but no real one (when it matches a real initial, the result is right anyway).

Conservative on purpose: a warning that asks for a look, not a rewrite. Ordinary words that
happen to start with a fake name ("Smithsonian") are counted too.
"""

from bisect import bisect_right
from collections.abc import Iterable

from veil.engine.forms import Form, word_spans
from veil.persona.model import EntityKind
from veil.text.normalize import canon

NAME_KINDS = frozenset({EntityKind.NAME, EntityKind.PERSON_NAME})
MIN_LETTERS = 4


class Residue:
    """The fake name words of a lexicon's reverse forms, indexed for the scan. Holds values:
    its repr shows counts only."""

    def __init__(self, reverse: Iterable[Form]) -> None:
        self.words: dict[str, str] = {}  # fake name word → entity kind
        real_initials: set[str] = set()
        for form in reverse:
            if form.entity.kind not in NAME_KINDS:
                continue
            for word in _words(form.variant.real):  # reverse forms: real = the fake spelling
                if len(word) >= MIN_LETTERS:
                    self.words.setdefault(word, form.entity.kind.value)
            real_initials.update(word[0] for word in _words(form.variant.fake))
        self.lengths = sorted({len(w) for w in self.words})
        self.shortenings: dict[str, str] = {}
        for word, kind in self.words.items():
            for end in range(MIN_LETTERS, len(word)):
                self.shortenings.setdefault(word[:end], kind)
        self.initials = {w[0]: k for w, k in self.words.items() if w[0] not in real_initials}

    def __repr__(self) -> str:
        return f"Residue(words={len(self.words)})"

    def count(
        self, text: str, covered: list[tuple[int, int]], names: list[tuple[int, int]]
    ) -> dict[str, int]:
        """Leftovers per entity kind. `covered`: spans reverse replaces or must leave alone
        (sorted); `names`: replaced spans of person names (initials are checked before them)."""
        counts: dict[str, int] = {}
        if not self.words:
            return counts
        merged = _merge(covered)
        starts = [s for s, _ in merged]
        for start, end in word_spans(text):
            for piece_start, piece_end in _uncovered(start, end, merged, starts):
                kind = self._kind(canon(text[piece_start:piece_end]))
                if kind:
                    counts[kind] = counts.get(kind, 0) + 1
        for start, _ in names:
            kind = self._initial(text, start)
            if kind:
                counts[kind] = counts.get(kind, 0) + 1
        return counts

    def _kind(self, word: str) -> str | None:
        if word in self.words:
            return self.words[word]
        for length in self.lengths:
            if length < len(word) and word[:length] in self.words:
                return self.words[word[:length]]
        if word.isalpha() and word in self.shortenings:
            return self.shortenings[word]
        return None

    def _initial(self, text: str, start: int) -> str | None:
        """An initial (\"A. \" or \"A.\") right before `start`, as a word of its own."""
        i = start
        if i > 0 and text[i - 1] in " \t\u00a0":
            i -= 1
        if i < 2 or text[i - 1] != "." or not text[i - 2].isalpha():
            return None
        if i >= 3 and (text[i - 3].isalnum() or text[i - 3] == "_"):
            return None
        return self.initials.get(canon(text[i - 2]))


def _words(text: str) -> list[str]:
    folded = canon(text)
    return [folded[s:e] for s, e in word_spans(folded)]


def _merge(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _uncovered(
    start: int, end: int, merged: list[tuple[int, int]], starts: list[int]
) -> list[tuple[int, int]]:
    """The parts of [start, end) outside the merged spans ("alexsmith99" with "alexsmith"
    restored leaves "99")."""
    pieces: list[tuple[int, int]] = []
    cursor = start
    i = max(bisect_right(starts, start) - 1, 0)
    while i < len(merged) and merged[i][0] < end:
        span_start, span_end = merged[i]
        if span_end > cursor:
            if span_start > cursor:
                pieces.append((cursor, span_start))
            cursor = max(cursor, span_end)
        i += 1
    if cursor < end:
        pieces.append((cursor, end))
    return pieces


LABELS = {EntityKind.NAME.value: "your name", EntityKind.PERSON_NAME.value: "other people's names"}


def warning(counts: dict[str, int]) -> str | None:
    """The value-free stderr warning for `counts` (from Engine.residue), or None."""
    total = sum(counts.values())
    if not total:
        return None
    detail = ", ".join(f"{LABELS.get(kind, kind)} {n}" for kind, n in sorted(counts.items()))
    return (
        f"veil: warning: {total} leftover piece(s) of fake names not restored ({detail}): "
        "shortened or joined forms reverse can't map; check the text before using it"
    )
