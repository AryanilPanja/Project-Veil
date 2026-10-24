"""The production matcher (M1.4): Aho-Corasick search, raw-offset rewriting.

Selection has the same semantics as the reference translator (`reference.py`, the oracle):
every bounded hit of every form (case-insensitive, invisible characters ignored) → drop hits on
`never_translate` text and context-guarded forms without a keyword within CONTEXT_WINDOW →
leftmost-longest, ties broken by lexicon order.

The difference is what gets rewritten. The reference works on NFKC text and returns NFKC text:
it would silently turn the user's "ﬁ" into "fi" and full-width letters into ASCII. The matcher
keeps a map from the normalized text back to the raw input and replaces only the matched raw
spans; everything else stays byte-identical.

Raw ↔ normalized mapping: the raw text is cut into clusters (a character plus the combining
marks after it). Each cluster is normalized on its own, so every normalized character knows its
raw cluster. A hit must cover whole clusters; a hit that would replace part of one (just the "f"
of "ﬁ") is rejected, so veil never edits half of a character.
"""

import unicodedata
from dataclasses import dataclass

from veil.engine.lexicon import Form, Lexicon
from veil.text.aho import PatternIndex
from veil.text.containment import PreparedText
from veil.text.normalize import canon

CONTEXT_WINDOW = 200


@dataclass(frozen=True, slots=True)
class RawMatch:
    start: int  # raw offsets
    end: int
    form: Form
    replacement: str = ""

    def __repr__(self) -> str:
        return f"RawMatch({self.start}, {self.end}, {self.form!r})"


class Mapped:
    """The raw text, its cluster-wise NFKC form, and the map between them."""

    __slots__ = ("cluster_of", "clusters", "prepared", "raw")

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.clusters: list[tuple[int, int, int, int]] = []  # raw start, raw end, norm start, end
        pieces: list[str] = []
        self.cluster_of: list[int] = []  # normalized index → cluster index
        norm_len = 0
        for raw_start, raw_end in _clusters(raw):
            piece = unicodedata.normalize("NFKC", raw[raw_start:raw_end])
            self.clusters.append((raw_start, raw_end, norm_len, norm_len + len(piece)))
            self.cluster_of.extend([len(self.clusters) - 1] * len(piece))
            pieces.append(piece)
            norm_len += len(piece)
        self.prepared = PreparedText.from_normalized("".join(pieces))

    @property
    def text(self) -> str:
        return self.prepared.text

    def to_raw(self, start: int, end: int) -> tuple[int, int] | None:
        """Raw span for normalized [start, end), or None if it splits a cluster."""
        if start >= end:
            return None
        first, last = self.cluster_of[start], self.cluster_of[end - 1]
        if self.clusters[first][2] != start or self.clusters[last][3] != end:
            return None
        return self.clusters[first][0], self.clusters[last][1]


class Matcher:
    """One direction (forward or reverse) of the translation."""

    def __init__(self, forms: tuple[Form, ...], skip: frozenset[str]) -> None:
        self.forms = forms
        self.skip = skip
        self._index = PatternIndex([f.variant.real for f in forms])

    def __repr__(self) -> str:
        return f"Matcher(forms={len(self.forms)})"

    def find(self, raw: str) -> list[RawMatch]:
        """The chosen matches, in order, with their replacement text."""
        mapped = Mapped(raw)
        text = mapped.text
        hits = self._index.find(mapped.prepared)
        hits.sort(key=lambda h: (h.start, -(h.end - h.start), h.pattern))
        chosen: list[RawMatch] = []
        cursor = 0
        for hit in hits:
            if hit.start < cursor:
                continue
            found = text[hit.start : hit.end]
            form = self.forms[hit.pattern]
            if canon(found) in self.skip:
                continue
            if form.entity.contexts and not _context_near(text, hit.start, hit.end, form):
                continue
            raw_span = mapped.to_raw(hit.start, hit.end)
            if raw_span is None:
                continue
            chosen.append(RawMatch(raw_span[0], raw_span[1], form, form.variant.fake_for(found)))
            cursor = hit.end
        return chosen

    def apply(self, raw: str) -> str:
        out: list[str] = []
        cursor = 0
        for m in self.find(raw):
            out.append(raw[cursor : m.start])
            out.append(m.replacement)
            cursor = m.end
        out.append(raw[cursor:])
        return "".join(out)


class Engine:
    """forward (real → fake) and reverse (fake → real) over one lexicon."""

    def __init__(self, lexicon: Lexicon) -> None:
        self.lexicon = lexicon
        self.forward_matcher = Matcher(lexicon.forward, lexicon.never_translate)
        self.reverse_matcher = Matcher(
            lexicon.reverse, lexicon.never_reverse | lexicon.never_translate
        )

    def __repr__(self) -> str:
        return f"Engine({self.lexicon!r})"

    def forward(self, text: str) -> str:
        return self.forward_matcher.apply(text)

    def reverse(self, text: str) -> str:
        return self.reverse_matcher.apply(text)


def _clusters(raw: str) -> list[tuple[int, int]]:
    """(start, end) of each base character plus the combining marks that follow it."""
    spans: list[tuple[int, int]] = []
    start = 0
    for i in range(1, len(raw) + 1):
        if i == len(raw) or unicodedata.combining(raw[i]) == 0:
            spans.append((start, i))
            start = i
    return spans if raw else []


def _context_near(text: str, start: int, end: int, form: Form) -> bool:
    window = canon(text[max(0, start - CONTEXT_WINDOW) : end + CONTEXT_WINDOW])
    return any(canon(c) and canon(c) in window for c in form.entity.contexts)
