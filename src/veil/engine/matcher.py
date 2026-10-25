"""The production matcher (M1.4): Aho-Corasick search, raw-offset rewriting.

Selection has the same semantics as the reference translator (`reference.py`, the oracle):
every bounded hit of every form (case-insensitive, invisible characters ignored) → drop hits on
`never_translate` text and context-guarded forms without a bounded keyword in their window
(context.py) → leftmost-longest, ties broken by lexicon order.

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
from functools import cached_property

from veil.engine.context import Distances, context_near, overlaps_any
from veil.engine.forms import Form, Lexicon, raw_whitespace
from veil.engine.residue import NAME_KINDS, Residue
from veil.text.aho import PatternIndex
from veil.text.containment import PreparedText


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

    __slots__ = ("cluster_of", "clusters", "identity", "prepared", "raw")

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.clusters: list[tuple[int, int, int, int]] = []  # raw start, raw end, norm start, end
        self.cluster_of: list[int] = []
        self.identity = raw.isascii() or unicodedata.is_normalized("NFKC", raw)
        if self.identity:
            # Fast path: the text is already NFKC (always true for ASCII), so normalized and raw
            # offsets are the same. Clusters only matter for the never-split-a-character rule,
            # which to_raw checks directly (a span must not start on, or be followed by, a mark).
            self.prepared = PreparedText.from_normalized(raw)
            return
        pieces: list[str] = []
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
        if self.identity:
            raw = self.raw
            if unicodedata.combining(raw[start]) or (
                end < len(raw) and unicodedata.combining(raw[end])
            ):
                return None  # would split a base character from its combining marks
            return start, end
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
        self._protected = PatternIndex(sorted(skip))

    def __repr__(self) -> str:
        return f"Matcher(forms={len(self.forms)})"

    def find(self, raw: str, *, use_context: bool = True) -> list[RawMatch]:
        """The chosen matches, in order, with their replacement text.

        `use_context=False` ignores context guards (for conservative ambiguity counting).
        """
        mapped = Mapped(raw)
        text = mapped.text
        hits = self._index.find(mapped.prepared)
        protected = [(h.start, h.end) for h in self._protected.find(mapped.prepared)]
        hits.sort(key=lambda h: (h.start, -(h.end - h.start), h.pattern))
        usable = [
            h
            for h in hits
            if not overlaps_any(h.start, h.end, protected)  # never_translate / never_reverse
            and mapped.to_raw(h.start, h.end) is not None  # never split a character
        ]
        distances = None
        if use_context and any(self.forms[h.pattern].entity.contexts for h in usable):
            # Unit distances over the spans the unguarded forms replace (context.py).
            distances = Distances(
                len(text),
                _greedy(h for h in usable if not self.forms[h.pattern].entity.contexts),
            )
        keyword_spans: dict[str, list] = {}
        chosen: list[RawMatch] = []
        cursor = 0
        for hit in usable:
            if hit.start < cursor:
                continue
            found = text[hit.start : hit.end]
            form = self.forms[hit.pattern]
            if use_context and not context_near(
                mapped.prepared, hit.start, hit.end, form.entity, distances, keyword_spans
            ):
                continue
            raw_span = mapped.to_raw(hit.start, hit.end)
            if raw_span is None:  # filtered above; kept as a guard
                continue
            # NFKC turns a no-break space into a space: give the raw whitespace back first.
            found = raw_whitespace(found, raw[raw_span[0] : raw_span[1]])
            chosen.append(RawMatch(raw_span[0], raw_span[1], form, form.variant.fake_for(found)))
            cursor = hit.end
        return chosen

    def protected(self, raw: str) -> list[tuple[int, int]]:
        """Raw spans of the never_translate / never_reverse phrases in `raw`."""
        mapped = Mapped(raw)
        spans = (mapped.to_raw(h.start, h.end) for h in self._protected.find(mapped.prepared))
        return [span for span in spans if span is not None]

    def apply(self, raw: str) -> str:
        return self.apply_counted(raw)[0]

    def apply_counted(self, raw: str) -> tuple[str, dict[str, int]]:
        """The rewritten text, and the number of replacements per entity kind."""
        out: list[str] = []
        counts: dict[str, int] = {}
        cursor = 0
        for m in self.find(raw):
            out.append(raw[cursor : m.start])
            out.append(m.replacement)
            cursor = m.end
            kind = m.form.entity.kind.value
            counts[kind] = counts.get(kind, 0) + 1
        out.append(raw[cursor:])
        return "".join(out), counts


@dataclass(frozen=True, slots=True)
class AuditHit:
    line: int  # 1-based
    column: int  # 1-based, in characters of the raw input
    path: str  # the persona field path of the entity
    kind: str  # entity kind (name, email, phone…)


class Engine:
    """forward (real → fake) and reverse (fake → real) over one lexicon."""

    def __init__(self, lexicon: Lexicon) -> None:
        self.lexicon = lexicon
        self.forward_matcher = Matcher(lexicon.forward, lexicon.never_translate)
        self.reverse_matcher = Matcher(
            lexicon.reverse, lexicon.never_reverse | lexicon.never_translate
        )
        self.sensitive_matcher = Matcher(lexicon.sensitive, frozenset())

    def __repr__(self) -> str:
        return f"Engine({self.lexicon!r})"

    def forward(self, text: str) -> str:
        return self.forward_matcher.apply(text)

    def reverse(self, text: str) -> str:
        return self.reverse_matcher.apply(text)

    def forward_counted(self, text: str) -> tuple[str, dict[str, int]]:
        """forward(), plus replacements per entity kind (for value-free notifications)."""
        return self.forward_matcher.apply_counted(text)

    def reverse_counted(self, text: str) -> tuple[str, dict[str, int]]:
        return self.reverse_matcher.apply_counted(text)

    def sensitive(self, text: str) -> list[RawMatch]:
        """Listed special-category terms in `text` (ADR-0012), leftmost-longest, raw offsets.

        Each match's `form.entity` carries the policy (ASK or GENERALIZE) and the category
        (`meta_value("category")`); never the term itself in anything shown to the user.
        """
        return self.sensitive_matcher.find(text)

    @staticmethod
    def generalize(text: str, matches: list[RawMatch]) -> str:
        """`text` with each match replaced by its generalized phrase, verbatim."""
        out: list[str] = []
        cursor = 0
        for m in sorted(matches, key=lambda m: m.start):
            out.append(text[cursor : m.start])
            out.append(m.form.variant.fake)
            cursor = m.end
        out.append(text[cursor:])
        return "".join(out)

    def audit(self, text: str) -> list["AuditHit"]:
        """Every real form in `text` (context guards ignored: an audit must be conservative).

        Positions and field paths only; the matched text is never part of the result.
        """
        hits: list[AuditHit] = []
        for match in self.forward_matcher.find(text, use_context=False):
            line = text.count("\n", 0, match.start) + 1
            column = match.start - (text.rfind("\n", 0, match.start) + 1) + 1
            entity = match.form.entity
            hits.append(AuditHit(line, column, entity.sources[0], entity.kind.value))
        return hits

    @cached_property
    def _residue(self) -> Residue:
        return Residue(self.lexicon.reverse)

    def residue(self, text: str) -> dict[str, int]:
        """Pieces of fake person names in fake-side `text` that reverse leaves unrestored
        (M2.7, residue.py): counts per entity kind, never which ones."""
        matches = self.reverse_matcher.find(text)
        covered = [(m.start, m.end) for m in matches] + self.reverse_matcher.protected(text)
        names = [(m.start, m.end) for m in matches if m.form.entity.kind in NAME_KINDS]
        return self._residue.count(text, covered, names)

    def ambiguous(self, text: str) -> dict[str, int]:
        """Fake forms already present in real input, by entity id → count (spec §5.5, §5.7).

        Such text cannot round-trip: after translation nobody can tell the genuine occurrence
        from a translated one. Context guards are ignored here on purpose: forward translation
        can create the context a guarded fake form needs ("3rd year" next to a translated
        institution), so counting must be conservative. Callers warn (counts and entity ids
        only, never the text); the proxy's taint tracking (v0.2) builds on this.
        `never_reverse` names are not counted: they are handled explicitly.
        """
        counts: dict[str, int] = {}
        for match in self.reverse_matcher.find(text, use_context=False):
            entity_id = match.form.entity.id
            counts[entity_id] = counts.get(entity_id, 0) + 1
        return counts


def _clusters(raw: str) -> list[tuple[int, int]]:
    """(start, end) of each base character plus the combining marks that follow it."""
    spans: list[tuple[int, int]] = []
    start = 0
    for i in range(1, len(raw) + 1):
        if i == len(raw) or unicodedata.combining(raw[i]) == 0:
            spans.append((start, i))
            start = i
    return spans if raw else []


def _greedy(hits) -> list[tuple[int, int]]:
    """Leftmost-longest selection of (start, end) spans from sorted hits."""
    spans: list[tuple[int, int]] = []
    cursor = 0
    for hit in hits:
        if hit.start >= cursor:
            spans.append((hit.start, hit.end))
            cursor = hit.end
    return spans
