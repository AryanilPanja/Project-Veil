"""The engine's runtime data: variants, forms and the lexicon (no pydantic or YAML imports).

Kept light on purpose: the warm path (the encrypted lexicon cache, ADR-0029) rebuilds a Lexicon
from these classes without importing the persona schema. `variants.py` and `lexicon.py` build
them and re-export them.
"""

import re
import unicodedata
from dataclasses import dataclass, field

from veil.persona.model import Entity

_WHITESPACE = re.compile(r"\s+")  # same as str.isspace / str.split()


@dataclass(frozen=True, slots=True)
class Variant:
    """One matchable form (unique by canon) and the output spellings for it."""

    real: str  # a representative spelling (the first generated)
    fake: str
    spellings: tuple[tuple[str, str], ...] = field(repr=False)  # exact real spelling → fake
    origin: str  # "declared" | "join" | "reversed"

    def __repr__(self) -> str:
        return f"Variant(origin={self.origin}, spellings={len(self.spellings)})"

    def fake_for(self, matched: str) -> str:
        """The fake spelling for `matched` (the exact text found in the input).

        Keeps what the reverse direction needs to give `matched` back exactly (board Q15): the
        whitespace between words ("Jane⏎Doe" → "Alex⏎Smith"), and the case of each word
        ("Doe jane" → "Smith alex", "JaneDOE" → "AlexSMITH").
        """
        for real, fake in self.spellings:
            if real == matched:
                return fake
        single = " ".join(matched.split())
        if single != matched:
            return respace(matched, self.fake_for(single))
        by_word = self._case_by_word(matched)
        if by_word is not None:
            return by_word
        return case_like(matched, self.fake)

    def _case_by_word(self, matched: str) -> str | None:
        """Case `matched` word by word, using a known spelling with the same letters.

        A spelling `real` equal to `matched` but for case gives the word boundaries (separators
        and lower→Upper humps); its fake must have as many words. Glued forms without a known
        word structure ("doejane") return None.
        """
        folded = matched.lower()
        best: tuple[list[tuple[int, int]], str] | None = None
        for real, fake in self.spellings:
            if len(real) != len(matched) or real.lower() != folded:
                continue
            words = word_spans(real)
            if (
                len(words) >= 2
                and len(words) == len(word_spans(fake))
                and (best is None or len(words) > len(best[0]))
            ):
                best = (words, fake)
        if best is None:
            return None
        words, fake = best
        out: list[str] = []
        cursor = 0
        for (start, end), (fstart, fend) in zip(words, word_spans(fake), strict=True):
            out.append(fake[cursor:fstart])
            out.append(case_like(matched[start:end], fake[fstart:fend]))
            cursor = fend
        out.append(fake[cursor:])
        return "".join(out)


@dataclass(frozen=True, slots=True)
class Form:
    """One matchable form in one direction: `match` is searched, `variant.fake_for` produces."""

    variant: Variant
    entity: Entity

    def __repr__(self) -> str:
        return f"Form(entity={self.entity.id!r}, origin={self.variant.origin})"


@dataclass(frozen=True)
class Lexicon:
    forward: tuple[Form, ...]  # real → fake
    reverse: tuple[Form, ...]  # fake → real (reversible entities only)
    never_translate: frozenset[str]  # canon forms
    never_reverse: frozenset[str]  # canon forms

    def __repr__(self) -> str:
        return f"Lexicon(forward={len(self.forward)}, reverse={len(self.reverse)})"


# ── case ──────────────────────────────────────────────────────────────────────


def case_like(source: str, target: str) -> str:
    """Give `target` the case pattern of `source` (used when no exact spelling is known)."""
    letters = [c for c in source if c.isalpha() and c.lower() != c.upper()]
    if not letters:
        return target  # no cased letters (digits, Indic scripts…): keep the declared spelling
    if all(c.isupper() for c in letters) and len(letters) > 1:
        return target.upper()
    if all(c.islower() for c in letters):
        return target.lower()
    if len(source) == len(target) and all(  # JaneD → AlexS: copy the case letter by letter
        s.isalpha() == t.isalpha() for s, t in zip(source, target, strict=True)
    ):
        return "".join(
            t.upper() if s.isupper() else t.lower() for s, t in zip(source, target, strict=True)
        )
    if _is_capitalised_words(source):
        return capitalise_words(target)
    return target  # mixed case we can't map: the declared spelling is the safest choice


def respace(source: str, target: str) -> str:
    """Give `target` the whitespace runs of `source`, gap by gap, when both have as many gaps.

    `target` is single-spaced (a declared spelling). Otherwise it is returned unchanged.
    """
    runs = _WHITESPACE.findall(source.strip())
    gaps = target.split(" ")
    if len(gaps) != len(runs) + 1 or any(not g or _WHITESPACE.search(g) for g in gaps):
        return target
    out = [gaps[0]]
    for run, word in zip(runs, gaps[1:], strict=True):
        out.append(run)
        out.append(word)
    return "".join(out)


def raw_whitespace(found: str, raw: str) -> str:
    """`found` (normalized) with the whitespace runs of `raw` (the same span, as typed).

    Unchanged unless both have the same number of runs.
    """
    if found == raw or not _WHITESPACE.search(raw):
        return found
    runs = _WHITESPACE.findall(raw)
    parts = _WHITESPACE.split(found)
    if len(parts) != len(runs) + 1:
        return found
    out = [parts[0]]
    for run, part in zip(runs, parts[1:], strict=True):
        out.append(run)
        out.append(part)
    return "".join(out)


def word_spans(text: str) -> list[tuple[int, int]]:
    """(start, end) of each word: alphanumeric runs, also split at lower→Upper ("JaneDoe").

    Combining marks belong to their word (Indic vowel signs, accents), as in the boundary rule.
    """
    spans: list[tuple[int, int]] = []
    start: int | None = None
    for i, ch in enumerate(text):
        if not (ch.isalnum() or unicodedata.category(ch).startswith("M")):
            if start is not None:
                spans.append((start, i))
                start = None
            continue
        if start is None:
            start = i
        elif ch.isupper() and text[i - 1].islower():
            spans.append((start, i))
            start = i
    if start is not None:
        spans.append((start, len(text)))
    return spans


def capitalise_words(text: str) -> str:
    """Upper-case the first letter of each space-separated word; leave the rest as is."""
    return " ".join(w[:1].upper() + w[1:] for w in text.split(" "))


def _is_capitalised_words(text: str) -> bool:
    words = [w for w in text.split() if any(c.isalpha() for c in w)]
    return bool(words) and all(
        w[0].isupper() and not w[1:].isupper() for w in words if w[0].isalpha()
    )
