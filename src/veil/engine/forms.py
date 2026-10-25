"""The engine's runtime data: variants, forms and the lexicon (no pydantic or YAML imports).

Kept light on purpose: the warm path (the encrypted lexicon cache, ADR-0029) rebuilds a Lexicon
from these classes without importing the persona schema. `variants.py` and `lexicon.py` build
them and re-export them.
"""

from dataclasses import dataclass, field

from veil.persona.model import Entity


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
        """The fake spelling for `matched` (the exact text found in the input)."""
        for real, fake in self.spellings:
            if real == matched:
                return fake
        return case_like(matched, self.fake)


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


def capitalise_words(text: str) -> str:
    """Upper-case the first letter of each space-separated word; leave the rest as is."""
    return " ".join(w[:1].upper() + w[1:] for w in text.split(" "))


def _is_capitalised_words(text: str) -> bool:
    words = [w for w in text.split() if any(c.isalpha() for c in w)]
    return bool(words) and all(
        w[0].isupper() and not w[1:].isupper() for w in words if w[0].isalpha()
    )
