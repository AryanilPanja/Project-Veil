"""The lexicon: every form the engine matches, in both directions (M1.1 + M1.2).

Built once per process from the flattened persona:
    declared entities → variants (case spellings, name joins)       [variants.py]
    + derived identity forms (jdoe, janed …), dropped if they collide [compose.py]

Building fails closed: if the expanded declared forms break the bijection (E010-E014), the
engine refuses to start (`veil persona check` shows the same findings by field path).
"""

from collections.abc import Sequence
from dataclasses import dataclass

from veil.engine.compose import derived_entities
from veil.engine.variants import ExpandedEntity, Variant, expand_all, validate_expanded
from veil.errors import ValidationFailed
from veil.persona.entities import Entity, FlatPersona
from veil.text.normalize import canon


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


def build_lexicon(flat: FlatPersona) -> Lexicon:
    declared = expand_all(flat)
    errors = [f for f in validate_expanded(declared) if f.code.startswith("E")]
    if errors:
        raise ValidationFailed(
            f"the persona has {len(errors)} bijection error(s) in its generated forms; "
            "run `veil persona check` for the field paths"
        )
    expanded: Sequence[ExpandedEntity] = [*declared, *derived_entities(flat, declared)]
    forward = tuple(Form(v, e.entity) for e in expanded for v in e.variants)
    reverse = tuple(
        Form(_swap(v), e.entity) for e in expanded if e.entity.reversible for v in e.variants
    )
    return Lexicon(
        forward=forward,
        reverse=reverse,
        never_translate=frozenset(canon(t) for t in flat.never_translate if canon(t)),
        never_reverse=frozenset(canon(t) for t in flat.never_reverse if canon(t)),
    )


def _swap(variant: Variant) -> Variant:
    return Variant(
        real=variant.fake,
        fake=variant.real,
        spellings=tuple((f, r) for r, f in variant.spellings),
        origin=variant.origin,
    )
