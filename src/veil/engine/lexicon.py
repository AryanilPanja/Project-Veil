"""The lexicon: every form the engine matches, in both directions (M1.1 + M1.2).

Built once per process from the flattened persona:
    declared entities → variants (case spellings, name joins)       [variants.py]
    + derived identity forms (jdoe, janed …), dropped if they collide [compose.py]
    + class-term phrases (degree templates, year ordinals)            [academic.py]

Building fails closed: if the expanded declared forms break the bijection (E010-E014), the
engine refuses to start (`veil persona check` shows the same findings by field path).
"""

from collections.abc import Sequence

from veil.engine.academic import class_term_forms
from veil.engine.compose import derived_entities
from veil.engine.forms import Form, Lexicon, Variant
from veil.engine.variants import ExpandedEntity, expand_all, validate_expanded
from veil.errors import ValidationFailed
from veil.persona.entities import FlatPersona
from veil.persona.walk import EntityKind
from veil.text.normalize import canon

__all__ = ["Form", "Lexicon", "build_lexicon"]


def build_lexicon(flat: FlatPersona) -> Lexicon:
    # The bare year of study ("2") is never a form: only its ordinal phrases are (academic.py).
    declared = [e for e in expand_all(flat) if e.entity.kind is not EntityKind.YEAR]
    errors = [f for f in validate_expanded(declared) if f.code.startswith("E")]
    if errors:
        raise ValidationFailed(
            f"the persona has {len(errors)} bijection error(s) in its generated forms; "
            "run `veil persona check` for the field paths"
        )
    expanded: Sequence[ExpandedEntity] = [*declared, *derived_entities(flat, declared)]
    taken_real = {canon(v.real) for e in expanded for v in e.variants}
    taken_fake = {canon(v.fake) for e in expanded for v in e.variants}
    class_terms = class_term_forms(flat.academic, taken_real, taken_fake)

    forward = tuple(Form(v, e.entity) for e in expanded for v in e.variants) + tuple(
        Form(v, c.forward.entity) for c in class_terms for v in c.forward.variants
    )
    reverse = tuple(
        Form(_swap(v), e.entity) for e in expanded if e.entity.reversible for v in e.variants
    ) + tuple(Form(_swap(v), c.reverse_entity) for c in class_terms for v in c.forward.variants)
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
