"""Variant expansion: the surface forms each entity is matched in (spec v0.2 §5.2, M1.1).

Matching is case-insensitive (it runs on canon-folded text), so case never needs extra *match*
forms. What case does need is the right *output* spelling: "JANE" → "ALEX", "janeDoe" →
"alexSmith". So every entity gets a table of exact spellings (`Variant.spellings`), and
`case_like` covers anything not in the table.

Per declared (real, fake) pair, index-aligned:
- spellings: as declared, lower, UPPER, Capitalised Words;
- multi-word names (the owner's names, other people): joins `janedoe`, `jane.doe`, `jane_doe`,
  `jane-doe`, the reversed `doe jane` and `doe, jane`, plus PascalCase/camelCase spellings of the
  joins (`JaneDoe`, `janeDoe`).

Not here, by design:
- possessives ("Jane's"): the boundary rule already matches "Jane" before the apostrophe;
- JSON/URL-escaped forms: decoded before matching (spec §6.3), not expanded;
- initials ("J. Doe"): need a per-entity opt-in in the schema first (TODO-later).

After expansion, the whole table is re-validated with the M0 bijection rules (E010-E014): a
join of one entity must not collide with another entity's form.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from veil.persona.entities import Entity, FlatPersona
from veil.persona.report import Finding
from veil.persona.validate import FormRow, validate_forms
from veil.persona.walk import EntityKind
from veil.text.normalize import canon

JOIN_SEPARATORS = ("", ".", "_", "-")
NAME_KINDS = frozenset({EntityKind.NAME, EntityKind.PERSON_NAME})


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
class ExpandedEntity:
    entity: Entity
    variants: tuple[Variant, ...]

    def __repr__(self) -> str:
        return f"ExpandedEntity({self.entity!r}, variants={len(self.variants)})"


def expand(entity: Entity) -> ExpandedEntity:
    pairs: list[tuple[str, str, str]] = [
        (r, f, "declared") for r, f in zip(entity.real_forms, entity.fake_forms, strict=False)
    ]
    if entity.kind in NAME_KINDS:
        for real, fake in zip(entity.real_forms, entity.fake_forms, strict=False):
            pairs.extend(_name_joins(real, fake))
    return ExpandedEntity(entity, _group(pairs))


def expand_all(flat: FlatPersona) -> list[ExpandedEntity]:
    """Expand every entity that has fakes (needs_generation ones get theirs in M1.6)."""
    return [expand(e) for e in flat.entities if e.fake_forms]


def validate_expanded(expanded: Sequence[ExpandedEntity]) -> list[Finding]:
    """Re-run the bijection rules (E010-E014) over every variant of every entity.

    Like the M0 validator, the year of study is left out: its bare digits only ever match next to
    a degree or institution form (context guard), so "2" must not collide with every "Block 2".
    """
    rows = [
        FormRow(
            path=f"{item.entity.id}~{variant.origin}",
            real=variant.real,
            fake=variant.fake,
            reversible=item.entity.reversible,
        )
        for item in expanded
        if item.entity.kind is not EntityKind.YEAR
        for variant in item.variants
    ]
    return validate_forms(rows)


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


# ── names ─────────────────────────────────────────────────────────────────────


def _name_joins(real: str, fake: str) -> Iterable[tuple[str, str, str]]:
    real_words, fake_words = real.split(), fake.split()
    if len(real_words) < 2 or len(fake_words) < 2:
        return
    for sep in JOIN_SEPARATORS:
        yield sep.join(real_words), sep.join(fake_words), "join"
    # PascalCase / camelCase joins (match the same canon as the plain join, but spell differently)
    yield _pascal(real_words), _pascal(fake_words), "join"
    yield _camel(real_words), _camel(fake_words), "join"
    first_r, last_r = real_words[0], real_words[-1]
    first_f, last_f = fake_words[0], fake_words[-1]
    yield f"{last_r} {first_r}", f"{last_f} {first_f}", "reversed"
    yield f"{last_r}, {first_r}", f"{last_f}, {first_f}", "reversed"


def _pascal(words: Sequence[str]) -> str:
    return "".join(w[:1].upper() + w[1:].lower() for w in words)


def _camel(words: Sequence[str]) -> str:
    pascal = _pascal(words)
    return pascal[:1].lower() + pascal[1:]


def _group(pairs: Iterable[tuple[str, str, str]]) -> tuple[Variant, ...]:
    """One Variant per canon(real); collects spellings (declared, lower, UPPER, Capitalised)."""
    order: list[str] = []
    data: dict[str, tuple[str, str, str, dict[str, str]]] = {}
    for real, fake, origin in pairs:
        key = canon(real)
        if not key or not canon(fake):
            continue
        if key not in data:
            order.append(key)
            data[key] = (real, fake, origin, {})
        table = data[key][3]
        for r, f in _case_spellings(real, fake):
            table.setdefault(r, f)
    return tuple(
        Variant(
            real=data[k][0], fake=data[k][1], spellings=tuple(data[k][3].items()), origin=data[k][2]
        )
        for k in order
    )


def _case_spellings(real: str, fake: str) -> Iterable[tuple[str, str]]:
    yield real, fake
    yield real.lower(), fake.lower()
    yield real.upper(), fake.upper()
    yield capitalise_words(real.lower()), capitalise_words(fake.lower())
