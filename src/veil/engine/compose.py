"""Compositional mapping (spec v0.2 §5.1, M1.2): compound values translate part by part.

Most of this needs no code. The boundary rule (ADR-0026) treats `@ / . _ -` as edges, so in
`jane.doe@research.xyz.example.test`, `/home/janed/jane-thesis/` or `github.com/jane-doe-dev`
each known part matches on its own: the local part through the name entities, the host through
the domain entities (the longest declared one wins), each path segment through its entity.

What matching alone misses are identifiers *derived* from a name that nobody declared:
`jdoe@…`, `doej`, `janed`. Without them, the domain would be translated while the real surname
stays visible next to it. This module derives them from the owner's names and other people's
two-part names:

    initial+family  jdoe  j.doe  j_doe      →  asmith  a.smith  a_smith
    given+initial   janed jane.d jane_d     →  alexs   alex.s   alex_s
    family+given    doejane doe.jane …      →  smithalex …
    family+initial  doej  doe.j  doe_j      →  smitha  …

Derived forms are heuristics, not declarations, so they never cause errors: a derived form is
dropped when it is too short (< 4 letters, or a spelled-out name part < 3 letters), when it
equals or collides with a declared form, or when it contains or sits inside another form.
When two people derive the same form (family members share initials and surname), **the
owner's derivation wins** (their own email is by far the likeliest meaning) and the others are
dropped; between two other people, both are dropped.
Each derived form also gets PascalCase spellings (`JDoe` → `ASmith`).
"""

from collections.abc import Iterable, Sequence

from veil.engine.variants import ExpandedEntity, Variant, expand
from veil.persona.entities import Entity, FlatPersona
from veil.persona.policy import Policy
from veil.persona.walk import EntityKind
from veil.text.containment import NaiveIndex
from veil.text.normalize import canon

MIN_DERIVED = 4  # letters and digits, separators not counted
MIN_PART = 3  # a spelled-out name part must have at least this many letters
DERIVED_SEPARATORS = ("", ".", "_")


def derived_entities(flat: FlatPersona, declared: Sequence[ExpandedEntity]) -> list[ExpandedEntity]:
    """Derived identity forms that are safe to add next to the declared (expanded) ones."""
    kept = _filter(list(_candidates(flat)), declared)
    return [expand(entity) for entity in kept]


# ── candidates ────────────────────────────────────────────────────────────────


def _candidates(flat: FlatPersona) -> Iterable[tuple[bool, Entity]]:
    """(is_owner, entity) per person; the owner (if any) comes first."""
    for owner, source, parts in _name_parts(flat):
        (rg, rf), (fg, ff) = parts
        pairs = list(_derivations(rg, rf, fg, ff))
        if pairs:
            yield owner, _derived_entity(source, pairs)


def _name_parts(
    flat: FlatPersona,
) -> Iterable[tuple[bool, str, tuple[tuple[str, str], tuple[str, str]]]]:
    """(is_owner, source id, ((real given, real family), (fake given, fake family)))."""
    by_role = {e.role: e for e in flat.entities if e.kind is EntityKind.NAME and e.fake_forms}
    given, family = by_role.get("given"), by_role.get("family")
    if given and family:
        yield (
            True,
            f"{given.id}+{family.id}",
            (
                (given.real_forms[0], family.real_forms[0]),
                (given.fake_forms[0], family.fake_forms[0]),
            ),
        )
    elif "full" in by_role:
        split = _split_full(by_role["full"].real_forms[0], by_role["full"].fake_forms[0])
        if split:
            yield True, by_role["full"].id, split
    for entity in flat.entities:
        if entity.kind is not EntityKind.PERSON_NAME or not entity.fake_forms:
            continue
        split = _split_full(entity.real_forms[0], entity.fake_forms[0])
        if split:
            yield False, entity.id, split


def _split_full(real: str, fake: str) -> tuple[tuple[str, str], tuple[str, str]] | None:
    """First and last name words, skipping titles and initials ("Prof.", "M.")."""
    rw = [w for w in real.split() if not w.endswith(".") and len(w) > 1]
    fw = [w for w in fake.split() if not w.endswith(".") and len(w) > 1]
    if len(rw) < 2 or len(fw) < 2:
        return None
    return (rw[0], rw[-1]), (fw[0], fw[-1])


def _derivations(rg: str, rf: str, fg: str, ff: str) -> Iterable[tuple[str, str]]:
    rgl, rfl, fgl, ffl = rg.lower(), rf.lower(), fg.lower(), ff.lower()
    # (shape, which full name parts it spells out): a shape is used only when every full part
    # it spells has at least MIN_PART letters on both sides ("Li Ng" → no "ling").
    shapes = (
        ((lambda g, f, s: f"{g[:1]}{s}{f}"), ("family",)),  # jdoe
        ((lambda g, f, s: f"{g}{s}{f[:1]}"), ("given",)),  # janed
        ((lambda g, f, s: f"{f}{s}{g}"), ("family", "given")),  # doejane
        ((lambda g, f, s: f"{f}{s}{g[:1]}"), ("family",)),  # doej
    )
    lengths = {"given": min(len(rgl), len(fgl)), "family": min(len(rfl), len(ffl))}
    for shape, parts in shapes:
        if any(lengths[part] < MIN_PART for part in parts):
            continue
        for sep in DERIVED_SEPARATORS:
            yield shape(rgl, rfl, sep), shape(fgl, ffl, sep)
        yield shape(_cap(rgl), _cap(rfl), ""), shape(_cap(fgl), _cap(ffl), "")  # JDoe


def _cap(word: str) -> str:
    return word[:1].upper() + word[1:]


def _derived_entity(source: str, pairs: list[tuple[str, str]]) -> Entity:
    return Entity(
        id=f"derived:{source}",
        sources=(source,),
        kind=EntityKind.USERNAME,
        role="derived",
        real_forms=tuple(r for r, _ in pairs),
        fake_forms=tuple(f for _, f in pairs),
        policy=Policy.SWAP,
        needs_generation=False,
        reversible=True,
        contexts=(),
        allow_short=False,
        meta=(("derived", "true"),),
    )


# ── filtering ─────────────────────────────────────────────────────────────────


def _filter(
    candidates: Sequence[tuple[bool, Entity]], declared: Sequence[ExpandedEntity]
) -> list[Entity]:
    declared_real = {canon(v.real) for e in declared for v in e.variants}
    declared_fake = {canon(v.fake) for e in declared for v in e.variants}
    real_texts = [v.real for e in declared for v in e.variants]
    fake_texts = [v.fake for e in declared for v in e.variants]
    real_index, fake_index = NaiveIndex(real_texts), NaiveIndex(fake_texts)

    def safe(real: str, fake: str) -> bool:
        r, f = canon(real), canon(fake)
        if _letters(r) < MIN_DERIVED or _letters(f) < MIN_DERIVED:
            return False
        if r in declared_real or r in declared_fake or f in declared_fake or f in declared_real:
            return False  # a declared form already covers it (or would be contradicted)
        if real_index.containing(fake) or fake_index.containing(real):
            return False
        return not (_inside_any(real, fake_texts) or _inside_any(fake, real_texts))

    # How each canon real/fake is derived by people other than the owner.
    others_targets: dict[str, set[str]] = {}
    others_sources: dict[str, set[str]] = {}
    for owner, entity in candidates:
        if owner:
            continue
        for real, fake in zip(entity.real_forms, entity.fake_forms, strict=True):
            others_targets.setdefault(canon(real), set()).add(canon(fake))
            others_sources.setdefault(canon(fake), set()).add(canon(real))

    taken_real: dict[str, str] = {}  # canon real → canon fake, across everything kept
    taken_fake: dict[str, str] = {}
    kept: list[Entity] = []
    for owner, entity in candidates:
        accepted: set[str] = set()
        for real, fake in zip(entity.real_forms, entity.fake_forms, strict=True):
            r, f = canon(real), canon(fake)
            if r in accepted or r in taken_real or f in taken_fake:
                continue
            if not owner and (len(others_targets[r]) > 1 or len(others_sources[f]) > 1):
                continue  # two other people derive it differently
            if safe(real, fake):
                accepted.add(r)
                taken_real[r], taken_fake[f] = f, r
        pairs = [
            (real, fake)
            for real, fake in zip(entity.real_forms, entity.fake_forms, strict=True)
            if canon(real) in accepted
        ]
        if pairs:
            kept.append(_derived_entity(entity.sources[0], pairs))
    return kept


def _letters(text: str) -> int:
    return sum(c.isalnum() for c in text)


def _inside_any(text: str, others: Sequence[str]) -> bool:
    """Does any of `others` occur (bounded) inside `text`?"""
    index = NaiveIndex([text])
    return any(index.containing(other) for other in others if canon(other))


def all_variants(expanded: Sequence[ExpandedEntity]) -> list[tuple[Variant, Entity]]:
    return [(v, e.entity) for e in expanded for v in e.variants]
