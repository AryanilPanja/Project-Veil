"""Flatten a Persona into the entities the M1 engine matches (the M0 → M1 contract).

Rules (ADR-0026):
- Excluded: disabled entries, KEEP (and ASK) policies, pairs whose real side is empty, and pairs
  whose real and fake are canonically equal (e.g. gender f → f, treated as KEEP).
- Real and fake forms are index-aligned: real_forms[i] ↔ fake_forms[i]. Empty slots are dropped
  pairwise; extra items of an unequal list are dropped (the validator reports E015).
- FPE/SHIFT with every fake empty → `needs_generation` (M1 generates and stores the fakes).
- Any other empty fake → not emitted (the validator reports E016); flatten never emits an
  entity the engine could not apply.
- Identical (real, fake, policy) entries from several fields merge into one entity with every
  source path (e.g. hostname = linux_user).
- Order is deterministic: schema order of first appearance.
- Vault keys must use HMAC(seed, canon(real)), never `id`/paths (list indices shift).

repr() of every object here is redacted: entities hold real values.
"""

from dataclasses import dataclass
from itertools import zip_longest

from veil.persona.policy import REVERSIBLE, Policy, effective_policy
from veil.persona.schema import Persona
from veil.persona.walk import EntityKind, PairRecord, iter_pair_records
from veil.text.normalize import canon

GENERATED = frozenset({Policy.FPE, Policy.SHIFT})
NOT_TRANSLATED = frozenset({Policy.KEEP, Policy.ASK})


@dataclass(frozen=True, slots=True)
class Entity:
    id: str  # first source path; for reporting only
    sources: tuple[str, ...]
    kind: EntityKind
    role: str
    real_forms: tuple[str, ...]
    fake_forms: tuple[str, ...]  # aligned with real_forms, or () when needs_generation
    policy: Policy
    needs_generation: bool
    reversible: bool
    contexts: tuple[str, ...]
    allow_short: bool
    meta: tuple[tuple[str, str], ...]

    def meta_value(self, key: str, default: str = "") -> str:
        return dict(self.meta).get(key, default)

    def __repr__(self) -> str:
        return (
            f"Entity(id={self.id!r}, kind={self.kind.value}, policy={self.policy.value}, "
            f"forms={len(self.real_forms)}, sources={len(self.sources)})"
        )


@dataclass(frozen=True, slots=True)
class SensitiveTerm:
    category: str
    terms: tuple[str, ...]
    generalized: str
    policy: Policy

    def __repr__(self) -> str:
        return f"SensitiveTerm(category={self.category!r}, terms={len(self.terms)})"


@dataclass(frozen=True, slots=True)
class PatternRule:
    kind: str  # "ip" | "mac"
    policy: Policy


@dataclass(frozen=True, slots=True)
class Settings:
    fidelity: str
    date_shift_days: int
    ask_timeout_seconds: int
    sensitive_default: Policy


@dataclass(frozen=True, slots=True)
class AcademicProfile:
    """One education entry's class terms, for phrase templates and context guards (M1.5).

    Holds real values: repr shows the path only.
    """

    path: str  # education[i]
    degree_enabled: bool
    degree_real: str
    degree_fake: str
    year_enabled: bool
    year_real: str
    year_fake: str
    year_context_required: bool
    context_real: tuple[str, ...]  # institution + aliases + declared degree phrases
    context_fake: tuple[str, ...]

    def __repr__(self) -> str:
        return f"AcademicProfile(path={self.path!r})"


@dataclass(frozen=True, slots=True)
class FlatPersona:
    entities: tuple[Entity, ...]
    sensitive: tuple[SensitiveTerm, ...]
    pattern_rules: tuple[PatternRule, ...]
    never_translate: frozenset[str]
    never_reverse: frozenset[str]
    settings: Settings
    canary: str
    academic: tuple[AcademicProfile, ...] = ()

    def __repr__(self) -> str:
        return (
            f"FlatPersona(entities={len(self.entities)}, sensitive={len(self.sensitive)}, "
            f"pattern_rules={len(self.pattern_rules)})"
        )


def flatten(persona: Persona) -> FlatPersona:
    merged: dict[tuple[object, ...], Entity] = {}
    for record in iter_pair_records(persona):
        entity = _to_entity(record)
        if entity is None:
            continue
        key = (
            tuple(canon(f) for f in entity.real_forms),
            tuple(canon(f) for f in entity.fake_forms),
            entity.policy,
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = entity
        else:
            merged[key] = _merge(existing, entity)
    return FlatPersona(
        entities=tuple(merged.values()),
        sensitive=_sensitive(persona),
        pattern_rules=_pattern_rules(persona),
        never_translate=frozenset(t for t in persona.never_translate if t.strip()),
        never_reverse=frozenset(t for t in persona.never_reverse if t.strip()),
        settings=Settings(
            fidelity=persona.fidelity,
            date_shift_days=persona.numbers.date_shift_days,
            ask_timeout_seconds=persona.sensitive.ask_timeout_seconds,
            sensitive_default=persona.sensitive.default_policy,
        ),
        canary=persona.veil_canary,
        academic=_academic(persona),
    )


def _academic(persona: Persona) -> tuple[AcademicProfile, ...]:
    profiles: list[AcademicProfile] = []
    for i, edu in enumerate(persona.education):
        degree, year = edu.degree, edu.year_of_study
        if not (degree.enabled and degree.real.strip()) and not (
            year.enabled and year.real is not None
        ):
            continue
        # Only forms that are themselves translated: the bare degree term ("MS") is not, so it
        # could satisfy a guard forward but not in reverse (the round trip would break).
        context_real = [edu.institution.real, *edu.aliases.real, *degree.phrases.real]
        context_fake = [edu.institution.fake, *edu.aliases.fake, *degree.phrases.fake]
        profiles.append(
            AcademicProfile(
                path=f"education[{i}]",
                degree_enabled=degree.enabled,
                degree_real=degree.real,
                degree_fake=degree.fake,
                year_enabled=year.enabled,
                year_real="" if year.real is None else str(year.real),
                year_fake="" if year.fake is None else str(year.fake),
                year_context_required=year.context_required,
                context_real=tuple(c for c in context_real if c.strip()),
                context_fake=tuple(c for c in context_fake if c.strip()),
            )
        )
    return tuple(profiles)


def _to_entity(record: PairRecord) -> Entity | None:
    if not record.enabled:
        return None
    policy = effective_policy(record.policy, record.path)
    if policy in NOT_TRANSLATED:
        return None
    pairs = [
        (real, fake)
        for real, fake in zip_longest(record.reals, record.fakes, fillvalue=None)
        if real is not None and fake is not None and real.strip()
    ]
    if not pairs:
        return None
    reals = tuple(real for real, _ in pairs)
    fakes = tuple(fake for _, fake in pairs)
    needs_generation = False
    if all(not fake.strip() for fake in fakes):
        if policy not in GENERATED:
            return None  # E016: a fake is required (the validator reports it)
        needs_generation = True
        fakes = ()
    elif any(not fake.strip() for fake in fakes):
        return None  # partially filled: E016 again; never emit a half-usable entity
    elif all(canon(real) == canon(fake) for real, fake in pairs):
        return None  # identical on both sides: nothing to translate (I002)
    return Entity(
        id=record.path,
        sources=(record.path,),
        kind=record.kind,
        role=record.role,
        real_forms=reals,
        fake_forms=fakes,
        policy=policy,
        needs_generation=needs_generation,
        reversible=policy in REVERSIBLE,
        contexts=tuple(c for c in record.contexts if c.strip()),
        allow_short=record.allow_short,
        meta=record.meta,
    )


def _merge(first: Entity, other: Entity) -> Entity:
    return Entity(
        id=first.id,
        sources=(*first.sources, *other.sources),
        kind=first.kind,
        role=first.role,
        real_forms=first.real_forms,
        fake_forms=first.fake_forms,
        policy=first.policy,
        needs_generation=first.needs_generation,
        reversible=first.reversible,
        contexts=tuple(dict.fromkeys((*first.contexts, *other.contexts))),
        allow_short=first.allow_short or other.allow_short,
        meta=tuple(dict.fromkeys((*first.meta, *other.meta))),
    )


def _sensitive(persona: Persona) -> tuple[SensitiveTerm, ...]:
    out: list[SensitiveTerm] = []
    section = persona.sensitive
    for category in ("health", "religion", "caste", "political", "sexuality"):
        entry = getattr(section, category)
        terms = tuple(t for t in entry.real if t.strip())
        if not terms:
            continue
        out.append(
            SensitiveTerm(
                category=category,
                terms=terms,
                generalized=entry.generalized,
                policy=entry.policy or section.default_policy,
            )
        )
    return tuple(out)


def _pattern_rules(persona: Persona) -> tuple[PatternRule, ...]:
    rules: list[PatternRule] = []
    for kind, node, path in (
        ("ip", persona.infra.ip_addresses, "infra.ip_addresses"),
        ("mac", persona.infra.mac_addresses, "infra.mac_addresses"),
    ):
        policy = effective_policy(node.policy, path)
        if policy not in NOT_TRANSLATED:
            rules.append(PatternRule(kind=kind, policy=policy))
    return tuple(rules)
