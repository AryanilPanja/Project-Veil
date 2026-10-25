"""The flattened persona model: the M0 → M1 contract, with no pydantic or YAML imports.

Kept free of heavy imports on purpose: the engine's warm path (the encrypted lexicon cache,
ADR-0029) loads these classes without importing the persona schema. `entities.py` builds them
from a parsed persona (`flatten`) and re-exports them.

repr() of every object here is redacted: entities hold real values.
"""

from dataclasses import dataclass
from enum import StrEnum

from veil.persona.policy import Policy


class EntityKind(StrEnum):
    NAME = "name"  # the owner's own names
    PERSON_NAME = "person_name"  # other people: family, friends, advisor, manager
    EMAIL = "email"
    PHONE = "phone"
    USERNAME = "username"
    HANDLE = "handle"
    ORG = "org"
    DOMAIN = "domain"
    PLACE = "place"
    ADDRESS = "address"
    POSTAL_CODE = "postal_code"
    PATH = "path"
    HOSTNAME = "hostname"
    IDENTIFIER = "identifier"
    DATE = "date"
    CLASS_TERM = "class_term"  # identity phrases such as "MS student"
    YEAR = "year"  # year of study (numbers; ordinal phrases generated in M1)
    PET_NAME = "pet_name"
    TOKEN = "token"  # noqa: S105 - an entity kind, not a credential. Other short strings
    TEXT = "text"  # longer phrases (paper titles, research area)


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
