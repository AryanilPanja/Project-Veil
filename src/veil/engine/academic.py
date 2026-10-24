"""Class terms: degree and year of study as identity *phrases* (spec v0.2 §5.8, M1.5).

The bare tokens never match: "MS" (500 ms, MS Word, Microsoft) and "2" (Block 2, 2 apples) stay
as they are. Only phrases that state an identity are translated:

- degree d → D (when enabled): templates such as "d student", "my d", "an d" (with the right
  article on each side: "an MS" → "a PhD"), plus the phrases the user declared;
- year of study n → m (when enabled): ordinal phrases "2nd year", "second year", "2nd-year",
  "II year", "year 2" … and, when `context_required` (the default), only if one of that education
  entry's institution forms or degree phrases occurs within YEAR_WINDOW characters. Reverse
  translation uses their fake counterparts. Context keywords are always forms that are
  themselves translated, never the bare degree term: otherwise a guard could hold forward but
  not in reverse, and the round trip would break.

Templates are generated, not declared, so a template that collides with an existing form is
dropped (never an error), like the derived identifiers of M1.2.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace

from veil.engine.variants import ExpandedEntity, expand
from veil.persona.entities import AcademicProfile, Entity
from veil.persona.policy import Policy
from veil.persona.walk import EntityKind
from veil.text.normalize import canon

YEAR_WINDOW = 50
DEGREE_TEMPLATES = (
    "{d} student",
    "{d} students",
    "{d} thesis",
    "{d} degree",
    "{d} program",
    "{d} programme",
    "{d} candidate",
    "{d} scholar",
    "my {d}",
    "{a} {d}",
)
ORDINAL_WORDS = (
    "first",
    "second",
    "third",
    "fourth",
    "fifth",
    "sixth",
    "seventh",
    "eighth",
    "ninth",
    "tenth",
)
ROMAN = ("I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X")


@dataclass(frozen=True, slots=True)
class ClassTermForms:
    """Forward and reverse expanded entities (reverse needs the fake-side context keywords)."""

    forward: ExpandedEntity
    reverse_entity: Entity


def class_term_forms(
    profiles: Sequence[AcademicProfile], taken_real: set[str], taken_fake: set[str]
) -> list[ClassTermForms]:
    out: list[ClassTermForms] = []
    for profile in profiles:
        degree = _degree_entity(profile)
        for entity in (degree, _year_entity(profile, degree)):
            if entity is None:
                continue
            pairs = [
                (r, f)
                for r, f in zip(entity.real_forms, entity.fake_forms, strict=True)
                if canon(r) not in taken_real and canon(f) not in taken_fake
            ]
            if not pairs:
                continue
            for r, f in pairs:
                taken_real.add(canon(r))
                taken_fake.add(canon(f))
            entity = replace(
                entity,
                real_forms=tuple(r for r, _ in pairs),
                fake_forms=tuple(f for _, f in pairs),
            )
            reverse_entity = replace(entity, contexts=_reverse_contexts(entity, profile, degree))
            out.append(ClassTermForms(expand(entity), reverse_entity))
    return out


# ── degree ────────────────────────────────────────────────────────────────────


def _degree_entity(profile: AcademicProfile) -> Entity | None:
    d, big_d = profile.degree_real.strip(), profile.degree_fake.strip()
    if not profile.degree_enabled or not d or not big_d or canon(d) == canon(big_d):
        return None
    pairs = [
        (t.format(d=d, a=article(d)), t.format(d=big_d, a=article(big_d))) for t in DEGREE_TEMPLATES
    ]
    return _entity(f"{profile.path}.degree~templates", pairs, contexts=(), window=None)


def article(term: str) -> str:
    """'a' or 'an' by sound: acronyms by letter name ("an MS", "an MBA"), words by vowel."""
    if term.isupper() and len(term.replace(".", "")) <= 5:
        return "an" if term[0] in "AEFHILMNORSX" else "a"
    return "an" if term[:1].lower() in "aeiou" else "a"


# ── year of study ─────────────────────────────────────────────────────────────


def _year_entity(profile: AcademicProfile, degree: Entity | None) -> Entity | None:
    if not profile.year_enabled:
        return None
    try:
        n, m = int(profile.year_real), int(profile.year_fake)
    except ValueError:
        return None
    if not (1 <= n <= len(ROMAN) and 1 <= m <= len(ROMAN)) or n == m:
        return None
    pairs = list(zip(ordinal_phrases(n), ordinal_phrases(m), strict=True))
    templates = degree.real_forms if degree else ()
    contexts = (*profile.context_real, *templates) if profile.year_context_required else ()
    return _entity(f"{profile.path}.year_of_study~ordinals", pairs, contexts, YEAR_WINDOW)


def ordinal_phrases(n: int) -> list[str]:
    nth = f"{n}{ordinal_suffix(n)}"
    word = ORDINAL_WORDS[n - 1]
    return [
        f"{nth} year",
        f"{nth}-year",
        f"{nth} yr",
        f"{word} year",
        f"{word}-year",
        f"{ROMAN[n - 1]} year",
        f"year {n}",
        f"year {word}",
    ]


def ordinal_suffix(n: int) -> str:
    if 10 <= n % 100 <= 20:
        return "th"
    return {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")


# ── helpers ───────────────────────────────────────────────────────────────────


def _entity(
    id_: str, pairs: Iterable[tuple[str, str]], contexts: tuple[str, ...], window: int | None
) -> Entity:
    pairs = list(pairs)
    meta = (("context_window", str(window)),) if window is not None else ()
    return Entity(
        id=id_,
        sources=(id_.split("~")[0],),
        kind=EntityKind.CLASS_TERM,
        role="class_term",
        real_forms=tuple(r for r, _ in pairs),
        fake_forms=tuple(f for _, f in pairs),
        policy=Policy.SWAP,
        needs_generation=False,
        reversible=True,
        contexts=contexts,
        allow_short=False,
        meta=meta,
    )


def _reverse_contexts(
    entity: Entity, profile: AcademicProfile, degree: Entity | None
) -> tuple[str, ...]:
    """The fake-side counterparts of the forward context keywords (all translated forms)."""
    if not entity.contexts:
        return ()
    return (*profile.context_fake, *(degree.fake_forms if degree else ()))
