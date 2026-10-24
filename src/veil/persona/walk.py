"""Walk a parsed Persona and yield every real/fake pair as a PairRecord, in schema order.

The walk is explicit per section (not reflective) so every field's kind and role is a
deliberate choice; a test checks that no Pair/ListPair field of the schema is left unvisited.

Grouping rules (one record, several forms):
- institution + aliases, lab + aliases, hometown + hometown_aliases, domain + sub_domains,
  advisor + advisor.forms;
- degree: only the identity phrases (the bare degree word is never matched, ADR-0010);
- year of study: one record with the numbers as text (M1 generates the ordinal phrases).
Not walked: advisor.title (template material, not an identity), footprint.profile_urls_to_index
(later), sensitive.* (they become SensitiveTerms), infra.ip/mac (pattern rules).
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum

from veil.persona.fieldpath import child, item
from veil.persona.policy import Policy
from veil.persona.schema import (
    Advisor,
    ClassTerm,
    Education,
    LabPair,
    ListPair,
    Pair,
    Persona,
    Pet,
    YearOfStudy,
)


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


@dataclass(frozen=True)
class PairRecord:
    path: str
    kind: EntityKind
    role: str
    reals: tuple[str, ...]
    fakes: tuple[str, ...]
    policy: Policy | None = None
    allow_short: bool = False
    contexts: tuple[str, ...] = ()
    enabled: bool = True
    meta: tuple[tuple[str, str], ...] = field(default=())
    # Grouped records: forms [0, head_forms) come from the head pair at `path`, the rest from the
    # index-aligned list at `list_path` (e.g. education[0].aliases).
    list_path: str = ""
    head_forms: int = 1

    def form_path(self, index: int) -> str:
        """Field path of one form, for findings (e.g. education[0].aliases[1])."""
        if not self.list_path or index < self.head_forms:
            return self.path
        return item(self.list_path, index - self.head_forms)

    def __repr__(self) -> str:  # never show values
        return f"PairRecord(path={self.path!r}, kind={self.kind.value}, forms={len(self.reals)})"


def iter_pair_records(persona: Persona) -> Iterator[PairRecord]:
    yield from _person(persona)
    yield from _many_pairs(persona.emails, "emails", EntityKind.EMAIL, "email")
    yield from _many_pairs(persona.phones, "phones", EntityKind.PHONE, "phone")
    yield from _handles(persona)
    for i, edu in enumerate(persona.education):
        yield from _education(edu, item("education", i))
    for i, work in enumerate(persona.work):
        base = item("work", i)
        yield _pair(work.employer, child(base, "employer"), EntityKind.ORG, "employer")
        yield _pair(work.team, child(base, "team"), EntityKind.ORG, "team")
        yield _pair(work.manager, child(base, "manager"), EntityKind.PERSON_NAME, "manager")
        yield _pair(
            work.employee_id, child(base, "employee_id"), EntityKind.IDENTIFIER, "employee_id"
        )
        yield _pair(work.role, child(base, "role"), EntityKind.TOKEN, "job_role")
    for i, ref in enumerate(persona.people):
        role = ref.relation or "other"
        yield _pair(
            ref, item("people", i), EntityKind.PERSON_NAME, role, meta=(("relation", role),)
        )
    yield from _infra(persona)
    yield from _ids(persona)
    yield from _attributes(persona)
    yield from _footprint(persona)


# ── Sections ──────────────────────────────────────────────────────────────────


def _person(persona: Persona) -> Iterator[PairRecord]:
    p = persona.person
    base = "person"
    for name, role in (
        ("first_name", "given"),
        ("short_name", "short"),
        ("last_name", "family"),
        ("full_name", "full"),
        ("middle_name", "middle"),
    ):
        yield _pair(getattr(p, name), child(base, name), EntityKind.NAME, role)
    yield from _many_pairs(p.nicknames, child(base, "nicknames"), EntityKind.NAME, "nickname")
    yield from _many_pairs(
        p.name_in_other_scripts, child(base, "name_in_other_scripts"), EntityKind.NAME, "script"
    )
    yield _pair(p.gender, child(base, "gender"), EntityKind.TOKEN, "gender")
    yield _pair(p.pronouns, child(base, "pronouns"), EntityKind.TOKEN, "pronouns")
    yield _pair(p.date_of_birth, child(base, "date_of_birth"), EntityKind.DATE, "date_of_birth")
    yield _grouped(
        p.hometown,
        p.hometown_aliases,
        child(base, "hometown"),
        child(base, "hometown_aliases"),
        EntityKind.PLACE,
        "hometown",
    )
    yield _pair(p.home_state, child(base, "home_state"), EntityKind.PLACE, "home_state")
    yield _pair(p.current_city, child(base, "current_city"), EntityKind.PLACE, "current_city")
    yield _pair(p.languages, child(base, "languages"), EntityKind.TOKEN, "languages")


def _handles(persona: Persona) -> Iterator[PairRecord]:
    h = persona.handles
    base = "handles"
    yield _pair(h.linux_user, child(base, "linux_user"), EntityKind.USERNAME, "linux_user")
    for name in (
        "github",
        "gitlab",
        "linkedin",
        "twitter_x",
        "discord",
        "leetcode",
        "kaggle",
        "huggingface",
        "google_scholar_id",
        "orcid",
    ):
        yield _pair(getattr(h, name), child(base, name), EntityKind.HANDLE, name)
    yield _pair(h.personal_website, child(base, "personal_website"), EntityKind.DOMAIN, "website")
    yield from _many_pairs(h.upi_ids, child(base, "upi_ids"), EntityKind.HANDLE, "upi")


def _education(edu: Education, base: str) -> Iterator[PairRecord]:
    yield _grouped(
        edu.institution,
        edu.aliases,
        child(base, "institution"),
        child(base, "aliases"),
        EntityKind.ORG,
        "institution",
    )
    yield _grouped(
        edu.domain,
        edu.sub_domains,
        child(base, "domain"),
        child(base, "sub_domains"),
        EntityKind.DOMAIN,
        "domain",
    )
    yield _pair(edu.department, child(base, "department"), EntityKind.ORG, "department")
    yield _lab(edu.lab, child(base, "lab"))
    degree = _degree(edu.degree, child(base, "degree"))
    if degree is not None:
        yield degree
    year = _year(edu.year_of_study, child(base, "year_of_study"))
    if year is not None:
        yield year
    yield _pair(edu.batch_year, child(base, "batch_year"), EntityKind.TOKEN, "batch_year")
    yield _advisor(edu.advisor, child(base, "advisor"))
    yield _pair(edu.research_area, child(base, "research_area"), EntityKind.TEXT, "research_area")
    yield _pair(edu.roll_number, child(base, "roll_number"), EntityKind.IDENTIFIER, "roll_number")
    yield _pair(edu.hostel_room, child(base, "hostel_room"), EntityKind.ADDRESS, "hostel_room")
    yield _pair(edu.board, child(base, "board"), EntityKind.ORG, "board")


def _infra(persona: Persona) -> Iterator[PairRecord]:
    f = persona.infra
    base = "infra"
    yield _pair(f.hostname, child(base, "hostname"), EntityKind.HOSTNAME, "hostname")
    yield _pair(f.home_dir, child(base, "home_dir"), EntityKind.PATH, "home_dir")
    yield from _many_pairs(f.clusters, child(base, "clusters"), EntityKind.HOSTNAME, "cluster")
    yield from _many_pairs(
        f.cluster_usernames, child(base, "cluster_usernames"), EntityKind.USERNAME, "cluster_user"
    )
    yield from _many_pairs(
        f.slurm_accounts, child(base, "slurm_accounts"), EntityKind.TOKEN, "slurm_account"
    )
    yield from _many_pairs(f.wifi_ssids, child(base, "wifi_ssids"), EntityKind.TOKEN, "wifi_ssid")
    yield from _many_pairs(f.private_repos, child(base, "private_repos"), EntityKind.TOKEN, "repo")


def _ids(persona: Persona) -> Iterator[PairRecord]:
    d = persona.ids
    base = "ids"
    for name in ("aadhaar", "pan", "passport", "voter_id", "driving_licence", "ifsc"):
        yield _pair(getattr(d, name), child(base, name), EntityKind.IDENTIFIER, name)
    yield from _many_pairs(
        d.bank_accounts, child(base, "bank_accounts"), EntityKind.IDENTIFIER, "bank_account"
    )
    yield from _many_pairs(d.cards, child(base, "cards"), EntityKind.IDENTIFIER, "card")
    yield from _many_pairs(d.address, child(base, "address"), EntityKind.ADDRESS, "address")
    yield from _many_pairs(d.pin_codes, child(base, "pin_codes"), EntityKind.POSTAL_CODE, "pin")


def _attributes(persona: Persona) -> Iterator[PairRecord]:
    a = persona.attributes
    base = "attributes"
    for i, pet in enumerate(a.pets):
        yield from _pet(pet, item(child(base, "pets"), i))
    for name, kind in (
        ("first_pet_name", EntityKind.PET_NAME),
        ("first_school", EntityKind.ORG),
        ("childhood_street", EntityKind.ADDRESS),
        ("favourite_food", EntityKind.TOKEN),
        ("favourite_sport_team", EntityKind.TOKEN),
        ("favourite_movie_book", EntityKind.TOKEN),
    ):
        yield _pair(getattr(a, name), child(base, name), kind, name)
    yield from _many_pairs(a.hobbies, child(base, "hobbies"), EntityKind.TOKEN, "hobby")
    yield _pair(a.vehicle, child(base, "vehicle"), EntityKind.IDENTIFIER, "vehicle")
    for i, custom in enumerate(a.custom):
        category = custom.category or "custom"
        yield _pair(
            custom,
            item(child(base, "custom"), i),
            EntityKind.TOKEN,
            category,
            meta=(("category", category),),
        )


def _footprint(persona: Persona) -> Iterator[PairRecord]:
    fp = persona.footprint
    base = "footprint"
    yield from _many_pairs(fp.paper_titles, child(base, "paper_titles"), EntityKind.TEXT, "paper")
    yield _pair(fp.thesis_title, child(base, "thesis_title"), EntityKind.TEXT, "thesis")
    yield from _many_pairs(
        fp.public_repo_names, child(base, "public_repo_names"), EntityKind.TOKEN, "public_repo"
    )


# ── Builders ──────────────────────────────────────────────────────────────────


def _pair(
    pair: Pair,
    path: str,
    kind: EntityKind,
    role: str,
    *,
    meta: tuple[tuple[str, str], ...] = (),
    policy: Policy | None = None,
) -> PairRecord:
    return PairRecord(
        path=path,
        kind=kind,
        role=role,
        reals=(pair.real,),
        fakes=(pair.fake,),
        policy=pair.policy if pair.policy is not None else policy,
        allow_short=pair.allow_short,
        contexts=pair.contexts,
        enabled=pair.enabled,
        meta=meta,
    )


def _many_pairs(
    pairs: tuple[Pair, ...], base: str, kind: EntityKind, role: str
) -> Iterator[PairRecord]:
    for i, pair in enumerate(pairs):
        yield _pair(pair, item(base, i), kind, role)


def _grouped(
    head: Pair, extra: ListPair, path: str, list_path: str, kind: EntityKind, role: str
) -> PairRecord:
    record = _pair(head, path, kind, role)
    return _with_forms(record, (head.real, *extra.real), (head.fake, *extra.fake), list_path)


def _lab(lab: LabPair, path: str) -> PairRecord:
    return _grouped(lab, lab.aliases, path, child(path, "aliases"), EntityKind.ORG, "lab")


def _advisor(advisor: Advisor, path: str) -> PairRecord:
    return PairRecord(
        path=path,
        kind=EntityKind.PERSON_NAME,
        role="advisor",
        reals=(advisor.real, *advisor.forms.real),
        fakes=(advisor.fake, *advisor.forms.fake),
        list_path=child(path, "forms"),
    )


def _degree(degree: ClassTerm, path: str) -> PairRecord | None:
    if not degree.phrases.real:
        return None
    return PairRecord(
        path=child(path, "phrases"),
        kind=EntityKind.CLASS_TERM,
        role="degree",
        reals=degree.phrases.real,
        fakes=degree.phrases.fake,
        enabled=degree.enabled,
        list_path=child(path, "phrases"),
        head_forms=0,
    )


def _year(year: YearOfStudy, path: str) -> PairRecord | None:
    if year.real is None or year.fake is None:
        return None
    return PairRecord(
        path=path,
        kind=EntityKind.YEAR,
        role="year_of_study",
        reals=(str(year.real),),
        fakes=(str(year.fake),),
        enabled=year.enabled,
        meta=(("context_required", "true" if year.context_required else "false"),),
    )


def _pet(pet: Pet, base: str) -> Iterator[PairRecord]:
    # Pet-level policy: SWAP_NAME_ONLY (or unset) swaps the name and keeps species and breed,
    # so advice about the animal stays correct. SWAP swaps all three; KEEP keeps all three.
    level = pet.policy or Policy.SWAP_NAME_ONLY
    name_policy = Policy.SWAP if level in (Policy.SWAP_NAME_ONLY, Policy.SWAP) else level
    other_policy = Policy.KEEP if level is Policy.SWAP_NAME_ONLY else level
    yield _pair(pet.name, child(base, "name"), EntityKind.PET_NAME, "pet_name", policy=name_policy)
    yield _pair(
        pet.species, child(base, "species"), EntityKind.TOKEN, "pet_species", policy=other_policy
    )
    yield _pair(pet.breed, child(base, "breed"), EntityKind.TOKEN, "pet_breed", policy=other_policy)


def _with_forms(
    record: PairRecord, reals: tuple[str, ...], fakes: tuple[str, ...], list_path: str
) -> PairRecord:
    return PairRecord(
        path=record.path,
        kind=record.kind,
        role=record.role,
        reals=reals,
        fakes=fakes,
        policy=record.policy,
        allow_short=record.allow_short,
        contexts=record.contexts,
        enabled=record.enabled,
        meta=record.meta,
        list_path=list_path,
    )
