"""Cross-field rules, warnings and notes (validator part 2).

Errors:
  E017  institutional email: the fake must use the fake institution domain
  E018  year of study / batch year must be complete and shift consistently
  E019  degree phrases: present when enabled, and multi-word (never the bare degree)
  E020  a policy used where it is not allowed
  E021  a sensitive generalized phrase contains a listed sensitive term (it would be sent)
  E022  FPE/SHIFT with some fakes filled and some empty (emitted in validate.py)
Warnings:
  W101  short form without allow_short/contexts (emitted in validate.py)
  W102  a family member's fake does not use the fake surname
  W103  a fake under KEEP (or kept species/breed) is ignored
  W104  a fake without a real value is ignored
  W105  spaces at the ends, Unicode that changes under normalization, or "null" written as text
  W106  a never_translate token equals a real value (that value is never translated)
  W107  a never_reverse entry contains none of the fake forms (no effect)
  W108  SHIFT with an empty fake while date_shift_days is 0 (no change)
  W109  a sensitive term overlaps a persona value
  W110  full name = first + last on the real side but not on the fake side
  W111  unknown people[].relation
  W112  a value made only of invisible characters is ignored (emitted in validate.py)
  W113  a value kept unchanged occurs inside a fake (emitted in validate.py)
Notes (validate.py): I001 fake will be generated, I002 real == fake (treated as KEEP).

Every message is a fixed template plus field paths (and, for E018, the required year delta).
"""

from collections.abc import Iterable, Sequence

from veil.persona.fieldpath import child, item
from veil.persona.policy import Policy, effective_policy, is_allowed
from veil.persona.report import Finding, Severity
from veil.persona.schema import Persona
from veil.persona.walk import PairRecord
from veil.text.containment import contains_bounded
from veil.text.normalize import canon, nfkc

KNOWN_RELATIONS = frozenset(
    {
        "father",
        "mother",
        "mother_maiden_name",
        "sibling",
        "partner",
        "spouse",
        "child",
        "relative",
        "friend",
        "labmate",
        "roommate",
        "colleague",
        "manager",
        "mentor",
        "other",
    }
)
FAMILY = frozenset({"father", "mother", "sibling"})
NULL_WORDS = frozenset({"null", "none", "nil", "~"})
PET_POLICIES = frozenset({Policy.SWAP_NAME_ONLY, Policy.SWAP, Policy.KEEP})
PATTERN_POLICIES = frozenset({Policy.FPE, Policy.KEEP})
SENSITIVE_POLICIES = frozenset({Policy.ASK, Policy.KEEP, Policy.GENERALIZE})


def cross_field_findings(persona: Persona, records: Sequence[PairRecord]) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_institutional_emails(persona))
    findings.extend(_academic(persona))
    findings.extend(_policy_placement(persona, records))
    findings.extend(_record_warnings(persona, records))
    findings.extend(_family_surnames(persona))
    findings.extend(_full_name(persona))
    findings.extend(_relations(persona))
    findings.extend(_never_lists(persona, records))
    findings.extend(_sensitive_overlap(persona, records))
    return findings


# ── E017 ──────────────────────────────────────────────────────────────────────


def _institutional_emails(persona: Persona) -> Iterable[Finding]:
    domains: dict[str, tuple[str, str]] = {}  # real domain → (fake domain, path)
    for i, edu in enumerate(persona.education):
        base = item("education", i)
        candidates = [(edu.domain.real, edu.domain.fake, child(base, "domain"))]
        candidates += [
            (r, f, item(child(base, "sub_domains"), j))
            for j, (r, f) in enumerate(
                zip(edu.sub_domains.real, edu.sub_domains.fake, strict=False)
            )
        ]
        for real, fake, path in candidates:
            if real.strip() and fake.strip():
                domains[_domain(real)] = (_domain(fake), path)
    if not domains:
        return
    for i, email in enumerate(persona.emails):
        path = item("emails", i)
        real, fake = email.real.strip(), email.fake.strip()
        if "@" not in real or not fake:
            continue
        if effective_policy(email.policy, path) in (Policy.KEEP, Policy.ASK):
            continue
        real_domain = _domain(real.rsplit("@", 1)[1])
        matches = [d for d in domains if real_domain == d or real_domain.endswith("." + d)]
        if not matches:
            continue
        institution_domain = max(matches, key=len)
        fake_domain, source = domains[institution_domain]
        expected = real_domain[: len(real_domain) - len(institution_domain)] + fake_domain
        if "@" not in fake:
            yield _error("E017", path, "institutional email: the fake has no @domain")
        elif _domain(fake.rsplit("@", 1)[1]) != expected:
            yield _error(
                "E017",
                path,
                f"institutional email: the fake must use the fake domain from {source}",
            )


def _domain(text: str) -> str:
    return text.strip().strip(".").lower()


# ── E018, E019 ────────────────────────────────────────────────────────────────


def _academic(persona: Persona) -> Iterable[Finding]:
    for i, edu in enumerate(persona.education):
        base = item("education", i)
        year = edu.year_of_study
        year_path = child(base, "year_of_study")
        if year.enabled:
            if year.real is None or year.fake is None:
                yield _error("E018", year_path, "enabled, but needs both a real and a fake year")
            else:
                yield from _batch(edu.batch_year.real, edu.batch_year.fake, year, base)
        degree = edu.degree
        phrases_path = child(child(base, "degree"), "phrases")
        if degree.enabled:
            if not any(p.strip() for p in degree.phrases.real):
                yield _error("E019", phrases_path, "the degree is enabled but has no phrases")
            for side, values in (("real", degree.phrases.real), ("fake", degree.phrases.fake)):
                for j, phrase in enumerate(values):
                    if phrase.strip() and len(canon(phrase).split(" ")) < 2:
                        yield _error(
                            "E019",
                            item(phrases_path, j),
                            f"{side} phrase must be several words (e.g. 'MS student'), "
                            "never the bare degree",
                        )


def _batch(real: str, fake: str, year, base: str) -> Iterable[Finding]:
    path = child(base, "batch_year")
    real, fake = real.strip(), fake.strip()
    if not real or not fake:
        return
    if not (real.isdigit() and fake.isdigit() and len(real) == 4 and len(fake) == 4):
        yield _error("E018", path, "must be a 4-digit year when the year of study is translated")
        return
    expected = -(year.fake - year.real)
    if int(fake) - int(real) != expected:
        yield _error(
            "E018",
            path,
            f"the batch (admission) year must shift by {expected:+d} to match the year-of-study "
            "shift",
        )


# ── E020 ──────────────────────────────────────────────────────────────────────


def _policy_placement(persona: Persona, records: Sequence[PairRecord]) -> Iterable[Finding]:
    for record in records:
        if record.policy is not None and not is_allowed(record.policy, record.path):
            yield _error("E020", record.path, f"policy {record.policy.value} is not allowed here")
    for i, pet in enumerate(persona.attributes.pets):
        if pet.policy is not None and pet.policy not in PET_POLICIES:
            yield _error(
                "E020",
                item(child("attributes", "pets"), i),
                f"policy {pet.policy.value} is not allowed for pets "
                "(use SWAP_NAME_ONLY, SWAP or KEEP)",
            )
    for name in ("ip_addresses", "mac_addresses"):
        node = getattr(persona.infra, name)
        if node.policy is not None and node.policy not in PATTERN_POLICIES:
            yield _error(
                "E020",
                child("infra", name),
                f"policy {node.policy.value} is not allowed here (use FPE or KEEP)",
            )
    section = persona.sensitive
    if section.default_policy not in SENSITIVE_POLICIES:
        yield _error(
            "E020",
            "sensitive.default_policy",
            f"policy {section.default_policy.value} is not allowed (use ASK, GENERALIZE or KEEP)",
        )
    categories = ("health", "religion", "caste", "political", "sexuality")
    all_terms = [t for c in categories for t in getattr(section, c).real if canon(t)]
    for category in categories:
        entry = getattr(section, category)
        path = child("sensitive", category)
        policy = entry.policy or section.default_policy
        if entry.policy is not None and entry.policy not in SENSITIVE_POLICIES:
            yield _error(
                "E020",
                path,
                f"policy {entry.policy.value} is not allowed (use ASK, GENERALIZE or KEEP)",
            )
        if (
            policy is Policy.GENERALIZE
            and any(canon(t) for t in entry.real)
            and not canon(entry.generalized)
        ):
            yield _error(
                "E020", child(path, "generalized"), "GENERALIZE needs a generalized phrase"
            )
        if canon(entry.generalized) and any(
            contains_bounded(term, entry.generalized) for term in all_terms
        ):
            yield _error(
                "E021",
                child(path, "generalized"),
                "the generalized phrase contains a listed sensitive term (it would be sent)",
            )


# ── Per-record warnings: W103, W104, W105, W108 ───────────────────────────────


def _record_warnings(persona: Persona, records: Sequence[PairRecord]) -> Iterable[Finding]:
    shift_days = persona.numbers.date_shift_days
    for record in records:
        if not record.enabled:
            continue
        policy = effective_policy(record.policy, record.path)
        for i in range(max(len(record.reals), len(record.fakes))):
            real = record.reals[i] if i < len(record.reals) else ""
            fake = record.fakes[i] if i < len(record.fakes) else ""
            path = record.form_path(i)
            if not real.strip() and fake.strip():
                yield _warning("W104", path, "a fake without a real value is ignored")
            if (
                policy is Policy.KEEP
                and real.strip()
                and fake.strip()
                and canon(real) != canon(fake)
            ):
                yield _warning("W103", path, "policy KEEP: this fake is ignored")
            if policy is Policy.SHIFT and real.strip() and not fake.strip() and shift_days == 0:
                yield _warning(
                    "W108", path, "SHIFT with numbers.date_shift_days = 0 leaves the date unchanged"
                )
            for side, value in (("real", real), ("fake", fake)):
                yield from _odd_text(path, side, value)


def _odd_text(path: str, side: str, value: str) -> Iterable[Finding]:
    if not value:
        return
    if value != value.strip():
        yield _warning("W105", path, f"the {side} value has spaces at the start or end")
    if nfkc(value) != value:
        yield _warning(
            "W105",
            path,
            f"the {side} value has characters that change under Unicode normalization "
            "(it is matched in normalized form)",
        )
    if value.strip().lower() in NULL_WORDS:
        yield _warning("W105", path, f"the {side} value looks like an empty value written as text")


# ── W102, W110, W111 ──────────────────────────────────────────────────────────


def _family_surnames(persona: Persona) -> Iterable[Finding]:
    last = persona.person.last_name
    real_last, fake_last = canon(last.real), canon(last.fake)
    if not real_last or not fake_last:
        return
    for i, ref in enumerate(persona.people):
        if ref.relation not in FAMILY or not ref.real.strip() or not ref.fake.strip():
            continue
        real, fake = canon(ref.real), canon(ref.fake)
        shares_real = real == real_last or real.endswith(" " + real_last)
        shares_fake = fake == fake_last or fake.endswith(" " + fake_last)
        if shares_real and not shares_fake:
            yield _warning(
                "W102",
                item("people", i),
                "this family member's fake does not use the fake surname from person.last_name",
            )


def _full_name(persona: Persona) -> Iterable[Finding]:
    p = persona.person
    first, last, full = p.first_name, p.last_name, p.full_name
    if not all(x.real.strip() and x.fake.strip() for x in (first, last, full)):
        return
    composes_real = canon(full.real) == canon(f"{first.real} {last.real}")
    composes_fake = canon(full.fake) == canon(f"{first.fake} {last.fake}")
    if composes_real and not composes_fake:
        yield _warning(
            "W110",
            "person.full_name",
            "the real full name is first + last, but the fake full name is not",
        )


def _relations(persona: Persona) -> Iterable[Finding]:
    for i, ref in enumerate(persona.people):
        relation = ref.relation.strip()
        if relation and relation not in KNOWN_RELATIONS:
            yield _warning(
                "W111",
                child(item("people", i), "relation"),
                "unknown relation (known: " + ", ".join(sorted(KNOWN_RELATIONS)) + ")",
            )


# ── W106, W107, W109 ──────────────────────────────────────────────────────────


def _translated_forms(records: Sequence[PairRecord]) -> list[tuple[str, str, str, bool]]:
    """(path, real, fake, guarded) for every translated form."""
    out: list[tuple[str, str, str, bool]] = []
    for record in records:
        if not record.enabled:
            continue
        if effective_policy(record.policy, record.path) in (Policy.KEEP, Policy.ASK):
            continue
        guarded = any(c.strip() for c in record.contexts)
        for i, real in enumerate(record.reals):
            fake = record.fakes[i] if i < len(record.fakes) else ""
            if real.strip():
                out.append((record.form_path(i), real, fake, guarded))
    return out


def _never_lists(persona: Persona, records: Sequence[PairRecord]) -> Iterable[Finding]:
    forms = _translated_forms(records)
    for i, token in enumerate(persona.never_translate):
        if not token.strip():
            continue
        for path, real, _fake, guarded in forms:
            if not guarded and canon(real) == canon(token):
                yield _warning(
                    "W106",
                    item("never_translate", i),
                    f"equals the real value at {path}, which will then never be translated",
                )
                break
    fakes = [fake for _path, _real, fake, _g in forms if fake.strip()]
    for i, entry in enumerate(persona.never_reverse):
        if entry.strip() and not any(contains_bounded(fake, entry) for fake in fakes):
            yield _warning(
                "W107",
                item("never_reverse", i),
                "contains none of your fake forms, so it has no effect",
            )


def _sensitive_overlap(persona: Persona, records: Sequence[PairRecord]) -> Iterable[Finding]:
    forms = _translated_forms(records)
    section = persona.sensitive
    for category in ("health", "religion", "caste", "political", "sexuality"):
        for j, term in enumerate(getattr(section, category).real):
            if not term.strip():
                continue
            for path, real, fake, _guarded in forms:
                hits = [
                    v
                    for v in (real, fake)
                    if v.strip() and (contains_bounded(term, v) or contains_bounded(v, term))
                ]
                if hits:
                    yield _warning(
                        "W109",
                        item(child("sensitive", category), j),
                        f"overlaps the persona value at {path}; asking may trigger unexpectedly",
                    )
                    break


def _error(code: str, path: str, message: str) -> Finding:
    return Finding(Severity.ERROR, code, path, message)


def _warning(code: str, path: str, message: str) -> Finding:
    return Finding(Severity.WARNING, code, path, message)
