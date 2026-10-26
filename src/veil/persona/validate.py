"""Semantic validation of a parsed persona. Part 1, the bijection (ADR-0001 / ADR-0026), is
here; part 2 (cross-field errors E017-E020, warnings W101-W111, notes I001-I002) is in rules.py.

Codes (all errors):
  E010  two different real values share one fake (reverse translation would be ambiguous)
  E011  one real value is given different fakes
  E012  a fake equals a real value elsewhere
  E013  a fake occurs (bounded) inside a real value
  E014  a real value occurs (bounded) inside a fake
  E015  real/fake lists of different lengths
  E016  a real value without a fake, under a policy that cannot generate one

Excluded from the bijection checks: disabled entries, KEEP/ASK, empty real values, pairs that
are identical on both sides (nothing to translate), and the year of study (context-guarded
digits; M1 only matches it next to the degree).
GENERALIZE is one-way: two GENERALIZE fakes may coincide (no E010), but a GENERALIZE fake is
still sent out, so it must not contain a real value (E014) or equal one (E012).

`validate_forms` is the core and works on plain (path, real, fake, reversible) rows, so M1 can
re-run it on the expanded variants.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from veil.persona.policy import Policy, effective_policy
from veil.persona.report import Finding, Report, Severity, make_report
from veil.persona.schema import Persona
from veil.persona.walk import EntityKind, PairRecord, iter_pair_records
from veil.text.aho import containment_pairs
from veil.text.normalize import canon

GENERATED = frozenset({Policy.FPE, Policy.SHIFT})
NOT_TRANSLATED = frozenset({Policy.KEEP, Policy.ASK})


@dataclass(frozen=True, slots=True)
class FormRow:
    """One aligned (real, fake) form with its field path. Holds values: never print it."""

    path: str
    real: str
    fake: str  # "" when the fake will be generated (FPE/SHIFT)
    reversible: bool

    def __repr__(self) -> str:
        return f"FormRow(path={self.path!r})"


def validate(persona: Persona) -> Report:
    from veil.persona.rules import cross_field_findings  # rules.py imports helpers from here

    findings: list[Finding] = []
    rows: list[FormRow] = []
    kept: list[FormRow] = []
    records = list(iter_pair_records(persona))
    for record in records:
        rows.extend(_rows_of(record, findings, kept))
    findings.extend(validate_forms(rows, kept))
    findings.extend(cross_field_findings(persona, records))
    if not any(f.severity is Severity.ERROR for f in findings):
        findings.extend(_expanded_findings(persona))
    return make_report(findings)


def _expanded_findings(persona: Persona) -> list[Finding]:
    """The bijection over every generated variant (name joins etc.), as the engine will see it.

    Only run on an otherwise valid persona: declared-form errors would just repeat here.
    """
    from veil.engine.variants import expand_all, validate_expanded  # engine imports this module
    from veil.persona.entities import flatten

    return validate_expanded(expand_all(flatten(persona)))


def validate_forms(rows: Sequence[FormRow], kept: Sequence[FormRow] = ()) -> list[Finding]:
    """`kept`: values passed on unchanged (KEEP, or real == fake). They take part in the
    bijection too: a fake equal to one would make reverse rewrite the kept value (E012)."""
    findings: list[Finding] = []
    with_fake = [r for r in rows if canon(r.fake)]
    findings.extend(_many_to_one(with_fake))
    findings.extend(_one_to_many(with_fake))
    findings.extend(_equal_across([*rows, *kept], with_fake))
    findings.extend(_containment(rows, with_fake))
    findings.extend(_kept_inside_fakes(kept, with_fake))
    return findings


# ── Rows ──────────────────────────────────────────────────────────────────────


def _rows_of(
    record: PairRecord, findings: list[Finding], kept: list[FormRow] | None = None
) -> Iterable[FormRow]:
    kept = [] if kept is None else kept
    if not record.enabled:
        return []
    policy = effective_policy(record.policy, record.path)
    if policy in NOT_TRANSLATED:
        if policy is Policy.KEEP:
            kept.extend(
                FormRow(record.form_path(i), real, real, reversible=False)
                for i, real in enumerate(record.reals)
                if canon(real)
            )
        return []
    if record.list_path and record.reals and record.fakes:
        real_list = len(record.reals) - record.head_forms
        fake_list = len(record.fakes) - record.head_forms
        if real_list != fake_list and real_list > 0 and fake_list > 0:
            findings.append(
                _error(
                    "E015",
                    record.list_path,
                    f"real and fake lists have different lengths ({real_list} vs {fake_list})",
                )
            )
    if policy in GENERATED:
        filled = [
            bool(canon(record.fakes[i])) if i < len(record.fakes) else False
            for i, real in enumerate(record.reals)
            if canon(real)
        ]
        if any(filled) and not all(filled):
            # Generated fakes are all-or-nothing per entity: a half-filled group would be
            # dropped whole (nothing translated, not even the filled forms).
            findings.append(
                _error(
                    "E022",
                    record.path,
                    f"fill every fake or none ({policy.value} generates them all together)",
                )
            )
    rows: list[FormRow] = []
    for i, real in enumerate(record.reals):
        path = record.form_path(i)
        if not canon(real):
            # Emptiness by the canonical form: str.strip() keeps zero-width characters.
            if real.strip():
                findings.append(
                    Finding(
                        Severity.WARNING,
                        "W112",
                        path,
                        "the value is only invisible characters; it is ignored",
                    )
                )
            continue
        fake = record.fakes[i] if i < len(record.fakes) else ""
        if not canon(fake):
            if policy not in GENERATED:
                findings.append(
                    _error("E016", path, "a fake is required (or set `policy: KEEP` to pass it on)")
                )
                continue
            # The fake will be generated in M1; the real value must still never appear inside
            # anyone's fake, so it stays in as a real-only row.
            findings.append(
                Finding(Severity.INFO, "I001", path, f"the fake will be generated ({policy.value})")
            )
            findings.extend(_short_form(record, path, real, ""))
            rows.append(FormRow(path, real, "", reversible=True))
            continue
        if canon(real) == canon(fake):
            findings.append(
                Finding(Severity.INFO, "I002", path, "real and fake are the same; treated as KEEP")
            )
            kept.append(FormRow(path, real, real, reversible=False))
            continue
        if record.kind is EntityKind.YEAR:
            continue
        findings.extend(_short_form(record, path, real, fake))
        rows.append(FormRow(path, real, fake, reversible=policy is not Policy.GENERALIZE))
    return rows


SHORT = 3


def _short_form(record: PairRecord, path: str, real: str, fake: str) -> list[Finding]:
    """W101: very short forms match inside ordinary text unless explicitly allowed or guarded."""
    if record.allow_short or any(c.strip() for c in record.contexts):
        return []
    sides = [
        side for side, value in (("real", real), ("fake", fake)) if 0 < len(canon(value)) <= SHORT
    ]
    if not sides:
        return []
    return [
        Finding(
            Severity.WARNING,
            "W101",
            path,
            f"short {' and '.join(sides)} form (≤{SHORT} characters) can match ordinary text; "
            "set `allow_short: true` or add `contexts`",
        )
    ]


# ── Checks ────────────────────────────────────────────────────────────────────


def _many_to_one(rows: Sequence[FormRow]) -> Iterable[Finding]:
    first_real_for_fake: dict[str, FormRow] = {}
    for row in rows:
        if not row.reversible:
            continue
        key = canon(row.fake)
        first = first_real_for_fake.get(key)
        if first is None:
            first_real_for_fake[key] = row
        elif canon(first.real) != canon(row.real):
            yield _error(
                "E010",
                row.path,
                f"this fake is also the fake of a different real value at {first.path}",
            )


def _one_to_many(rows: Sequence[FormRow]) -> Iterable[Finding]:
    first_fake_for_real: dict[str, FormRow] = {}
    for row in rows:
        key = canon(row.real)
        first = first_fake_for_real.get(key)
        if first is None:
            first_fake_for_real[key] = row
        elif canon(first.fake) != canon(row.fake):
            yield _error("E011", row.path, f"this real value has a different fake at {first.path}")


def _equal_across(all_rows: Sequence[FormRow], rows: Sequence[FormRow]) -> Iterable[Finding]:
    real_at: dict[str, FormRow] = {}
    for row in all_rows:
        real_at.setdefault(canon(row.real), row)
    for row in rows:
        other = real_at.get(canon(row.fake))
        if other is not None:
            yield _error("E012", row.path, f"the fake equals the real value at {other.path}")


def _containment(all_rows: Sequence[FormRow], rows: Sequence[FormRow]) -> Iterable[Finding]:
    reals = list(all_rows)
    fakes = list(rows)
    fakes_in_reals = containment_pairs([r.fake for r in fakes], [r.real for r in reals])
    reals_in_fakes = containment_pairs([r.real for r in reals], [r.fake for r in fakes])
    for f, row in enumerate(fakes):
        for i in fakes_in_reals.get(f, ()):
            other = reals[i]
            if canon(other.real) != canon(row.fake):  # equality is E012
                yield _error(
                    "E013", row.path, f"the fake occurs inside the real value at {other.path}"
                )
    for r, row in enumerate(reals):
        for i in reals_in_fakes.get(r, ()):
            other = fakes[i]
            if canon(other.fake) != canon(row.real):
                yield _error(
                    "E014", other.path, f"the real value at {row.path} occurs inside this fake"
                )


def _kept_inside_fakes(kept: Sequence[FormRow], fakes: Sequence[FormRow]) -> Iterable[Finding]:
    """W113: a fake that contains a value you keep unchanged makes reverse rewrite that value
    wherever it appears inside the fake ("New Delhi" as a fake while "Delhi" is kept)."""
    pairs = containment_pairs([r.real for r in kept], [r.fake for r in fakes])
    for k, row in enumerate(kept):
        for f in pairs.get(k, ()):
            other = fakes[f]
            if canon(other.fake) != canon(row.real):  # equality is E012
                yield Finding(
                    Severity.WARNING,
                    "W113",
                    other.path,
                    f"the value kept unchanged at {row.path} occurs inside this fake",
                )


def _error(code: str, path: str, message: str) -> Finding:
    return Finding(Severity.ERROR, code, path, message)
