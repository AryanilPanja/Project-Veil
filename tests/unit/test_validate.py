"""Bijection validation (E010 to E016) and report rendering."""

import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil.persona.report import Finding, Severity, make_report, render_json, render_text
from veil.persona.schema import parse_persona
from veil.persona.validate import FormRow, validate, validate_forms
from veil.persona.yamlio import load_yaml

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "synthetic_jane.yaml"
V = 'version: "1"\n'


def check(doc: str):
    return validate(parse_persona(load_yaml(doc)))


def people(*pairs: tuple[str, str], extra: str = "") -> str:
    items = ", ".join(f"{{real: '{r}', fake: '{f}'}}" for r, f in pairs)
    return V + f"people: [{items}]\n" + extra


def findings_of(doc: str) -> list[tuple[str, str]]:
    """Errors only: these tests are about the bijection (E010-E016). Warnings and notes are
    covered in test_rules.py."""
    return [(f.code, f.path) for f in check(doc).errors]


def all_findings_of(doc: str) -> list[tuple[str, str]]:
    """Every finding, warnings included (for the W112/W113 checks emitted here)."""
    return [(f.code, f.path) for f in check(doc).findings]


# ── Valid documents ───────────────────────────────────────────────────────────


def test_synthetic_fixture_is_valid():
    report = validate(parse_persona(load_yaml(FIXTURE.read_bytes())))
    assert report.errors == ()
    assert report.warnings == ()  # notes (I001/I002) are expected


def test_template_is_valid():
    report = validate(parse_persona(load_yaml((ROOT / "persona.example.yaml").read_bytes())))
    assert report.findings == ()


def test_overlapping_reals_and_overlapping_fakes_are_fine():
    # first name inside full name on both sides: that's normal, not a conflict
    doc = V + (
        "person: {first_name: {real: Jane, fake: Alex},"
        " full_name: {real: Jane Doe, fake: Alex Smith}}\n"
    )
    assert check(doc).findings == ()


# ── One example per code ──────────────────────────────────────────────────────


def test_e010_two_reals_share_a_fake():
    assert findings_of(people(("Ravi", "Om"), ("Kiran", "Om"))) == [("E010", "people[1]")]


def test_e010_is_case_and_width_insensitive():
    assert ("E010", "people[1]") in findings_of(people(("Ravi", "Om"), ("Kiran", "ＯＭ")))


def test_e011_one_real_two_fakes():
    assert findings_of(people(("Ravi", "Om"), ("RAVI", "Sam"))) == [("E011", "people[1]")]


def test_identical_duplicates_are_not_conflicts():
    assert findings_of(people(("Ravi", "Om"), ("Ravi", "Om"))) == []


def test_e012_fake_equals_another_real():
    found = findings_of(people(("Ravi", "Kiran"), ("Kiran", "Sam")))
    assert ("E012", "people[0]") in found


def test_e013_fake_inside_a_real():
    found = findings_of(people(("Jane Doe", "Alex Smith"), ("Ravi", "Doe")))
    assert ("E013", "people[1]") in found


def test_e014_real_inside_a_fake():
    found = findings_of(people(("Ravi", "Om"), ("Kiran", "Ravi Shah")))
    assert ("E014", "people[1]") in found


def test_e014_real_inside_its_own_fake():
    assert ("E014", "people[0]") in findings_of(people(("Kim", "Kim Shah")))


def test_unbounded_overlap_is_not_containment():
    # "ann" sits inside "joanne" but not on a word boundary
    assert findings_of(people(("Joanne", "Mira"), ("Tom", "Ann"))) == []


def test_digits_inside_longer_numbers_are_not_containment():
    doc = V + "ids: {pin_codes: [{real: '2021', fake: '9999'}, {real: '777777', fake: '12021'}]}\n"
    assert findings_of(doc) == []


def test_containment_in_indic_scripts():
    found = findings_of(people(("রাম কুমার", "Om"), ("Ravi", "রাম")))
    assert ("E013", "people[1]") in found


def test_real_domain_inside_real_email_is_fine():
    doc = V + (
        "emails: [{real: jane@xyz.example.test, fake: alex@abc.example.test}]\n"
        "education: [{domain: {real: xyz.example.test, fake: abc.example.test}}]\n"
    )
    assert findings_of(doc) == []


def test_containment_across_kinds():
    # The real username leaks through a fake home directory that still contains it
    doc = V + (
        "handles: {linux_user: {real: janed, fake: alexs}}\n"
        "infra: {home_dir: {real: /home/janed, fake: /home/janed/x}}\n"
    )
    assert ("E014", "infra.home_dir") in findings_of(doc)


def test_e015_list_lengths_differ_at_the_list_path():
    doc = V + (
        "education: [{institution: {real: A Inst, fake: B Inst},"
        " aliases: {real: [AI, AX], fake: [BI]}}]\n"
    )
    found = findings_of(doc)
    assert ("E015", "education[0].aliases") in found
    [finding] = [f for f in check(doc).findings if f.code == "E015"]
    assert "(2 vs 1)" in finding.message


@pytest.mark.parametrize(
    ("doc", "path"),
    [
        (V + "person: {first_name: {real: Jane, fake: ''}}\n", "person.first_name"),
        (V + "people: [{real: Ravi}]\n", "people[0]"),
        (
            V
            + "education: [{institution: {real: A, fake: B}, aliases: {real: [AI], fake: ['']}}]\n",
            "education[0].aliases[0]",
        ),
        (
            V
            + "education: [{advisor: {real: Prof X, fake: Prof Y,"
            + " forms: {real: [PX], fake: ['']}}}]\n",
            "education[0].advisor.forms[0]",
        ),
        (
            V
            + "education: [{degree: {enabled: true, phrases: {real: [MS student], fake: ['']}}}]\n",
            "education[0].degree.phrases[0]",
        ),
    ],
)
def test_e016_missing_fake_at_the_exact_form_path(doc, path):
    assert ("E016", path) in findings_of(doc)


@pytest.mark.parametrize(
    "doc",
    [
        V + "phones: [{real: '+91 90000 00001'}]\n",  # FPE by default: generated later
        V + "person: {date_of_birth: {real: '14/03/2001', policy: SHIFT}}\n",
        V + "person: {current_city: {real: Pune, policy: KEEP}}\n",
        V + "person: {first_name: {real: Jane, policy: KEEP}}\n",
        V + "education: [{research_area: {real: OCR, enabled: false}}]\n",
    ],
)
def test_no_e016_for_generated_kept_or_disabled(doc):
    assert check(doc).errors == ()


def test_generated_real_still_must_not_appear_in_a_fake():
    doc = V + "phones: [{real: '90000 00001'}]\npeople: [{real: Ravi, fake: 'Om 90000 00001'}]\n"
    assert ("E014", "people[0]") in findings_of(doc)


def test_generalize_fakes_may_coincide_but_must_not_contain_reals():
    doc = V + (
        "footprint: {paper_titles: [{real: Title One, fake: a paper},"
        " {real: Title Two, fake: a paper}]}\n"
    )
    assert findings_of(doc) == []  # one-way: no E010
    leaking = (
        V
        + "people: [{real: Ravi, fake: Om}]\n"
        + "footprint: {thesis_title: {real: T, fake: Ravi thesis}}\n"
    )
    assert ("E014", "footprint.thesis_title") in findings_of(leaking)


def test_year_of_study_is_excluded():
    doc = V + (
        "education: [{year_of_study: {enabled: true, real: '2', fake: '3'}}]\n"
        "ids: {address: [{real: 'Block 2 Hall', fake: 'Block 9 Hall'}]}\n"
    )
    assert findings_of(doc) == []


def test_identical_pairs_take_part_in_the_bijection():
    # gender f→f is kept (I002); a fake "f" elsewhere would make reverse rewrite every kept "f"
    # into "Ravi" (sweep 2026-10-26: this test used to expect no finding).
    doc = V + "person: {gender: {real: f, fake: f}}\npeople: [{real: Ravi, fake: f}]\n"
    assert ("E012", "people[0]") in findings_of(doc)


def test_kept_values_take_part_in_the_bijection():
    doc = V + "person: {languages: {real: Om, policy: KEEP}}\npeople: [{real: Ravi, fake: Om}]\n"
    assert ("E012", "people[0]") in findings_of(doc)


def test_kept_value_inside_a_fake_warns():
    doc = (
        V
        + "person: {current_city: {real: Delhi, policy: KEEP}}\n"
        + "people: [{real: Ravi Kumar, fake: Delhi Sharma}]\n"
    )
    assert ("W113", "people[0]") in all_findings_of(doc)


def test_unrelated_kept_values_are_fine():
    doc = V + "person: {languages: {real: Hindi, policy: KEEP}}\npeople: [{real: Ravi, fake: Om}]\n"
    assert findings_of(doc) == []


@pytest.mark.parametrize(
    "invisible", ["\u200b", "\u2060", "\u00ad", "\ufe0f", "\u200b\u200b", "\ufeff"]
)
def test_invisible_only_fake_is_missing(invisible):
    # str.strip() keeps these; the canonical form drops them: the real value would be sent as is.
    doc = V + f'people: [{{real: Ravi Kumar, fake: "{invisible}"}}]\n'
    assert ("E016", "people[0]") in findings_of(doc)


def test_invisible_only_real_warns():
    doc = V + 'people: [{real: "\u200b", fake: Om}]\n'
    assert ("W112", "people[0]") in all_findings_of(doc)


def test_invisible_only_fake_never_reaches_the_lexicon():
    from tests.unit.test_matcher import lexicon_from

    lexicon = lexicon_from(V + 'people: [{real: Ravi Kumar, fake: "\u200b"}]\n')
    assert lexicon.forward == ()


def test_multiple_problems_are_all_reported():
    doc = people(("Ravi", "Om"), ("Kiran", "Om"), ("Ravi", "Sam"), ("Tom", ""))
    codes = sorted(code for code, _ in findings_of(doc))
    assert codes == ["E010", "E011", "E016"]


# ── validate_forms (also used by M1 on expanded variants) ─────────────────────


def test_validate_forms_directly():
    rows = [
        FormRow("a", "Jane", "Alex", True),
        FormRow("b", "Ravi", "Alex", True),
        FormRow("c", "Om", "", True),  # real-only row (generated fake)
        FormRow("d", "Kim", "Om Shah", True),
    ]
    codes = sorted(f.code for f in validate_forms(rows))
    assert codes == ["E010", "E014"]


def test_form_row_repr_is_redacted():
    assert "Jane" not in repr(FormRow("a", "Jane", "Alex", True))


# ── Report ────────────────────────────────────────────────────────────────────


def test_report_orders_errors_first_and_deduplicates():
    findings = [
        Finding(Severity.WARNING, "W101", "a", "w"),
        Finding(Severity.ERROR, "E010", "b", "e"),
        Finding(Severity.ERROR, "E010", "b", "e"),
        Finding(Severity.INFO, "I001", "c", "i"),
    ]
    report = make_report(findings)
    assert [f.code for f in report.findings] == ["E010", "W101", "I001"]
    assert report.failed() is True
    assert make_report(findings[:1]).failed() is False
    assert make_report(findings[:1]).failed(strict=True) is True


def test_render_text_and_json():
    report = make_report([Finding(Severity.ERROR, "E011", "people[1]", "msg")])
    text = render_text(report)
    assert "ERROR   E011 people[1]: msg" in text
    assert text.endswith("1 error(s), 0 warning(s), 0 note(s)")
    data = json.loads(render_json(report))
    assert data["errors"] == 1
    assert data["findings"][0] == {
        "severity": "ERROR",
        "code": "E011",
        "path": "people[1]",
        "message": "msg",
    }


# ── No value ever reaches the report ──────────────────────────────────────────

TOKENS = st.text(alphabet="QXZJVK", min_size=4, max_size=7)


@given(st.lists(st.tuples(TOKENS, TOKENS), min_size=2, max_size=6))
def test_reports_never_contain_values(pairs):
    report = check(people(*pairs))
    rendered = render_text(report) + render_json(report)
    for real, fake in pairs:
        assert real not in rendered
        assert fake not in rendered
