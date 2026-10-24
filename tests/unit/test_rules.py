"""Validator part 2: cross-field errors (E017-E020), warnings (W101-W111), notes (I001-I002)."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil.persona.report import render_json, render_text
from veil.persona.rules import KNOWN_RELATIONS
from veil.persona.schema import parse_persona
from veil.persona.validate import validate
from veil.persona.yamlio import load_yaml

V = 'version: "1"\n'


def report(doc: str):
    return validate(parse_persona(load_yaml(doc)))


def codes_at(doc: str) -> set[tuple[str, str]]:
    return {(f.code, f.path) for f in report(doc).findings}


def has(doc: str, code: str, path: str) -> bool:
    return (code, path) in codes_at(doc)


def lacks(doc: str, code: str) -> bool:
    return all(f.code != code for f in report(doc).findings)


EDU = (
    "education: [{institution: {real: XYZ Institute, fake: ABC University},"
    " domain: {real: xyz.example.test, fake: abc.example.test},"
    " sub_domains: {real: [research.xyz.example.test], fake: [lab.abc.example.test]}}]\n"
)


# ── E017 institutional email domain ───────────────────────────────────────────


@pytest.mark.parametrize(
    ("real", "fake"),
    [
        ("jane@xyz.example.test", "alex@abc.example.test"),
        ("jane@research.xyz.example.test", "alex@lab.abc.example.test"),  # listed sub-domain
        ("jane@cs.xyz.example.test", "alex@cs.abc.example.test"),  # unlisted: prefix carried
        ("JANE@XYZ.EXAMPLE.TEST", "alex@ABC.example.test"),  # case-insensitive
        ("jane@mail.example.test", "alex@anything.example.test"),  # not institutional
    ],
)
def test_e017_valid(real, fake):
    assert lacks(V + EDU + f"emails: [{{real: '{real}', fake: '{fake}'}}]\n", "E017")


@pytest.mark.parametrize(
    ("real", "fake"),
    [
        ("jane@xyz.example.test", "alex@gmail.example.test"),
        ("jane@research.xyz.example.test", "alex@research.abc.example.test"),  # listed fake differs
        ("jane@cs.xyz.example.test", "alex@abc.example.test"),  # prefix dropped
        ("jane@xyz.example.test", "alex-without-domain"),
    ],
)
def test_e017_wrong_fake_domain(real, fake):
    assert has(V + EDU + f"emails: [{{real: '{real}', fake: '{fake}'}}]\n", "E017", "emails[0]")


def test_e017_skipped_for_kept_email_and_without_education():
    assert lacks(V + EDU + "emails: [{real: jane@xyz.example.test, policy: KEEP}]\n", "E017")
    assert lacks(V + "emails: [{real: jane@xyz.example.test, fake: alex@other.test}]\n", "E017")


def test_e017_message_names_the_domain_source_not_values():
    [finding] = [
        f
        for f in report(V + EDU + "emails: [{real: j@xyz.example.test, fake: a@x.test}]\n").findings
        if f.code == "E017"
    ]
    assert "education[0].domain" in finding.message
    assert "xyz" not in finding.message
    assert "abc" not in finding.message


# ── E018 year of study / batch ────────────────────────────────────────────────


def year_doc(real_year: str, fake_year: str, real_batch: str = "", fake_batch: str = "") -> str:
    return V + (
        f"education: [{{year_of_study: {{enabled: true, real: '{real_year}', fake: '{fake_year}'}},"
        f" batch_year: {{real: '{real_batch}', fake: '{fake_batch}'}}}}]\n"
    )


def test_e018_consistent_shift_is_fine():
    assert lacks(year_doc("2", "3", "2024", "2023"), "E018")
    assert lacks(year_doc("3", "1", "2022", "2024"), "E018")


def test_e018_inconsistent_shift():
    findings = [f for f in report(year_doc("2", "3", "2024", "2024")).findings if f.code == "E018"]
    assert [f.path for f in findings] == ["education[0].batch_year"]
    assert "shift by -1" in findings[0].message


@pytest.mark.parametrize(("rb", "fb"), [("24", "23"), ("2024", "MMXXIII"), ("20245", "20235")])
def test_e018_batch_must_be_four_digits(rb, fb):
    assert has(year_doc("2", "3", rb, fb), "E018", "education[0].batch_year")


def test_e018_year_enabled_without_both_values():
    assert has(year_doc("2", ""), "E018", "education[0].year_of_study")


def test_e018_skipped_when_disabled_or_batch_missing():
    disabled = (
        V
        + "education: [{year_of_study: {enabled: false, real: '2'}, batch_year: {real: '2024', fake: '1999'}}]\n"
    )
    assert lacks(disabled, "E018")
    assert lacks(year_doc("2", "3"), "E018")


# ── E019 degree phrases ───────────────────────────────────────────────────────


def deg(real: str, fake: str, enabled: str = "true") -> str:
    return (
        V
        + f"education: [{{degree: {{enabled: {enabled}, phrases: {{real: {real}, fake: {fake}}}}}}}]\n"
    )


def test_e019_valid_phrases():
    assert lacks(deg("[MS student, my MS]", "[PhD student, my PhD]"), "E019")


def test_e019_enabled_without_phrases():
    assert has(
        V + "education: [{degree: {enabled: true, real: MS, fake: PhD}}]\n",
        "E019",
        "education[0].degree.phrases",
    )


@pytest.mark.parametrize(
    ("real", "fake", "path"),
    [
        ("[MS]", "[PhD student]", "education[0].degree.phrases[0]"),
        ("[MS student]", "[PhD]", "education[0].degree.phrases[0]"),
        ("[MS student, M.Tech]", "[PhD student, PhD x]", "education[0].degree.phrases[1]"),
    ],
)
def test_e019_bare_degree_is_rejected(real, fake, path):
    assert has(deg(real, fake), "E019", path)


def test_e019_skipped_when_disabled():
    assert lacks(deg("[MS]", "[PhD]", enabled="false"), "E019")


def test_duplicate_fake_phrases_are_e010():
    assert has(
        deg("[MS student, MSR student]", "[PhD student, PhD student]"),
        "E010",
        "education[0].degree.phrases[1]",
    )


# ── E020 policy placement ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("doc", "path"),
    [
        (V + "person: {first_name: {real: Jane, fake: Alex, policy: ASK}}\n", "person.first_name"),
        (
            V + "person: {first_name: {real: Jane, fake: Alex, policy: SHIFT}}\n",
            "person.first_name",
        ),
        (V + "people: [{real: Ravi, fake: Om, policy: SWAP_NAME_ONLY}]\n", "people[0]"),
        (
            V + "attributes: {pets: [{name: {real: M, fake: B}, policy: FPE}]}\n",
            "attributes.pets[0]",
        ),
        (V + "infra: {ip_addresses: {policy: SWAP}}\n", "infra.ip_addresses"),
        (V + "infra: {mac_addresses: {policy: ASK}}\n", "infra.mac_addresses"),
        (V + "sensitive: {default_policy: SWAP}\n", "sensitive.default_policy"),
        (V + "sensitive: {health: {real: [x-condition], policy: FPE}}\n", "sensitive.health"),
        (
            V + "sensitive: {health: {real: [x-condition], policy: GENERALIZE}}\n",
            "sensitive.health.generalized",
        ),
    ],
)
def test_e020_policy_not_allowed(doc, path):
    assert has(doc, "E020", path)


@pytest.mark.parametrize(
    "doc",
    [
        V + "person: {date_of_birth: {real: '1/1/2000', policy: SHIFT}}\n",
        V + "attributes: {pets: [{name: {real: Mochi, fake: Bruno}, policy: SWAP}]}\n",
        V + "infra: {ip_addresses: {policy: KEEP}, mac_addresses: {policy: FPE}}\n",
        V
        + "sensitive: {health: {real: [x-condition], policy: GENERALIZE, generalized: a condition}}\n",
        V
        + "sensitive: {health: {real: [], policy: GENERALIZE}}\n",  # nothing listed: nothing to say
        V + "person: {first_name: {real: Jane, fake: Alex, policy: REDACT}}\n",
    ],
)
def test_e020_allowed_placements(doc):
    assert lacks(doc, "E020")


# ── Warnings ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("doc", "warned"),
    [
        (V + "people: [{real: Ram, fake: Kishore}]\n", True),  # short real
        (V + "people: [{real: Ravindra, fake: Om}]\n", True),  # short fake
        (V + "people: [{real: Ram, fake: Kishore, allow_short: true}]\n", False),
        (V + "people: [{real: Ram, fake: Kishore, contexts: [friend]}]\n", False),
        (V + "people: [{real: Ravindra, fake: Kishore}]\n", False),
        (V + "phones: [{real: '123'}]\n", True),  # short real with a generated fake
    ],
)
def test_w101_short_forms(doc, warned):
    assert (not lacks(doc, "W101")) is warned


def test_w102_family_surname():
    base = V + "person: {last_name: {real: Doe, fake: Smith}}\n"
    assert has(
        base + "people: [{real: John Doe, fake: Sam Jones, relation: father}]\n",
        "W102",
        "people[0]",
    )
    assert lacks(base + "people: [{real: John Doe, fake: Sam Smith, relation: father}]\n", "W102")
    # different real surname (e.g. married name): no expectation
    assert lacks(base + "people: [{real: Joan Roe, fake: Kim Lane, relation: mother}]\n", "W102")
    # maiden name and friends are exempt
    assert lacks(base + "people: [{real: Doe, fake: Lane, relation: mother_maiden_name}]\n", "W102")
    assert lacks(base + "people: [{real: Ravi Doe, fake: Om Prakash, relation: friend}]\n", "W102")


def test_w102_works_in_indic_scripts():
    doc = (
        V
        + "person: {last_name: {real: দাস, fake: সেন}}\npeople: [{real: রাম দাস, fake: শ্যাম বসু, relation: sibling}]\n"
    )
    assert has(doc, "W102", "people[0]")


def test_w103_fake_under_keep_is_ignored():
    assert has(
        V + "person: {current_city: {real: Pune, fake: Agra, policy: KEEP}}\n",
        "W103",
        "person.current_city",
    )
    assert lacks(V + "person: {current_city: {real: Pune, policy: KEEP}}\n", "W103")
    pets = (
        V
        + "attributes: {pets: [{species: {real: cat, fake: dog}, name: {real: M1, fake: B1}, policy: SWAP_NAME_ONLY}]}\n"
    )
    assert has(pets, "W103", "attributes.pets[0].species")


def test_w104_fake_without_real():
    assert has(V + "people: [{fake: Om Prakash}]\n", "W104", "people[0]")
    assert has(
        V + "education: [{aliases: {real: [''], fake: [ABCU]}}]\n",
        "W104",
        "education[0].aliases[0]",
    )


@pytest.mark.parametrize(
    "value",
    [" Jane", "Jane ", "Ｊane", "ﬁona", "null", "None", "~ "],
)
def test_w105_odd_text(value):
    assert has(V + f"people: [{{real: '{value}', fake: Kishore Kumar}}]\n", "W105", "people[0]")


def test_w105_clean_text():
    assert lacks(V + "people: [{real: Ravindra, fake: Kishore Kumar}]\n", "W105")


def test_w106_never_translate_hides_a_real_value():
    doc = (
        V
        + "people: [{real: Ruby Shah, fake: Mira Das}, {real: Ruby, fake: Mira}]\nnever_translate: [Ruby]\n"
    )
    assert has(doc, "W106", "never_translate[0]")
    guarded = (
        V
        + "infra: {clusters: [{real: ruby, fake: kepler, contexts: [ssh]}]}\nnever_translate: [Ruby]\n"
    )
    assert lacks(guarded, "W106")


def test_w107_never_reverse_without_fake_forms():
    doc = (
        V
        + "people: [{real: Ravindra, fake: Kishore}]\nnever_reverse: [Kishore Kumar Stadium, Unrelated Thing]\n"
    )
    found = codes_at(doc)
    assert ("W107", "never_reverse[1]") in found
    assert ("W107", "never_reverse[0]") not in found


def test_w108_zero_shift():
    assert has(
        V + "person: {date_of_birth: {real: '1/1/2000', policy: SHIFT}}\n",
        "W108",
        "person.date_of_birth",
    )
    shifted = (
        V
        + "person: {date_of_birth: {real: '1/1/2000', policy: SHIFT}}\nnumbers: {date_shift_days: '-37'}\n"
    )
    assert lacks(shifted, "W108")
    explicit = V + "person: {date_of_birth: {real: '1/1/2000', fake: '2/2/2000', policy: SHIFT}}\n"
    assert lacks(explicit, "W108")


def test_w109_sensitive_overlap():
    doc = (
        V
        + "people: [{real: Mira Das, fake: Asha Sen}]\nsensitive: {health: {real: [asha], generalized: x}}\n"
    )
    assert has(doc, "W109", "sensitive.health[0]")
    assert lacks(
        V + "people: [{real: Mira Das, fake: Ritu Sen}]\nsensitive: {health: {real: [asthma]}}\n",
        "W109",
    )


def test_w110_full_name_composition():
    base = "person: {first_name: {real: Jane, fake: Alex}, last_name: {real: Doe, fake: Smith, allow_short: true}, "
    assert has(
        V + base + "full_name: {real: Jane Doe, fake: Alex Jones}}\n", "W110", "person.full_name"
    )
    assert lacks(V + base + "full_name: {real: Jane Doe, fake: Alex Smith}}\n", "W110")
    assert lacks(V + base + "full_name: {real: Jane Q Doe, fake: Alex Jones}}\n", "W110")


def test_w111_unknown_relation():
    assert has(
        V + "people: [{real: Ravindra, fake: Kishore, relation: cousin-ish}]\n",
        "W111",
        "people[0].relation",
    )
    for relation in sorted(KNOWN_RELATIONS):
        assert lacks(
            V + f"people: [{{real: Ravindra, fake: Kishore, relation: {relation}}}]\n", "W111"
        )


def test_w111_message_does_not_echo_the_relation():
    [finding] = [
        f
        for f in report(
            V + "people: [{real: Ravindra, fake: Kishore, relation: Zorblax}]\n"
        ).findings
        if f.code == "W111"
    ]
    assert "Zorblax" not in finding.message


# ── Notes ─────────────────────────────────────────────────────────────────────


def test_i001_and_i002():
    doc = V + "phones: [{real: '+91 90000 00001'}]\nperson: {gender: {real: f, fake: f}}\n"
    found = codes_at(doc)
    assert ("I001", "phones[0]") in found
    assert ("I002", "person.gender") in found


def test_notes_and_warnings_do_not_fail_but_strict_does():
    r = report(V + "people: [{real: Ram, fake: Kishore}]\n")
    assert r.errors == ()
    assert r.failed() is False
    assert r.failed(strict=True) is True


# ── No value ever reaches the rendered report ─────────────────────────────────

TOKENS = st.text(alphabet="QXZJVK", min_size=4, max_size=7)


@given(TOKENS, TOKENS, TOKENS, TOKENS)
def test_rule_messages_never_contain_values(a, b, c, d):
    doc = V + (
        f"person: {{last_name: {{real: {a}, fake: {b}}}, full_name: {{real: ' {c}', fake: {d}}}}}\n"
        f"people: [{{real: '{c} {a}', fake: '{d}', relation: father}}, {{fake: {d}}}]\n"
        f"emails: [{{real: '{a}@{c}.example.test', fake: '{b}@nowhere.test'}}]\n"
        f"education: [{{domain: {{real: {c}.example.test, fake: {d}.example.test}}}}]\n"
        f"never_reverse: ['{c}{a}']\n"
        f"sensitive: {{health: {{real: ['{a}']}}}}\n"
    )
    result = report(doc)
    # The document is built to trigger many findings; an empty report would make this vacuous.
    assert {"E017", "W104", "W105"} <= {f.code for f in result.findings}
    rendered = render_text(result) + render_json(result)
    for token in (a, b, c, d):
        assert token not in rendered
