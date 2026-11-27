from pathlib import Path

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st
from pydantic import ValidationError

from veil.errors import ValidationFailed
from veil.exitcodes import ExitCode
from veil.persona.policy import Policy
from veil.persona.schema import (
    ListPair,
    Pair,
    Persona,
    PersonaSchemaError,
    SchemaIssue,
    parse_persona,
)
from veil.persona.yamlio import load_yaml

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "synthetic_jane.yaml"
TEMPLATE = ROOT / "persona.example.yaml"


def parse(doc: str) -> Persona:
    return parse_persona(load_yaml(doc))


def issues(doc: str) -> tuple[SchemaIssue, ...]:
    with pytest.raises(PersonaSchemaError) as info:
        parse(doc)
    return info.value.issues


def only_issue(doc: str) -> SchemaIssue:
    [issue] = issues(doc)
    return issue


V = 'version: "1"\n'


def _vocabulary() -> str:
    """Every word the schema itself can print: field names, policies, fixed problem texts."""
    import veil.persona.schema as schema_module

    words: set[str] = {p.value for p in Policy}
    for obj in vars(schema_module).values():
        if isinstance(obj, type) and issubclass(obj, schema_module.RedactedModel):
            words.update(obj.model_fields)
    words.update(schema_module._PROBLEMS.values())
    words.update(
        [
            "unknown field (did you mean",
            "unknown policy",
            "a number is required",
            "must be a whole number",
            "must be between",
            "invalid value",
            "top level",
            # allowed literal values
            "semantic",
            "loose",
            "max",
        ]
    )
    return " ".join(words).lower()


SCHEMA_VOCABULARY = _vocabulary()


# ── Real documents ────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def synthetic() -> Persona:
    return parse_persona(load_yaml(FIXTURE.read_bytes()))


def test_synthetic_fixture_parses(synthetic):
    assert synthetic.person.first_name.real == "Jane"
    assert synthetic.person.first_name.fake == "Alex"
    assert synthetic.person.nicknames[0].allow_short is True
    assert synthetic.person.date_of_birth.policy is Policy.SHIFT
    assert synthetic.person.current_city.policy is Policy.KEEP
    assert len(synthetic.person.name_in_other_scripts) == 3
    assert synthetic.emails[1].fake == "alexsmith2001@mail.example.test"


def test_synthetic_fixture_nested_and_typed_fields(synthetic):
    edu = synthetic.education[0]
    assert edu.degree.enabled is True
    assert edu.degree.phrases.real == ("MS student", "my MS", "MS thesis")
    assert edu.year_of_study.real == 2
    assert edu.year_of_study.fake == 3
    assert edu.advisor.forms.fake == ("A. Minor", "aminor")
    assert edu.lab.aliases.real == ("VL",)
    assert edu.research_area.enabled is False
    assert synthetic.education[1].aliases.real == ()
    assert synthetic.sensitive.ask_timeout_seconds == 120
    assert synthetic.sensitive.health.real == ("asthma",)
    assert synthetic.numbers.date_shift_days == -37
    assert synthetic.infra.ip_addresses.policy is Policy.FPE
    assert synthetic.attributes.pets[0].policy is Policy.SWAP_NAME_ONLY
    assert synthetic.never_reverse == ("Alex Smith Stadium",)


def test_template_parses_with_defaults():
    persona = parse_persona(load_yaml(TEMPLATE.read_bytes()))
    assert persona.version == "1"
    assert len(persona.education) == 3
    assert persona.education[0].degree.enabled is False
    assert persona.education[0].year_of_study.real is None
    assert persona.sensitive.default_policy is Policy.ASK
    assert persona.numbers.date_shift_days == 0
    assert persona.never_translate == ("Ruby", "Julia")


def test_minimal_persona_is_all_defaults():
    persona = parse(V)
    assert persona.person.first_name.real == ""
    assert persona.emails == ()
    assert persona.fidelity == "semantic"
    assert persona.sensitive.ask_timeout_seconds == 120


# ── Version ───────────────────────────────────────────────────────────────────


def test_missing_version():
    issue = only_issue("person: {}\n")
    assert (issue.code, issue.path) == ("E004", "version")
    assert "missing" in issue.problem


@pytest.mark.parametrize("raw", ["1.0", "01", "2", "true", '"v1"', "~"])
def test_unsupported_versions(raw):
    issue = only_issue(f"version: {raw}\n")
    assert (issue.code, issue.path) == ("E004", "version")


@pytest.mark.parametrize("raw", ["1", '"1"', "'1'"])
def test_version_one_in_any_spelling(raw):
    assert parse(f"version: {raw}\n").version == "1"


def test_version_given_as_int_by_code_is_rejected():
    with pytest.raises(PersonaSchemaError):
        parse_persona({"version": 1})


# ── Strict types: yamlio's "everything stays text" must survive ───────────────


@pytest.mark.parametrize(
    ("doc", "path", "problem"),
    [
        (
            V + "education: [{degree: {enabled: yes}}]\n",
            "education[0].degree.enabled",
            "true or false",
        ),
        (
            V + "education: [{degree: {enabled: '1'}}]\n",
            "education[0].degree.enabled",
            "true or false",
        ),
        (V + "person: {first_name: {real: [x]}}\n", "person.first_name.real", "must be text"),
        (V + "person: {first_name: {real: true}}\n", "person.first_name.real", "must be text"),
        (V + "person: {first_name: {real: {a: b}}}\n", "person.first_name.real", "must be text"),
        (V + "person: x\n", "person", "mapping"),
        (V + "person: {first_name: x}\n", "person.first_name", "mapping"),
        (V + "emails: {a: b}\n", "emails", "list"),
        (V + "fidelity: medium\n", "fidelity", "not allowed"),
        (V + "fidelity: true\n", "fidelity", "not allowed"),
    ],
)
def test_wrong_types_are_reported_by_path(doc, path, problem):
    issue = only_issue(doc)
    assert issue.code == "E003"
    assert issue.path == path
    assert problem in issue.problem


@pytest.mark.parametrize(
    ("doc", "problem"),
    [
        (V + "sensitive: {ask_timeout_seconds: '9999'}\n", "between 1 and 600"),
        (V + "sensitive: {ask_timeout_seconds: '0'}\n", "between 1 and 600"),
        (V + "sensitive: {ask_timeout_seconds: abc}\n", "whole number"),
        (V + "sensitive: {ask_timeout_seconds: '2.5'}\n", "whole number"),
        (V + "sensitive: {ask_timeout_seconds: ''}\n", "number is required"),
        (V + "sensitive: {ask_timeout_seconds: true}\n", "whole number"),
        (V + "numbers: {date_shift_days: '-36501'}\n", "between -36500 and 36500"),
        (V + "education: [{year_of_study: {real: '11'}}]\n", "between 1 and 10"),
        (V + "education: [{year_of_study: {real: two}}]\n", "whole number"),
    ],
)
def test_number_fields_are_parsed_and_range_checked(doc, problem):
    issue = only_issue(doc)
    assert issue.code == "E003"
    assert problem in issue.problem


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("'120'", 120), ("'+5'", 5), ("' 30 '", 30), ("'600'", 600), ("'1'", 1)],
)
def test_valid_timeouts(raw, expected):
    assert (
        parse(V + f"sensitive: {{ask_timeout_seconds: {raw}}}\n").sensitive.ask_timeout_seconds
        == expected
    )


def test_negative_date_shift_and_empty_year():
    persona = parse(
        V + "numbers: {date_shift_days: '-177'}\neducation: [{year_of_study: {real: ''}}]\n"
    )
    assert persona.numbers.date_shift_days == -177
    assert persona.education[0].year_of_study.real is None


@pytest.mark.parametrize("raw", ["SWAPP", "swap", "Keep", "SWAP_", "'ASK '"])
def test_unknown_policy(raw):
    issue = only_issue(V + f"person: {{first_name: {{policy: {raw}}}}}\n")
    assert issue.path == "person.first_name.policy"
    assert issue.problem == "unknown policy"


@pytest.mark.parametrize("raw", list(Policy))
def test_every_policy_name_parses(raw):
    persona = parse(V + f"person: {{first_name: {{policy: {raw.value}}}}}\n")
    assert persona.person.first_name.policy is raw


# ── Lenient shapes that are still unambiguous ─────────────────────────────────


def test_null_text_becomes_empty_and_null_flag_false():
    persona = parse(V + "person: {first_name: {real: ~, fake: , allow_short: ~}}\n")
    pair = persona.person.first_name
    assert (pair.real, pair.fake, pair.allow_short) == ("", "", False)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("[]", ()), ("''", ()), ("~", ()), ("[a, b]", ("a", "b")), ("single", ("single",))],
)
def test_list_fields_accept_list_empty_or_single_text(raw, expected):
    persona = parse(V + f"education: [{{aliases: {{real: {raw}}}}}]\n")
    assert persona.education[0].aliases.real == expected


def test_list_length_mismatch_is_left_to_the_validator():
    persona = parse(V + "education: [{aliases: {real: [a, b], fake: [x]}}]\n")
    assert len(persona.education[0].aliases.real) == 2


# ── Unknown fields: suggestion from the schema, never the written key ─────────


@pytest.mark.parametrize(
    ("doc", "path", "suggestion"),
    [
        (V + "person: {fist_name: {real: x}}\n", "person", "first_name"),
        (V + "persn: {}\n", "<top level>", "person"),
        (V + "education: [{instituton: {}}]\n", "education[0]", "institution"),
        (V + "person: {first_name: {raal: x}}\n", "person.first_name", "real"),
        (V + "sensitive: {helth: {}}\n", "sensitive", "health"),
    ],
)
def test_unknown_field_suggests_schema_name(doc, path, suggestion):
    issue = only_issue(doc)
    assert issue.path == path
    assert issue.problem == f"unknown field (did you mean '{suggestion}'?)"


def test_unknown_field_never_echoes_the_key():
    found = issues(V + "person: {'Jane Doe 9876543210': x}\n")
    assert all("Jane" not in str(i) and "9876543210" not in str(i) for i in found)
    assert found[0].problem == "unknown field"


def test_old_degree_shape_is_reported_at_its_path():
    """Porting hint: the old `degree: {real: ..., policy: KEEP}` line must become the new block."""
    issue = only_issue(V + "education: [{degree: {real: '', policy: KEEP}}]\n")
    assert issue.path == "education[0].degree"
    assert issue.problem.startswith("unknown field")


# ── Error object ──────────────────────────────────────────────────────────────


def test_several_issues_are_collected():
    doc = V + "person: {first_name: {real: [x]}, last_name: {real: [y]}}\nfidelity: z\n"
    found = issues(doc)
    assert len(found) == 3
    with pytest.raises(PersonaSchemaError) as info:
        parse(doc)
    assert str(info.value).endswith("(+2 more)")


def test_schema_error_is_a_validation_failure_without_chained_input():
    with pytest.raises(PersonaSchemaError) as info:
        parse(V + "person: {first_name: {real: [Jane Doe]}}\n")
    error = info.value
    assert isinstance(error, ValidationFailed)
    assert error.exit_code is ExitCode.FINDINGS
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "Jane" not in str(error)


@pytest.mark.parametrize(
    "template",
    [
        "person: {{first_name: {{real: [{t}]}}}}\n",
        "person: {{first_name: {{policy: {t}}}}}\n",
        "person: {{'{t}': x}}\n",
        "{t}: x\n",
        "fidelity: {t}\n",
        "sensitive: {{ask_timeout_seconds: {t}}}\n",
        "education: [{{degree: {{enabled: {t}}}}}]\n",
        "emails: {{{t}: x}}\n",
    ],
)
@given(
    token=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=8, max_size=16
    )
)
def test_no_value_ever_reaches_an_error(template, token):
    # Tokens that ARE schema vocabulary (a valid policy, or a piece of a field name such as
    # "sensitiv") legitimately appear in paths and messages, so they are not secrets.
    assume(token.lower() not in SCHEMA_VOCABULARY)
    with pytest.raises(PersonaSchemaError) as info:
        parse(V + template.format(t=token))
    rendered = [str(info.value), *(str(i) for i in info.value.issues)]
    assert all(token not in r for r in rendered)


# ── Redaction and immutability ────────────────────────────────────────────────


def test_repr_and_str_are_redacted(synthetic):
    for obj in (synthetic, synthetic.person, synthetic.person.first_name, synthetic.education[0]):
        assert "Jane" not in repr(obj)
        assert "Jane" not in str(obj)
    assert "<redacted>" in repr(synthetic.person.first_name)


def test_values_remain_available_to_code(synthetic):
    dumped = synthetic.model_dump()
    assert dumped["person"]["first_name"]["real"] == "Jane"


def test_models_are_frozen(synthetic):
    with pytest.raises(ValidationError) as info:
        synthetic.person.first_name.real = "Changed"  # type: ignore[misc]
    assert "Jane" not in str(info.value)


def test_building_blocks_default_to_empty():
    assert Pair().real == ""
    assert Pair().enabled is True
    assert ListPair().real == ()
