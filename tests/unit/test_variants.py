"""engine/variants.py (M1.1): case spellings, name joins, and bijection over expanded forms."""

from pathlib import Path

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from veil.engine import variants
from veil.engine.variants import Variant, case_like, expand, expand_all, validate_expanded
from veil.persona.entities import Entity, flatten
from veil.persona.policy import Policy
from veil.persona.schema import parse_persona
from veil.persona.walk import EntityKind
from veil.persona.yamlio import load_yaml
from veil.text.containment import contains_bounded
from veil.text.normalize import canon

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic_jane.yaml"


def entity(
    reals, fakes, *, kind=EntityKind.NAME, role="full", id_="person.full_name", reversible=True
) -> Entity:
    return Entity(
        id=id_,
        sources=(id_,),
        kind=kind,
        role=role,
        real_forms=tuple(reals),
        fake_forms=tuple(fakes),
        policy=Policy.SWAP,
        needs_generation=False,
        reversible=reversible,
        contexts=(),
        allow_short=False,
        meta=(),
    )


def by_real(expanded) -> dict[str, Variant]:
    return {canon(v.real): v for v in expanded.variants}


# ── case ──────────────────────────────────────────────────────────────────────


class TestCaseLike:
    @pytest.mark.parametrize(
        ("source", "target", "expected"),
        [
            ("JANE", "Alex", "ALEX"),
            ("jane", "Alex", "alex"),
            ("Jane", "alex", "Alex"),
            ("Jane Doe", "alex smith", "Alex Smith"),
            ("J", "alex", "Alex"),  # one capital letter: treated as Capitalised
            ("jAnE", "Alex", "aLeX"),  # equal length: case copied letter by letter
            ("jAnE", "Alexander", "Alexander"),  # unmappable mixed case: declared spelling
            ("2021", "2019", "2019"),
            ("জেন", "অ্যালেক্স", "অ্যালেক্স"),  # no case in Bengali
            ("JANE-04", "alex-07", "ALEX-07"),
            ("McDonald", "macleod", "Macleod"),
        ],
    )
    def test_patterns(self, source, target, expected):
        assert case_like(source, target) == expected

    @given(st.text(alphabet="abcdefghij", min_size=2), st.text(alphabet="klmnopqrs ", min_size=1))
    def test_upper_and_lower_sources(self, source, target):
        assert case_like(source.upper(), target) == target.upper()
        assert case_like(source, target) == target.lower()

    def test_capitalise_words_keeps_inner_case(self):
        assert variants.capitalise_words("mcDonald smith") == "McDonald Smith"
        assert variants.capitalise_words("") == ""


# ── expansion ─────────────────────────────────────────────────────────────────


class TestExpandNames:
    def test_full_name_joins_and_reversed(self):
        ex = expand(entity(["Jane Doe"], ["Alex Smith"]))
        table = by_real(ex)
        for real, fake in [
            ("jane doe", "alex smith"),
            ("janedoe", "alexsmith"),
            ("jane.doe", "alex.smith"),
            ("jane_doe", "alex_smith"),
            ("jane-doe", "alex-smith"),
            ("doe jane", "smith alex"),
            ("doe, jane", "smith, alex"),
        ]:
            assert canon(table[real].fake) == fake

    @pytest.mark.parametrize(
        ("matched", "expected"),
        [
            ("Jane Doe", "Alex Smith"),
            ("JANE DOE", "ALEX SMITH"),
            ("jane doe", "alex smith"),
            ("JaneDoe", "AlexSmith"),
            ("janeDoe", "alexSmith"),
            ("janedoe", "alexsmith"),
            ("JANEDOE", "ALEXSMITH"),
            ("jane.doe", "alex.smith"),
            ("Jane.Doe", "Alex.Smith"),
            ("Doe, Jane", "Smith, Alex"),
        ],
    )
    def test_output_spelling_follows_the_input(self, matched, expected):
        table = by_real(expand(entity(["Jane Doe"], ["Alex Smith"])))
        assert table[canon(matched)].fake_for(matched) == expected

    def test_unknown_mixed_case_falls_back_safely(self):
        table = by_real(expand(entity(["Jane Doe"], ["Alex Smith"])))
        assert table["jane doe"].fake_for("jAnE dOeX") == "Alex Smith"

    def test_three_word_real_two_word_fake(self):
        table = by_real(expand(entity(["Jane Mary Doe"], ["Alex Smith"])))
        assert canon(table["janemarydoe"].fake) == "alexsmith"
        assert canon(table["doe jane"].fake) == "smith alex"

    def test_single_word_names_get_no_joins(self):
        ex = expand(entity(["Jane"], ["Alex"], role="given"))
        assert [v.origin for v in ex.variants] == ["declared"]

    def test_other_people_get_joins_too(self):
        ex = expand(
            entity(["Ravi Kumar"], ["Om Prakash"], kind=EntityKind.PERSON_NAME, role="friend")
        )
        assert "ravikumar" in by_real(ex)

    @pytest.mark.parametrize(
        "kind", [EntityKind.ORG, EntityKind.PLACE, EntityKind.TEXT, EntityKind.EMAIL]
    )
    def test_non_name_kinds_get_no_joins(self, kind):
        ex = expand(entity(["Example University"], ["Other University"], kind=kind))
        assert [v.origin for v in ex.variants] == ["declared"]

    def test_indic_names(self):
        ex = expand(entity(["জেন ডো"], ["অ্যালেক্স স্মিথ"]))
        table = by_real(ex)
        assert table["জেনডো"].fake == "অ্যালেক্সস্মিথ"
        assert table["ডো জেন"].fake == "স্মিথ অ্যালেক্স"

    def test_index_aligned_forms(self):
        ex = expand(entity(["Jane Doe", "Janie D"], ["Alex Smith", "Al S"]))
        table = by_real(ex)
        assert canon(table["janied"].fake) == "als"
        assert canon(table["janedoe"].fake) == "alexsmith"

    def test_empty_forms_are_skipped(self):
        ex = expand(entity(["", "Jane Doe"], ["Alex", ""]))
        assert ex.variants == ()

    def test_case_duplicates_collapse_into_one_variant(self):
        ex = expand(entity(["Jane", "JANE"], ["Alex", "ALEX"], role="given"))
        assert len(ex.variants) == 1
        assert ex.variants[0].fake_for("JANE") == "ALEX"

    def test_declared_spelling_wins_over_generated(self):
        ex = expand(entity(["McDonald"], ["MacLeod"], role="family"))
        assert ex.variants[0].fake_for("McDonald") == "MacLeod"
        assert ex.variants[0].fake_for("MCDONALD") == "MACLEOD"

    def test_repr_is_value_free(self):
        ex = expand(entity(["Jane Doe"], ["Alex Smith"]))
        for text in (repr(ex), repr(ex.variants[0])):
            assert "Jane" not in text
            assert "Alex" not in text


# ── bijection over the expanded table ─────────────────────────────────────────


class TestValidateExpanded:
    def test_synthetic_persona_is_clean(self):
        flat = flatten(parse_persona(load_yaml(FIXTURE.read_bytes())))
        expanded = expand_all(flat)
        assert validate_expanded(expanded) == []
        assert sum(len(e.variants) for e in expanded) > len(expanded)

    def test_needs_generation_entities_are_skipped(self):
        flat = flatten(parse_persona(load_yaml(FIXTURE.read_bytes())))
        ids = {e.entity.id for e in expand_all(flat)}
        assert not {e.id for e in flat.entities if e.needs_generation} & ids

    def test_join_colliding_with_another_real_with_different_fake(self):
        full = entity(["Jane Doe"], ["Alex Smith"])
        user = entity(
            ["janedoe"],
            ["asmith"],
            kind=EntityKind.USERNAME,
            role="linux_user",
            id_="handles.linux_user",
        )
        codes = {f.code for f in validate_expanded([expand(full), expand(user)])}
        assert "E011" in codes

    def test_join_consistent_with_another_entity_is_fine(self):
        full = entity(["Jane Doe"], ["Alex Smith"])
        user = entity(
            ["janedoe"],
            ["alexsmith"],
            kind=EntityKind.USERNAME,
            role="linux_user",
            id_="handles.linux_user",
        )
        assert validate_expanded([expand(full), expand(user)]) == []

    def test_fake_join_equal_to_a_real_value(self):
        full = entity(["Jane Doe"], ["Alex Smith"])
        other = entity(
            ["alexsmith"], ["zed"], kind=EntityKind.USERNAME, role="github", id_="handles.github"
        )
        codes = {f.code for f in validate_expanded([expand(full), expand(other)])}
        assert codes & {"E012", "E013"}

    def test_findings_name_variant_origin_but_no_values(self):
        full = entity(["Jane Doe"], ["Alex Smith"])
        user = entity(
            ["janedoe"],
            ["asmith"],
            kind=EntityKind.USERNAME,
            role="linux_user",
            id_="handles.linux_user",
        )
        findings = validate_expanded([expand(full), expand(user)])
        text = " ".join(f"{f.path} {f.message}" for f in findings)
        assert "~join" in text or "~declared" in text
        for value in ("Jane", "jane", "Alex", "alex", "smith", "Doe"):
            assert value not in text


WORDS = st.text(alphabet="abcdefgh", min_size=2, max_size=6)


@st.composite
def name_entities(draw):
    count = draw(st.integers(1, 4))
    out = []
    for i in range(count):
        real = " ".join(draw(st.lists(WORDS, min_size=1, max_size=3)))
        fake = " ".join(draw(st.lists(WORDS, min_size=1, max_size=3)))
        out.append(
            entity([real], [fake], id_=f"people[{i}]", kind=EntityKind.PERSON_NAME, role="friend")
        )
    return out


@settings(max_examples=200)
@given(name_entities())
def test_property_clean_validation_means_no_fake_inside_any_real(entities):
    """M1.1 DoD: whenever validation passes, no expanded fake occurs (bounded) in an expanded real."""
    expanded = [expand(e) for e in entities]
    assume(validate_expanded(expanded) == [])
    reals = [v.real for item in expanded for v in item.variants]
    fakes = [v.fake for item in expanded for v in item.variants]
    for fake in fakes:
        for real in reals:
            assert not contains_bounded(fake, real)


@settings(max_examples=200)
@given(name_entities())
def test_property_every_spelling_maps_to_a_fake_with_the_same_canon(entities):
    for item in (expand(e) for e in entities):
        for variant in item.variants:
            for real, fake in variant.spellings:
                assert canon(real) == canon(variant.real)
                assert canon(fake) == canon(variant.fake)
                assert variant.fake_for(real) == fake


def test_year_of_study_is_left_out_like_in_m0():
    year = entity(
        ["2"], ["3"], kind=EntityKind.YEAR, role="year_of_study", id_="education[0].year_of_study"
    )
    name = entity(["Jo"], ["Al2"], role="given", id_="person.first_name")
    assert validate_expanded([expand(year), expand(name)]) == []


def test_validator_reports_expanded_collisions_in_persona_check():
    from veil.persona.validate import validate

    yaml_text = (
        'version: "1"\n'
        "person:\n"
        "  full_name: { real: Jane Doe, fake: Alex Smith }\n"
        "handles:\n"
        "  kaggle: { real: jd-kaggle, fake: alexsmith }\n"
    )
    report = validate(parse_persona(load_yaml(yaml_text)))
    codes = {(f.code, f.path) for f in report.errors}
    assert ("E010", "handles.kaggle~declared") in codes
