"""engine/academic.py + context.py + Engine.ambiguous (M1.5): class terms, guards, round trip."""

import unicodedata
from pathlib import Path

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from veil.engine import academic, reference
from veil.engine.context import DEFAULT_WINDOW, context_near, window_of
from veil.engine.lexicon import build_lexicon
from veil.engine.matcher import Engine
from veil.persona.entities import flatten
from veil.persona.schema import parse_persona
from veil.persona.yamlio import load_yaml

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic_jane.yaml"


def engine_from(text: str) -> Engine:
    return Engine(build_lexicon(flatten(parse_persona(load_yaml(text)))))


@pytest.fixture(scope="module")
def lex():
    return build_lexicon(flatten(parse_persona(load_yaml(FIXTURE.read_bytes()))))


@pytest.fixture(scope="module")
def engine(lex):
    return Engine(lex)


EDU = (
    'version: "1"\neducation:\n'
    "  - institution: {{ real: XYZ Institute, fake: ABC University }}\n"
    "    aliases: {{ real: [XYZI], fake: [ABCU] }}\n"
    "    degree: {{ enabled: {deg}, real: MS, fake: PhD }}\n"
    "    year_of_study: {{ enabled: {year}, real: '2', fake: '3', context_required: {ctx} }}\n"
)


def edu_engine(deg="true", year="true", ctx="true") -> Engine:
    return engine_from(EDU.format(deg=deg, year=year, ctx=ctx))


# ── helpers ───────────────────────────────────────────────────────────────────


class TestHelpers:
    @pytest.mark.parametrize(
        ("term", "expected"),
        [
            ("MS", "an"),
            ("MBA", "an"),
            ("PhD", "a"),
            ("BTech", "a"),
            ("MTech", "a"),
            ("M.S.", "an"),
            ("HSC", "an"),
            ("BS", "a"),
            ("engineering", "an"),
            ("masters", "a"),
            ("undergrad", "an"),
        ],
    )
    def test_article(self, term, expected):
        assert academic.article(term) == expected

    @pytest.mark.parametrize(
        ("n", "suffix"),
        [
            (1, "st"),
            (2, "nd"),
            (3, "rd"),
            (4, "th"),
            (11, "th"),
            (12, "th"),
            (13, "th"),
            (21, "st"),
            (22, "nd"),
        ],
    )
    def test_ordinal_suffix(self, n, suffix):
        assert academic.ordinal_suffix(n) == suffix

    def test_ordinal_phrases_are_aligned_and_unique(self):
        for n in range(1, 11):
            phrases = academic.ordinal_phrases(n)
            assert len(phrases) == len(academic.ordinal_phrases(1))
            assert len(set(phrases)) == len(phrases)
        assert "2nd year" in academic.ordinal_phrases(2)
        assert "II year" in academic.ordinal_phrases(2)
        assert "second-year" in academic.ordinal_phrases(2)


# ── degree ────────────────────────────────────────────────────────────────────


class TestDegree:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("I am an MS student", "I am a PhD student"),
            ("my MS thesis", "my PhD thesis"),
            ("MS program", "PhD program"),
            ("my MS", "my PhD"),
            ("an MS", "a PhD"),
            ("MS STUDENT", "PHD STUDENT"),
        ],
    )
    def test_phrases(self, text, expected):
        engine = edu_engine(year="false")
        assert engine.forward(text) == expected
        assert engine.reverse(expected) == text

    @pytest.mark.parametrize(
        "text", ["MS", "500 ms", "MS Word", "Microsoft", "ms.", "the MS-DOS era", "a PhD"]
    )
    def test_bare_term_never_matches(self, text):
        assert edu_engine(year="false").forward(text) == text

    def test_disabled_degree_translates_nothing(self):
        assert edu_engine(deg="false", year="false").forward("an MS student") == "an MS student"

    def test_declared_phrases_and_templates_coexist(self, engine):
        assert engine.forward("my MS") == "my PhD"  # declared in the fixture
        assert engine.forward("MS candidate") == "PhD candidate"  # template

    def test_same_degree_on_both_sides_makes_no_templates(self):
        engine = engine_from(
            EDU.format(deg="true", year="false", ctx="true").replace("fake: PhD", "fake: MS")
        )
        assert engine.forward("an MS student") == "an MS student"


# ── year of study ─────────────────────────────────────────────────────────────


class TestYear:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("2nd year at XYZ Institute", "3rd year at ABC University"),
            ("second-year MS student", "third-year PhD student"),
            ("II year, XYZI", "III year, ABCU"),
            ("Year 2 of my MS", "Year 3 of my PhD"),
            ("Second Year MS student", "Third Year PhD student"),
        ],
    )
    def test_with_context(self, text, expected):
        engine = edu_engine()
        assert engine.forward(text) == expected
        assert engine.reverse(expected) == text

    @pytest.mark.parametrize(
        "text",
        [
            "2nd year",
            "I am in my second year.",
            "year 2 of the plan",
            "Second Year MS",
            "2nd year 500 ms",
        ],
    )
    def test_without_context_nothing_changes(self, text):
        assert edu_engine().forward(text) == text

    @pytest.mark.parametrize("text", ["2", "Block 2", "2 apples", "version 2", "2nd", "20 years"])
    def test_bare_number_never_matches(self, text):
        assert edu_engine(ctx="false").forward(text) == text

    def test_regression_bare_year_entity_is_not_a_form(self, engine):
        # Before M1.5 the year entity "2" → "3" went through the generic path.
        assert engine.forward("I have 2 cats, room 2, XYZIT") == "I have 2 cats, room 2, ABCU"

    def test_context_must_be_near(self):
        text = "2nd year" + " filler" * 20 + " XYZ Institute"
        assert edu_engine().forward(text).startswith("2nd year")

    def test_context_keyword_must_be_bounded(self):
        # "MS" (the degree, a context keyword) must not be found inside "items".
        assert edu_engine(deg="false").forward("2nd year items") == "2nd year items"

    def test_context_not_required(self):
        assert edu_engine(ctx="false").forward("I am in my 2nd year") == "I am in my 3rd year"

    def test_reverse_uses_fake_side_context(self):
        engine = edu_engine()
        assert engine.reverse("3rd year at ABC University") == "2nd year at XYZ Institute"
        assert engine.reverse("3rd year at XYZ Institute") == "3rd year at XYZ Institute"

    @pytest.mark.parametrize(("real", "fake"), [("0", "1"), ("11", "2"), ("2", "2"), ("2", "x")])
    def test_out_of_range_or_equal_years_make_no_phrases(self, real, fake):
        text = EDU.format(deg="false", year="true", ctx="false").replace(
            "real: '2', fake: '3'", f"real: '{real}', fake: '{fake}'"
        )
        try:
            engine = engine_from(text)
        except Exception:  # noqa: BLE001 - schema may reject; either way nothing is translated
            return
        assert engine.forward(f"{real}st year {real}nd year") == f"{real}st year {real}nd year"


# ── context helper ────────────────────────────────────────────────────────────


class TestContextHelper:
    def test_window_of(self, lex):
        entity = next(f.entity for f in lex.forward if f.entity.id.endswith("~ordinals"))
        assert window_of(entity) == academic.YEAR_WINDOW
        plain = next(f.entity for f in lex.forward if not f.entity.contexts)
        assert window_of(plain) == DEFAULT_WINDOW
        from veil.text.containment import PreparedText

        assert context_near(PreparedText("anything"), 0, 3, plain, None, {})


# ── ambiguity and the full round trip ─────────────────────────────────────────


class TestAmbiguous:
    def test_counts_fake_forms_in_real_input(self, engine):
        counts = engine.ambiguous("Alex met Alex Smith in Rivertown")
        assert sum(counts.values()) == 3
        assert all(isinstance(k, str) for k in counts)

    def test_none_in_clean_text(self, engine):
        assert engine.ambiguous("Jane met John in Springfield") == {}

    def test_never_reverse_names_are_not_counted(self):
        engine = engine_from(
            'version: "1"\nperson:\n  last_name: { real: Doe, fake: Thakur }\n'
            "never_reverse: [Anurag Thakur]\n"
        )
        assert engine.ambiguous("Anurag Thakur spoke") == {}

    def test_report_holds_ids_not_values(self, engine):
        counts = engine.ambiguous("Alex")
        assert "Alex" not in " ".join(counts)


REAL_BITS = st.sampled_from(
    [
        "Jane",
        "JANE DOE",
        "jane.doe@xyz.example.test",
        "/home/janed/",
        "jdoe@okaxis",
        "JDoe",
        "Ravi Kumar",
        "Springfield",
        "XYZIT",
        "ssh orion",
        "MS thesis",
        "an MS student",
        "2nd year",
        "second-year",
        "XYZ Institute of Technology",
        "2",
        "Block 2",
        "500 ms",
    ]
)
FAKE_BITS = st.sampled_from(["Alex", "PhD", "3rd year", "ABCU", "Rivertown", "kepler"])
FILLER = st.sampled_from(["the", "report", "42", "notes", "ok", "timeout", "Janet", "items"])
# No empty separator: gluing tokens makes casings like "DOEJane" that no different-length fake can
# mirror, so they cannot round-trip (documented limit, like full-width spellings).
SEP = st.sampled_from([" ", "\n", ", ", ".", "/", "@", "-"])


@settings(max_examples=400)
@given(st.lists(st.tuples(st.one_of(REAL_BITS, FILLER, FAKE_BITS), SEP), max_size=14))
def test_property_round_trip_for_text_without_fake_forms(engine, parts):
    """M1.5 DoD: reverse(forward(x)) == x whenever x has no fake forms (and is NFKC)."""
    text = "".join(a + b for a, b in parts)
    assume(unicodedata.normalize("NFKC", text) == text)
    assume(not engine.ambiguous(text))
    assert engine.reverse(engine.forward(text)) == text


@settings(max_examples=300)
@given(st.lists(st.tuples(st.one_of(REAL_BITS, FILLER, FAKE_BITS), SEP), max_size=14))
def test_property_engine_still_matches_reference(lex, engine, parts):
    text = "".join(a + b for a, b in parts)
    assume(unicodedata.normalize("NFKC", text) == text)
    assert engine.forward(text) == reference.forward(text, lex)
    assert engine.reverse(text) == reference.reverse(text, lex)


class TestAcademicProfile:
    def test_profile_from_fixture(self):
        flat = flatten(parse_persona(load_yaml(FIXTURE.read_bytes())))
        (profile,) = flat.academic
        assert profile.path == "education[0]"
        assert (profile.degree_real, profile.degree_fake) == ("MS", "PhD")
        assert (profile.year_real, profile.year_fake) == ("2", "3")
        assert profile.year_context_required

    def test_bare_degree_term_is_never_a_context_keyword(self):
        flat = flatten(parse_persona(load_yaml(FIXTURE.read_bytes())))
        (profile,) = flat.academic
        assert "MS" not in profile.context_real
        assert "PhD" not in profile.context_fake
        assert "XYZIT" in profile.context_real
        assert "ABCU" in profile.context_fake

    def test_entries_without_class_terms_have_no_profile(self):
        flat = flatten(
            parse_persona(
                load_yaml(
                    'version: "1"\neducation:\n  - institution: { real: A School, fake: B School }\n'
                )
            )
        )
        assert flat.academic == ()

    def test_repr_is_value_free(self):
        flat = flatten(parse_persona(load_yaml(FIXTURE.read_bytes())))
        assert "XYZ" not in repr(flat.academic[0])
        assert "MS" not in repr(flat.academic[0])


class TestUnitDistances:
    def test_plain_text_counts_characters(self):
        from veil.engine.context import Distances

        d = Distances(20, [])
        assert d.gap((0, 4), (10, 12)) == 6
        assert d.gap((10, 12), (0, 4)) == 6
        assert d.gap((0, 4), (4, 6)) == 0
        assert d.gap((0, 5), (3, 8)) == 0

    def test_a_replaced_span_counts_one_unit_whatever_its_length(self):
        from veil.engine.context import Distances

        short = Distances(30, [(10, 12)])
        long = Distances(40, [(10, 22)])
        # From the end of [0,4) to a keyword right after the span: 6 chars + 1 unit.
        assert short.gap((0, 4), (12, 14)) == 7
        assert long.gap((0, 4), (22, 24)) == 7

    def test_several_spans(self):
        from veil.engine.context import Distances

        d = Distances(50, [(5, 9), (12, 30)])
        assert d.gap((0, 2), (40, 42)) == 3 + 1 + 3 + 1 + 10

    def test_regression_round_trip_across_length_changing_names(self, engine):
        """Found by the round-trip property: three JANE DOE → ALEX SMITH replacements between
        "2nd year" and "MS thesis" used to push the keyword out of a *character* window in
        reverse only."""
        text = "2nd year Jane Jane JANE DOE JANE DOE JANE DOE MS thesis "
        out = engine.forward(text)
        assert out.startswith("3rd year")
        assert engine.reverse(out) == text

    @pytest.mark.parametrize("names", [0, 1, 3, 6, 10])
    def test_window_is_symmetric_for_any_number_of_replacements(self, engine, names):
        text = "2nd year " + "JANE DOE " * names + "MS thesis"
        assert engine.reverse(engine.forward(text)) == text
