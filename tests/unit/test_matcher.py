"""engine/matcher.py (M1.4): AC matcher with raw-offset rewriting.

Oracles: the reference translator (same selection semantics) and the raw input itself (text
outside replaced spans must come out byte-identical, never NFKC-normalized).
"""

import unicodedata
from pathlib import Path

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from veil.engine import reference
from veil.engine.lexicon import build_lexicon
from veil.engine.matcher import Engine, Mapped, Matcher
from veil.persona.entities import flatten
from veil.persona.schema import parse_persona
from veil.persona.yamlio import load_yaml

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic_jane.yaml"
ZWSP, SHY = chr(0x200B), chr(0x00AD)
LIG_FI, LIG_FL = chr(0xFB01), chr(0xFB02)
FW_Q, FW_J = chr(0xFF31), chr(0xFF2A)
ACUTE = chr(0x0301)


def lexicon_from(text: str):
    return build_lexicon(flatten(parse_persona(load_yaml(text))))


@pytest.fixture(scope="module")
def lex():
    return lexicon_from(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def engine(lex):
    return Engine(lex)


# ── raw ↔ normalized mapping ──────────────────────────────────────────────────


class TestMapped:
    def test_plain_ascii_is_identity(self):
        m = Mapped("Jane Doe")
        assert m.text == "Jane Doe"
        assert m.to_raw(0, 4) == (0, 4)

    def test_ligature_expands_inside_one_cluster(self):
        m = Mapped(f"a{LIG_FI}b")
        assert m.text == "afib"
        assert m.to_raw(1, 3) == (1, 2)  # "fi" ↔ the ligature
        assert m.to_raw(1, 2) is None  # half the ligature: rejected
        assert m.to_raw(0, 4) == (0, 3)

    def test_combining_mark_composes_with_its_base(self):
        m = Mapped("e" + ACUTE + "x")
        assert m.text == "\N{LATIN SMALL LETTER E WITH ACUTE}x"
        assert m.to_raw(0, 1) == (0, 2)

    def test_fullwidth(self):
        m = Mapped(FW_J + "ane")
        assert m.text == "Jane"
        assert m.to_raw(0, 4) == (0, 4)

    def test_leading_combining_mark(self):
        m = Mapped(ACUTE + "a")
        assert m.raw == ACUTE + "a"
        assert len(m.clusters) == 2

    def test_empty(self):
        m = Mapped("")
        assert m.text == ""
        assert m.to_raw(0, 0) is None


# ── matcher behaviour ─────────────────────────────────────────────────────────


class TestBoundaries:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("timeout", "timeout"),
            ("Janet", "Janet"),
            ("jane04", "alex04"),
            ("janeResume", "alexResume"),
            ("JaneDoe", "AlexSmith"),
            ("/home/janed/", "/home/alexs/"),
            ("Jane's", "Alex's"),
            ("20240", "20240"),  # batch year 2024 must not match inside a longer number
            ("2024-25", "2023-25"),
            ("জেন লিখেছে", "অ্যালেক্স লিখেছে"),
            ("জেনা", "জেনা"),
            ("जेन", "एलेक्स"),
        ],
    )
    def test_cases(self, engine, text, expected):
        assert engine.forward(text) == expected


class TestRawPreservation:
    def test_ligatures_outside_matches_are_kept(self, engine):
        assert engine.forward(f"{LIG_FI}le by Jane") == f"{LIG_FI}le by Alex"

    def test_fullwidth_outside_matches_is_kept(self, engine):
        assert engine.forward(f"{FW_Q} Jane") == f"{FW_Q} Alex"

    def test_invisible_chars_outside_matches_are_kept(self, engine):
        text = f"a{ZWSP}b Jane c{SHY}d"
        assert engine.forward(text) == f"a{ZWSP}b Alex c{SHY}d"

    def test_crlf_and_tabs_kept(self, engine):
        assert engine.forward("Jane\r\n\tDoe") == "Alex Smith"  # whitespace run = one match
        assert engine.forward("x\r\n\ty") == "x\r\n\ty"

    def test_fullwidth_match_is_replaced_whole(self, engine):
        assert engine.forward(FW_J + "ANE wrote") == "ALEX wrote"

    def test_zero_width_inside_a_name_still_matches(self, engine):
        assert engine.forward("Ja" + ZWSP + "ne") == "Alex"

    def test_name_with_accent_is_a_different_name(self, engine):
        assert engine.forward("Jane" + ACUTE) == "Jane" + ACUTE

    def test_never_replaces_half_a_character(self):
        lex = lexicon_from(
            'version: "1"\nperson:\n  first_name: { real: f, fake: q, allow_short: true }\n'
        )
        assert Engine(lex).forward(f"{LIG_FI} f") == f"{LIG_FI} q"

    def test_whole_ligature_cluster_can_match(self):
        lex = lexicon_from(
            'version: "1"\nperson:\n  first_name: { real: Fi, fake: Xy, allow_short: true }\n'
        )
        assert Engine(lex).forward(f"{LIG_FI} Fi") == "xy Xy"


class TestSelection:
    def test_leftmost_longest(self, engine):
        assert engine.forward("Jane Doe") == "Alex Smith"

    def test_context_guard(self, engine):
        assert engine.forward("ssh orion") == "ssh kepler"
        assert engine.forward("the Orion nebula") == "the Orion nebula"

    def test_context_far_away_does_not_count(self, engine):
        text = "ssh" + " pad" * 80 + " orion"
        assert engine.forward(text).endswith("orion")

    def test_never_translate(self):
        lex = lexicon_from(
            'version: "1"\nperson:\n  first_name: { real: Ruby, fake: Opal }\nnever_translate: [Ruby]\n'
        )
        assert Engine(lex).forward("Ruby") == "Ruby"

    def test_never_reverse(self):
        lex = lexicon_from(
            'version: "1"\nperson:\n  first_name: { real: Jane, fake: Alex }\nnever_reverse: [Alex]\n'
        )
        engine = Engine(lex)
        assert engine.forward("Jane") == "Alex"
        assert engine.reverse("Alex") == "Alex"

    def test_find_reports_raw_spans(self, engine):
        matches = engine.forward_matcher.find(f"{LIG_FI} Jane")
        assert [(m.start, m.end, m.replacement) for m in matches] == [(2, 6, "Alex")]

    def test_repr_is_value_free(self, engine):
        text = (
            repr(engine)
            + repr(engine.forward_matcher)
            + repr(engine.forward_matcher.find("Jane")[0])
        )
        assert "Jane" not in text
        assert "Alex" not in text

    def test_empty_matcher(self):
        assert Matcher((), frozenset()).apply("anything") == "anything"


# ── properties ────────────────────────────────────────────────────────────────

REAL_BITS = st.sampled_from(
    [
        "Jane",
        "JANE DOE",
        "jane.doe@xyz.example.test",
        "/home/janed/",
        "jdoe@okaxis",
        "JDoe",
        "jane-thesis",
        "Ravi Kumar",
        "Springfield",
        "XYZIT",
        "ssh orion",
        "Orion",
        "2024",
        "জেন",
        "MS thesis",
    ]
)
FILLER = st.sampled_from(["the", "report", "42", "notes", "zq", "/srv/x", "ok", "timeout", "Janet"])
NASTY = st.sampled_from([LIG_FI, LIG_FL, FW_Q, ZWSP, SHY, ACUTE, "\t", "\r\n", "ß", "क"])
SEPARATORS = st.sampled_from([" ", "\n", ", ", ".", "/", "@", "-", "_", ""])
PIECES = st.lists(st.tuples(st.one_of(REAL_BITS, FILLER, NASTY), SEPARATORS), max_size=14)


def joined(parts) -> str:
    return "".join(a + b for a, b in parts)


@settings(max_examples=300)
@given(PIECES)
def test_property_matches_reference_on_normalized_text(lex, engine, parts):
    """Same selection semantics as the oracle wherever the input is already NFKC."""
    text = joined(parts)
    assume(unicodedata.normalize("NFKC", text) == text)
    assert engine.forward(text) == reference.forward(text, lex)
    assert engine.reverse(text) == reference.reverse(text, lex)


@settings(max_examples=300)
@given(PIECES)
def test_property_text_outside_matches_is_byte_identical(engine, parts):
    """M1.4 DoD: only matched raw spans change; everything else is copied verbatim."""
    text = joined(parts)
    matches = engine.forward_matcher.find(text)
    out = engine.forward(text)
    cursor_in, cursor_out = 0, 0
    for m in matches:
        gap = text[cursor_in : m.start]
        assert out[cursor_out : cursor_out + len(gap)] == gap
        cursor_out += len(gap) + len(m.replacement)
        cursor_in = m.end
    assert out[cursor_out:] == text[cursor_in:]


@settings(max_examples=300)
@given(st.lists(st.tuples(st.one_of(FILLER, NASTY), SEPARATORS), max_size=14))
def test_property_text_without_forms_is_untouched(engine, parts):
    text = joined(parts)
    assert engine.forward(text) == text


@settings(max_examples=300)
@given(PIECES)
def test_property_round_trip_on_normalized_text(engine, parts):
    """spec §5.5 for the production engine (text without fake forms, already NFKC)."""
    text = joined(parts)
    assume(unicodedata.normalize("NFKC", text) == text)
    assert engine.reverse(engine.forward(text)) == text


@settings(max_examples=200)
@given(PIECES)
def test_property_normalizing_the_output_gives_the_reference(lex, engine, parts):
    """Even on messy input, the only difference from the oracle is the untouched raw text."""
    text = joined(parts)
    out = engine.forward(text)
    assert unicodedata.normalize("NFKC", out) == unicodedata.normalize(
        "NFKC", reference.forward(text, lex)
    )
