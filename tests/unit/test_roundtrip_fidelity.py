"""Round-trip fidelity (board Q15): case per word and whitespace inside a match come back exactly.

reverse(forward(x)) == x byte for byte, for names in any per-word case (`Doe jane`, `JANE.doe`,
`JaneDOE`) and split by any whitespace (`Jane⏎Doe`, no-break spaces from web pages).
Synthetic persona only.
"""

import itertools
import unicodedata

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from tests.unit.test_matcher import FIXTURE, lexicon_from
from veil.engine import reference
from veil.engine.forms import Variant, case_like, raw_whitespace, respace, word_spans
from veil.engine.matcher import Engine

NBSP, EN_SPACE, ZWSP = chr(0xA0), chr(0x2002), chr(0x200B)
FW_J = chr(0xFF2A)  # full-width J


@pytest.fixture(scope="module")
def lex():
    return lexicon_from(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def engine(lex):
    return Engine(lex)


def round_trip(engine, text: str) -> tuple[str, str]:
    fake = engine.forward(text)
    return fake, engine.reverse(fake)


# ── helpers ───────────────────────────────────────────────────────────────────


class TestWordSpans:
    @pytest.mark.parametrize(
        ("text", "words"),
        [
            ("", []),
            ("jane", ["jane"]),
            ("Jane Doe", ["Jane", "Doe"]),
            ("jane.doe", ["jane", "doe"]),
            ("JaneDoe", ["Jane", "Doe"]),
            ("janeDoe", ["jane", "Doe"]),
            ("JaneDOE", ["Jane", "DOE"]),
            ("JANEdoe", ["JANEdoe"]),  # Upper→lower is not a hump
            ("Doe, Jane", ["Doe", "Jane"]),
            ("jane_doe-04", ["jane", "doe", "04"]),
            ("  a  ", ["a"]),
            ("জেন ডো", ["জেন", "ডো"]),
            ("...", []),
            ("नमस्ते जेन", ["नमस्ते", "जेन"]),
            ("e" + chr(0x301) + "x", ["e" + chr(0x301) + "x"]),
            (chr(0x301) + "a", [chr(0x301) + "a"]),
        ],
    )
    def test_table(self, text, words):
        assert [text[s:e] for s, e in word_spans(text)] == words

    @given(st.text(max_size=30))
    def test_spans_are_ordered_disjoint_alnum(self, text):
        spans = word_spans(text)
        assert all(s < e for s, e in spans)
        assert all(a[1] <= b[0] for a, b in itertools.pairwise(spans))
        is_word = lambda c: c.isalnum() or unicodedata.category(c).startswith("M")  # noqa: E731
        assert all(all(is_word(c) for c in text[s:e]) for s, e in spans)
        covered = {i for s, e in spans for i in range(s, e)}
        assert all(i in covered for i, c in enumerate(text) if is_word(c))


class TestRespace:
    @pytest.mark.parametrize(
        ("source", "target", "out"),
        [
            ("Jane\nDoe", "Alex Smith", "Alex\nSmith"),
            ("Jane \t Doe", "Alex Smith", "Alex \t Smith"),
            (f"Jane{NBSP}Doe", "Alex Smith", f"Alex{NBSP}Smith"),
            ("Doe,\n Jane", "Smith, Alex", "Smith,\n Alex"),
            ("Jane\nDoe", "Alex Smith Jr", "Alex Smith Jr"),  # gap counts differ: unchanged
            ("Jane Q\nDoe", "Alex Smith", "Alex Smith"),
            ("JaneDoe", "AlexSmith", "AlexSmith"),
            ("Jane\nDoe", "Alex  Smith", "Alex  Smith"),  # target not single-spaced
        ],
    )
    def test_table(self, source, target, out):
        assert respace(source, target) == out


class TestRawWhitespace:
    @pytest.mark.parametrize(
        ("found", "raw", "out"),
        [
            ("Jane Doe", f"Jane{NBSP}Doe", f"Jane{NBSP}Doe"),
            ("Jane Doe", "Jane Doe", "Jane Doe"),
            ("Jane  Doe", f"Jane{EN_SPACE}\nDoe", f"Jane{EN_SPACE}\nDoe"),
            ("JaneDoe", "JaneDoe", "JaneDoe"),
            ("Jane Doe", f"{FW_J}ane{NBSP}Doe", f"Jane{NBSP}Doe"),  # letters stay normalized
            ("Jane Doe", "Jane\nQ\nDoe", "Jane Doe"),  # run counts differ: unchanged
        ],
    )
    def test_table(self, found, raw, out):
        assert raw_whitespace(found, raw) == out


class TestFakeFor:
    VARIANT = Variant(
        real="Jane Doe",
        fake="Alex Smith",
        spellings=(
            ("Jane Doe", "Alex Smith"),
            ("jane doe", "alex smith"),
            ("JANE DOE", "ALEX SMITH"),
        ),
        origin="declared",
    )

    @pytest.mark.parametrize(
        ("matched", "fake"),
        [
            ("Jane Doe", "Alex Smith"),
            ("jane Doe", "alex Smith"),
            ("JANE doe", "ALEX smith"),
            ("Jane DOE", "Alex SMITH"),
            ("Jane\nDoe", "Alex\nSmith"),
            ("jane\t\tDOE", "alex\t\tSMITH"),
            (
                "jAnE dOe",
                "aLeX Smith",
            ),  # "dOe" vs "smith": no rule maps it, the word keeps the spelling's case
        ],
    )
    def test_table(self, matched, fake):
        assert self.VARIANT.fake_for(matched) == fake

    def test_glued_without_structure_falls_back(self):
        variant = Variant(
            real="janedoe", fake="alexsmith", spellings=(("janedoe", "alexsmith"),), origin="join"
        )
        assert variant.fake_for("JANEdoe") == case_like("JANEdoe", "alexsmith")  # as before


# ── engine round trips ────────────────────────────────────────────────────────


class TestEngineRoundTrip:
    @pytest.mark.parametrize(
        ("text", "fake"),
        [
            ("Doe jane", "Smith alex"),
            ("JANE.doe", "ALEX.smith"),
            ("JaneDOE", "AlexSMITH"),
            ("doeJane", "smithAlex"),
            ("jane_Doe", "alex_Smith"),
            ("Jane\nDoe", "Alex\nSmith"),
            ("Jane\r\n\tDoe", "Alex\r\n\tSmith"),
            (f"Jane{NBSP}Doe", f"Alex{NBSP}Smith"),
            (f"Doe,{NBSP}Jane", f"Smith,{NBSP}Alex"),
            ("JANE\nDoe", "ALEX\nSmith"),
            ("Doe,\n  jane", "Smith,\n  alex"),
            (
                "Mail jane.doe@xyz.example.test\nfrom Jane\nDoe",
                "Mail alex.smith@abc.example.test\nfrom Alex\nSmith",
            ),
        ],
    )
    def test_exact(self, engine, text, fake):
        assert round_trip(engine, text) == (fake, text)

    @pytest.mark.parametrize(
        "text", ["jane doe", "Jane Doe", "JANE DOE", "janeDoe", "JaneDoe", "jAnE", "JaneD", "JDoe"]
    )
    def test_previously_working_forms_unchanged(self, engine, text):
        assert round_trip(engine, text)[1] == text

    @pytest.mark.parametrize("text", [f"{FW_J}ane Doe", f"Ja{ZWSP}ne Doe"])
    def test_normalized_letters_inside_a_match_are_not_restored(self, engine, text):
        # Known limit: the replaced span is rewritten from the normalized text (full-width
        # letters, invisible characters). The words still come back.
        fake, back = round_trip(engine, text)
        assert "Jane" not in fake
        assert back.split() == ["Jane", "Doe"]

    def test_matcher_agrees_with_reference_on_whitespace_and_case(self, lex, engine):
        for text in ("Doe jane", "JANE.doe", "Jane\nDoe", "JaneDOE"):
            assert engine.forward(text) == reference.forward(text, lex)


WORDS = st.sampled_from(["Jane", "Doe"])
WORD_CASE = st.sampled_from([str.lower, str.upper, str.capitalize])
GAP = st.sampled_from([" ", "  ", "\n", "\t", "\r\n", NBSP, f" {NBSP}", EN_SPACE, ", ", ",\n"])
FILLER = st.sampled_from(
    ["hello", "the", "(", ")", ".", "XYZIT", "jane.doe@xyz.example.test", "2024", "জেন"]
)


@st.composite
def texts(draw):
    pieces: list[str] = []
    for _ in range(draw(st.integers(0, 8))):
        if draw(st.booleans()):
            pieces.append(draw(WORD_CASE)(draw(WORDS)))
        else:
            pieces.append(draw(FILLER))
        pieces.append(draw(GAP))
    return "".join(pieces)


@st.composite
def glued(draw):
    """Joins with a per-part case that has visible word structure."""
    first, second = draw(st.permutations(["jane", "doe"]))
    sep = draw(st.sampled_from(["", ".", "_", "-"]))
    pattern = draw(
        st.sampled_from(["lower", "upper", "pascal", "camel", "last-upper", "first-upper"])
    )
    if sep == "" and pattern == "first-upper":
        pattern = "pascal"  # "JANEdoe" has no visible boundary
    a, b = {
        "lower": (first, second),
        "upper": (first.upper(), second.upper()),
        "pascal": (first.capitalize(), second.capitalize()),
        "camel": (first, second.capitalize()),
        "last-upper": (first.capitalize(), second.upper()),
        "first-upper": (first.upper(), second),
    }[pattern]
    return a + sep + b


class TestProperties:
    @given(texts())
    def test_round_trip_exact_any_case_and_whitespace(self, engine, text):
        assume(not engine.ambiguous(text))
        assert round_trip(engine, text)[1] == text

    @given(glued())
    def test_round_trip_exact_joins(self, engine, text):
        assume(not engine.ambiguous(text))
        assert round_trip(engine, text)[1] == text

    @given(texts())
    def test_whitespace_outside_and_inside_matches_is_preserved(self, engine, text):
        fake = engine.forward(text)
        ws = lambda s: [c for c in s if c.isspace()]  # noqa: E731
        assert ws(fake) == ws(text)

    @given(texts())
    def test_no_real_name_left(self, engine, text):
        fake = engine.forward(text).lower()
        for word in fake.replace(",", " ").split():
            assert word not in ("jane", "doe")
