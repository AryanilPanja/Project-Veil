"""text/aho.py (M1.3): the Aho-Corasick index must agree exactly with M0's naive `find_bounded`."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from veil.text.aho import Hit, PatternIndex, containment_pairs
from veil.text.containment import NaiveIndex, PreparedText, find_bounded

ZWSP, ZWJ, SHY = chr(0x200B), chr(0x200D), chr(0x00AD)
COMBINING_ACUTE = chr(0x0301)
LIGATURE_FI = chr(0xFB01)
FULLWIDTH_A = chr(0xFF21)

# Small alphabet so patterns actually occur; full of the cases that broke M0 once.
ALPHABET = [
    *"abAB jJ.-_@/09",
    "ß",
    LIGATURE_FI,
    FULLWIDTH_A,
    COMBINING_ACUTE,
    ZWSP,
    ZWJ,
    SHY,
    "জ",
    "ে",
    "न",
    "\n",
    "\t",
]
TEXT = st.text(alphabet=ALPHABET, max_size=60)
PATTERN = st.text(alphabet=ALPHABET, min_size=1, max_size=6)


def oracle(patterns, text) -> list[Hit]:
    prepared = PreparedText(text)
    hits = [
        Hit(span.start, span.end, i)
        for i, pattern in enumerate(patterns)
        for span in find_bounded(pattern, prepared)
    ]
    return sorted(set(hits))


@settings(max_examples=400)
@given(st.lists(PATTERN, min_size=1, max_size=8), TEXT)
def test_property_aho_equals_naive(patterns, text):
    assert sorted(set(PatternIndex(patterns).find(text))) == oracle(patterns, text)


@settings(max_examples=200)
@given(st.lists(PATTERN, min_size=1, max_size=5), TEXT, st.data())
def test_property_planted_patterns_are_found_like_naive(patterns, filler, data):
    """Plant patterns into the text so most examples have real hits, not just misses."""
    pieces = [filler]
    for _ in range(data.draw(st.integers(1, 4))):
        pieces.append(data.draw(st.sampled_from(patterns)))
        pieces.append(data.draw(st.sampled_from([" ", ".", "/", "@", "-", "x", "9", ""])))
    text = "".join(pieces)
    assert sorted(set(PatternIndex(patterns).find(text))) == oracle(patterns, text)


class TestExamples:
    def test_overlapping_and_nested(self):
        index = PatternIndex(["Jane", "Jane Doe", "Doe"])
        assert index.find("Jane Doe") == [Hit(0, 4, 0), Hit(0, 8, 1), Hit(5, 8, 2)]

    def test_case_and_width_insensitive(self):
        index = PatternIndex(["ab"])
        assert [h.start for h in index.find("AB, ab, " + FULLWIDTH_A + "b")] == [0, 4, 8]

    def test_boundaries(self):
        index = PatternIndex(["jane", "2021"])
        assert index.find("janet") == []
        assert index.find("jane04") == [Hit(0, 4, 0)]
        assert index.find("20217") == []
        assert index.find("janeResume") == [Hit(0, 4, 0)]
        assert index.find("/home/jane/") == [Hit(6, 10, 0)]

    def test_never_splits_a_character(self):
        assert PatternIndex(["s"]).find("ß") == []
        assert PatternIndex(["ss"]).find("ß") == [Hit(0, 1, 0)]

    def test_invisible_characters_do_not_hide_a_match(self):
        index = PatternIndex(["jane"])
        assert index.find("ja" + ZWSP + "ne") == [Hit(0, 5, 0)]
        assert index.find("ja" + SHY + "ne") == [Hit(0, 5, 0)]

    def test_duplicate_patterns_report_every_id(self):
        index = PatternIndex(["Jane", "JANE", "jane"])
        assert index.find("jane") == [Hit(0, 4, 0), Hit(0, 4, 1), Hit(0, 4, 2)]

    @pytest.mark.parametrize("patterns", [[], [""], ["   "], [ZWSP]])
    def test_no_usable_patterns(self, patterns):
        assert PatternIndex(patterns).find("anything at all") == []

    def test_empty_text(self):
        assert PatternIndex(["a"]).find("") == []
        assert PatternIndex(["a"]).find(ZWSP) == []

    def test_indic(self):
        index = PatternIndex(["জেন"])
        assert index.find("জেন লিখেছে") == [Hit(0, 3, 0)]
        assert index.find("জেনা") == []  # letter continues: not bounded

    def test_prepared_text_reuse(self):
        index = PatternIndex(["jane"])
        prepared = PreparedText("Jane and jane")
        assert index.find(prepared) == index.find("Jane and jane")

    def test_repr_has_no_patterns(self):
        assert repr(PatternIndex(["Jane"])) == "PatternIndex(patterns=1)"


def test_scale_many_patterns_one_pass():
    patterns = [f"name{i:04d}" for i in range(5000)]
    index = PatternIndex(patterns)
    text = " ".join(patterns[::7]) * 3
    hits = index.find(text)
    assert len(hits) == 3 * len(patterns[::7])


@settings(max_examples=300)
@given(st.lists(PATTERN, min_size=1, max_size=8), st.lists(TEXT, min_size=1, max_size=6))
def test_property_containment_pairs_equal_naive(needles, haystacks):
    naive = NaiveIndex(haystacks)
    expected = {i: naive.containing(n) for i, n in enumerate(needles) if naive.containing(n)}
    assert containment_pairs(needles, haystacks) == expected


def test_containment_pairs_examples():
    assert containment_pairs(["doe", "jane"], ["Jane Doe", "janet", "x doe"]) == {0: [0, 2], 1: [0]}
    assert containment_pairs([], ["a"]) == {}
    assert containment_pairs(["a"], []) == {}
