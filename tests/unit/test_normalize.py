import unicodedata

import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil.text.normalize import DROPPED, canon, fold_with_map, nfkc


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Jane", "jane"),
        ("JANE DOE", "jane doe"),
        ("ＪＡＮＥ", "jane"),  # full-width → ASCII (NFKC)
        ("ﬁle", "file"),  # ligature
        ("Straße", "strasse"),  # casefold expands ß
        ("ǅ", "dž"),  # titlecase digraph
        ("J\u200bane", "jane"),  # zero-width space dropped
        ("J\u2060ane", "jane"),  # word joiner dropped
        ("\ufeffJane", "jane"),  # BOM dropped
        ("Ja\u00adne", "jane"),  # soft hyphen dropped
        ("  jane   doe \t\n", "jane doe"),  # whitespace collapsed and stripped
        ("jane\u00a0doe", "jane doe"),  # NBSP is whitespace
        ("", ""),
        ("   ", ""),
        ("\u200b\u200b", ""),
    ],
)
def test_canon(raw, expected):
    assert canon(raw) == expected


def test_zwj_and_zwnj_are_kept():
    # They change rendering and meaning in Bengali/Devanagari, so they must survive.
    assert "\u200d" in canon("ক্\u200dষ")
    assert "\u200c" in canon("ক্\u200cষ")


def test_bengali_and_devanagari_survive_unchanged_apart_from_nfkc():
    for word in ("রাম", "आदित्य", "জেন"):
        assert canon(word) == nfkc(word)


def test_nukta_precomposed_and_decomposed_are_equal():
    precomposed = "\u0958"  # DEVANAGARI LETTER QA
    decomposed = "\u0915\u093c"  # KA + NUKTA
    assert canon(precomposed) == canon(decomposed)


def test_dropped_set_never_contains_joiners():
    assert "\u200c" not in DROPPED
    assert "\u200d" not in DROPPED


def test_fold_with_map_tracks_origins():
    folded, origin = fold_with_map("Aß  b")
    assert folded == "ass b"
    assert origin == [0, 1, 1, 2, 4]


def test_fold_with_map_skips_dropped_characters():
    folded, origin = fold_with_map("a\u200bb")
    assert folded == "ab"
    assert origin == [0, 2]


def test_fold_with_map_lengths_always_agree():
    folded, origin = fold_with_map("İstanbul ß \u200b x")
    assert len(folded) == len(origin)


@given(st.text())
def test_canon_is_idempotent(text):
    assert canon(canon(text)) == canon(text)


@given(st.text())
def test_canon_has_no_dropped_chars_or_edge_spaces(text):
    out = canon(text)
    assert not (set(out) & DROPPED)
    assert out == out.strip(" ")
    assert "  " not in out


@given(st.text())
def test_canon_output_is_nfkc_stable(text):
    out = canon(text)
    assert canon(unicodedata.normalize("NFKC", out)) == out


@given(st.text())
def test_fold_map_origins_are_valid_and_non_decreasing(text):
    source = nfkc(text)
    folded, origin = fold_with_map(source)
    assert len(folded) == len(origin)
    assert all(0 <= i < len(source) for i in origin)
    assert origin == sorted(origin)
