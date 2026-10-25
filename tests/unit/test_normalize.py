import unicodedata

import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil.text.normalize import canon, fold_with_map, is_dropped, nfkc


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


def test_joiners_are_never_dropped():
    assert not is_dropped(chr(0x200C))
    assert not is_dropped(chr(0x200D))


@pytest.mark.parametrize(
    "cp",
    [
        0x200B,
        0x2060,
        0xFEFF,
        0x00AD,
        0x200E,
        0x200F,
        0x202A,
        0x202E,
        0x2066,
        0x2069,
        0x034F,
        0xFE0F,
        0x180E,
    ],
)
def test_invisible_format_characters_are_dropped(cp):
    assert is_dropped(chr(cp))
    assert canon("Ja" + chr(cp) + "ne") == "jane"


@pytest.mark.parametrize("ch", ["a", " ", "-", chr(0x09BE), chr(0x093C)])
def test_visible_characters_are_not_dropped(ch):
    assert not is_dropped(ch)


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
    assert not any(is_dropped(c) for c in out)
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


# ── M1.8 sweep: the ASCII fast path must be exactly the general algorithm ──

from hypothesis import given as _given  # noqa: E402
from hypothesis import settings as _settings  # noqa: E402
from hypothesis import strategies as _st  # noqa: E402

from veil.text import normalize as _normalize  # noqa: E402

ASCII_ALL = _st.text(alphabet=[chr(i) for i in range(128)], max_size=80)


@_settings(max_examples=500)
@_given(ASCII_ALL)
def test_property_ascii_fast_path_equals_general(text):
    assert _normalize.fold_with_map(text) == _normalize._fold_with_map_general(text)


def test_fast_path_handles_every_ascii_whitespace_kind():
    text = "a\tb\nc\rd\x0be\x0cf\x1cg\x1dh\x1ei\x1fj  k"
    assert _normalize.fold_with_map(text) == _normalize._fold_with_map_general(text)
    assert _normalize.fold_with_map(text)[0] == "a b c d e f g h i j k"


MIXED = _st.text(
    alphabet=[chr(i) for i in range(128)]
    + ["ß", "\u00ad", "\u200b", "\u200d", "\u3000", "\u00a0", "জ", "ে", "İ", "ﬁ", "Ａ", "\u0301"],
    max_size=80,
)


@_settings(max_examples=500)
@_given(MIXED)
def test_property_mixed_text_fast_path_equals_general(text):
    """ASCII stretches in mixed text, incl. whitespace runs that span ASCII and non-ASCII."""
    assert _normalize.fold_with_map(text) == _normalize._fold_with_map_general(text)
