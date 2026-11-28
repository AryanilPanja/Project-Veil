"""Mapped (matcher.py): segment map against a per-cluster reference; NFD Hangul (sweep 2026-11)."""

import tracemalloc
import unicodedata

from hypothesis import given, settings
from hypothesis import strategies as st

from tests.unit.test_matcher import FIXTURE, lexicon_from
from veil.engine import matcher
from veil.engine.matcher import Engine, Mapped

HANGUL_REAL, HANGUL_FAKE = "김민수", "박지훈"


def reference_mapping(raw: str):
    """The old per-cluster mapping: every cluster normalized on its own, one entry per char."""
    clusters, cluster_of, pieces, norm_len = [], [], [], 0
    for raw_start, raw_end in matcher._clusters(raw):
        piece = unicodedata.normalize("NFKC", raw[raw_start:raw_end])
        clusters.append((raw_start, raw_end, norm_len, norm_len + len(piece)))
        cluster_of.extend([len(clusters) - 1] * len(piece))
        pieces.append(piece)
        norm_len += len(piece)

    def to_raw(start, end):
        if start >= end:
            return None
        first, last = cluster_of[start], cluster_of[end - 1]
        if clusters[first][2] != start or clusters[last][3] != end:
            return None
        return clusters[first][0], clusters[last][1]

    return "".join(pieces), to_raw


ALPHABET = [
    *"ab Jz\n",
    "\u0301",  # combining acute
    "\u0323",  # combining dot below
    "\ufb01",  # fi ligature
    "\uff2a",  # fullwidth J
    "é", "ß", "Å",
    "ᄀ", "ᅡ", "ᆨ",  # conjoining jamo L V T
    "가", "한",  # precomposed Hangul (LV, LVT)
    "日", "か", "\u3099",  # kanji, kana, combining voiced mark
    "\u09c7", "\u09be", "ক",  # Bengali two-part vowel
]  # fmt: skip


@settings(max_examples=500)
@given(st.text(alphabet=ALPHABET, max_size=40), st.data())
def test_segments_map_like_the_per_cluster_reference(text, data):
    mapped = Mapped(text)
    ref_text, ref_to_raw = reference_mapping(text)
    assert mapped.text == ref_text
    if mapped.identity or not ref_text:
        return
    start = data.draw(st.integers(0, len(ref_text) - 1))
    end = data.draw(st.integers(start + 1, len(ref_text)))
    assert mapped.to_raw(start, end) == ref_to_raw(start, end)


def test_stable_run_characters_are_nfkc_alone():
    for ch in map(chr, range(0x110000)):
        if matcher._STABLE_RUN.fullmatch(ch):
            assert unicodedata.is_normalized("NFKC", ch), hex(ord(ch))
            assert not matcher._continues(ch), hex(ord(ch))


def test_conjoining_jamo_join_one_cluster():
    nfd = unicodedata.normalize("NFD", "김")
    assert len(nfd) == 3
    assert matcher._clusters(nfd) == [(0, 3)]


def _hangul_engine() -> Engine:
    yaml = FIXTURE.read_text(encoding="utf-8").replace(
        "full_name:    { real: Jane Doe, fake: Alex Smith }",
        f"full_name:    {{ real: {HANGUL_REAL}, fake: {HANGUL_FAKE} }}",
    )
    return Engine(lexicon_from(yaml))


def test_nfd_hangul_is_translated_and_audited():
    engine = _hangul_engine()
    nfd = unicodedata.normalize("NFD", f"{HANGUL_REAL} 씨가 왔다")
    out = engine.forward(nfd)
    assert HANGUL_FAKE in unicodedata.normalize("NFC", out)
    assert engine.audit(nfd)
    assert HANGUL_REAL in unicodedata.normalize(
        "NFC", engine.reverse(unicodedata.normalize("NFD", out))
    )


def _peak(text: str) -> int:
    tracemalloc.start()
    try:
        Mapped(text)
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_one_ligature_does_not_multiply_memory():
    text = "x" * 200_000
    # Was about 7x the all-ASCII cost (one tuple and one list slot per character).
    assert _peak(text + "\ufb01") < 1.5 * _peak(text)


# ── boundary: marks before a form take their base letter's case (sweep 2026-11) ──


def test_mark_before_uppercase_form_keeps_the_case_boundary():
    from veil.text.boundary import is_bounded

    for left in ("q\u0301", "x\u0323", "q\u0301\u0323"):
        text = left + "JD wrote"
        assert is_bounded(text, len(left), len(left) + 2), repr(text)
    assert not is_bounded("Q\u0301JD", 2, 4)  # Upper then Upper: still one word
    assert not is_bounded("\u0301JD"[0:3], 1, 3) or True  # lone mark at start: no crash
