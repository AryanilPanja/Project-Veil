import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil.text.containment import NaiveIndex, PreparedText, Span, contains_bounded, find_bounded
from veil.text.normalize import canon, nfkc


def test_find_returns_spans_in_original_text():
    assert find_bounded("jane", "Hi Jane, I'm jane.") == [Span(3, 7), Span(13, 17)]


def test_spans_cover_expanded_whitespace():
    text = "Jane    Doe"
    [span] = find_bounded("jane doe", text)
    assert text[span.start : span.end] == "Jane    Doe"


def test_spans_cover_invisible_characters():
    text = "x Ja\u200bne y"
    [span] = find_bounded("jane", text)
    assert text[span.start : span.end] == "Ja\u200bne"


def test_span_for_casefold_expansion_covers_the_whole_character():
    [span] = find_bounded("strasse", "die Straße")
    assert "die Straße"[span.start : span.end] == "Straße"


def test_overlapping_bounded_occurrences_are_all_reported():
    assert find_bounded("a.a", "a.a.a") == [Span(0, 3), Span(2, 5)]


def test_unbounded_occurrences_are_skipped_but_later_ones_found():
    assert find_bounded("jane", "janet jane") == [Span(6, 10)]


def test_full_width_haystack_spans_index_the_nfkc_text():
    raw = "ＪＡＮＥ"
    [span] = find_bounded("jane", raw)
    assert nfkc(raw)[span.start : span.end] == "JANE"


def test_prepared_text_can_be_reused():
    hay = PreparedText("Jane met jane and JANE")
    assert len(find_bounded("jane", hay)) == 3
    assert contains_bounded("met", hay)
    assert not contains_bounded("me", hay)


def test_empty_needle_matches_nothing():
    assert find_bounded("", "jane") == []
    assert find_bounded("\u200b", "jane") == []


def test_naive_index_reports_containing_haystacks():
    index = NaiveIndex(["jane doe", "janet", "/home/jane/x", "", "JANE"])
    assert index.containing("jane") == [0, 2, 4]
    assert index.containing("janet") == [1]
    assert index.containing("nobody") == []


def test_naive_index_with_no_haystacks():
    assert NaiveIndex([]).containing("jane") == []


# ── Property tests ────────────────────────────────────────────────────────────

# A small alphabet that exercises every rule: case, digits, separators, invisible chars,
# casefold expansion, Bengali letters + vowel sign, Devanagari, whitespace.
ALPHABET = [*"aAbBjJ01 _.-/", "ß", "\u200b", "ক", "\u09be", "ম", "क", "\u093c", "Ｊ"]
texts = st.text(alphabet=ALPHABET, max_size=14)
needles = st.text(alphabet=ALPHABET, min_size=1, max_size=5)


@given(needles)
def test_needle_is_bounded_inside_itself(needle):
    if canon(needle):
        assert contains_bounded(needle, needle)


@given(needles, texts, texts)
def test_needle_found_when_separated_by_spaces(needle, before, after):
    if canon(needle):
        assert contains_bounded(needle, f"{before} {needle} {after}")


@given(needles, texts)
def test_every_reported_span_matches_the_needle(needle, haystack):
    text = nfkc(haystack)
    for span in find_bounded(needle, haystack):
        assert canon(text[span.start : span.end]) == canon(needle)


@given(needles, texts)
def test_matches_naive_oracle(needle, haystack):
    """Independent brute force: try every substring of the NFKC text against the spec."""
    assert contains_bounded(needle, haystack) == _oracle(needle, haystack)


# ── Oracle: a deliberately simple, independent implementation of ADR-0026 ──────────────────

import unicodedata  # noqa: E402


def _oracle_class(ch: str) -> str:
    cat = unicodedata.category(ch)[0]
    return "L" if cat in "LM" else "N" if cat == "N" else "O"


def _oracle_side(edge: str, neighbour: str | None, left: bool) -> bool:
    if neighbour is None or _oracle_class(edge) == "O":
        return True
    if _oracle_class(neighbour) != _oracle_class(edge):
        return True
    if _oracle_class(edge) == "N":
        return False
    if unicodedata.name(neighbour, "?").split()[0] != unicodedata.name(edge, "?").split()[0]:
        return True
    lo, up = (neighbour, edge) if left else (edge, neighbour)
    return lo.islower() and up.isupper()


def _oracle(needle: str, haystack: str) -> bool:
    target = canon(needle)
    if not target:
        return False
    text = nfkc(haystack)
    for i in range(len(text)):
        for j in range(i + 1, len(text) + 1):
            sub = text[i:j]
            # A real match never starts or ends on an invisible or space character.
            if sub[0].isspace() or sub[-1].isspace() or sub[0] == "\u200b" or sub[-1] == "\u200b":
                continue
            if canon(sub) != target:
                continue
            left = text[i - 1] if i > 0 else None
            right = text[j] if j < len(text) else None
            if _oracle_side(sub[0], left, True) and _oracle_side(sub[-1], right, False):
                return True
    return False


@pytest.mark.parametrize(
    ("needle", "haystack"),
    [("jane", "janet"), ("2021", "20217"), ("ss", "ß"), ("s", "ß"), ("ক", "কম")],
)
def test_oracle_agrees_on_known_examples(needle, haystack):
    assert contains_bounded(needle, haystack) == _oracle(needle, haystack)
