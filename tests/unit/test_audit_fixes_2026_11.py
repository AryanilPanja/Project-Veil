"""Regressions found in the 2026-11 audit (veil-macos)."""

from veil.engine import generate
from veil.text import normalize


class _Stream:
    def digit(self) -> str:
        return "5"


def test_digits_into_ignores_superscript_digits():
    assert generate._digits_into("98²7", "123") == "12²3"


def test_orcid_with_label_prefix_keeps_label():
    out = generate._orcid("ORCID: 0000-0001-2345-6789", _Stream())
    assert out.startswith("ORCID: 0000-000")
    assert len(out) == len("ORCID: 0000-0001-2345-6789")


def test_joiner_runs_between_ascii_letters_are_dropped():
    for hidden in ("Ja‍‍ne", "Ja‍︀ne", "Ja‌‍‌ne"):
        assert normalize.canon(hidden) == "jane", repr(hidden)


def test_joiner_inside_indic_text_is_kept():
    assert "‍" in normalize.canon("क्‍ष")


def test_long_joiner_run_is_bounded_and_folded():
    text = "a" + "‍" * 10_000 + "b"
    assert normalize.canon(text) == "ab"
