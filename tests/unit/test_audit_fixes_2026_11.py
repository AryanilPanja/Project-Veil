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


# ── sensitive terms in the text commands (ADR-0012) ───────────────────────────


def _engine():
    from tests.unit.test_matcher import FIXTURE, lexicon_from
    from veil.engine.matcher import Engine

    return Engine(lexicon_from(FIXTURE.read_text(encoding="utf-8")))


def test_translate_generalizes_sensitive_terms(tmp_path, capsys):
    from veil import textcmd

    src = tmp_path / "in.txt"
    src.write_text("Jane Doe has asthma.\n", encoding="utf-8")
    engine = _engine()
    assert textcmd.translate(lambda: engine, src) == 0
    out, err = capsys.readouterr()
    assert "asthma" not in out
    assert "a chronic condition" in out
    assert "asthma" not in err
    assert "generalized 1 sensitive term(s)" in err


def test_audit_reports_sensitive_terms_without_the_term(tmp_path, capsys):
    from veil import textcmd

    src = tmp_path / "in.txt"
    src.write_text("ok\nhas asthma\n", encoding="utf-8")
    engine = _engine()
    assert textcmd.audit(lambda: engine, src) == 1
    out = capsys.readouterr().out
    assert "asthma" not in out
    assert "2:5  " in out
    assert "(sensitive " in out


def test_parser_hides_value_in_ignored_explicit_argument(capsys):
    import pytest

    from veil import cli

    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["--version=JANEDOE"])
    assert "JANEDOE" not in capsys.readouterr().err
