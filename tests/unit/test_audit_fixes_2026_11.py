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


def test_fill_skips_variant_colliding_with_another_real():
    from tests.unit.test_matcher import FIXTURE
    from veil.engine.fill import fill_generated
    from veil.engine.lexicon import build_lexicon
    from veil.engine.variants import expand_all, validate_expanded
    from veil.engine.vault import Vault
    from veil.persona.check import check_bytes
    from veil.persona.entities import flatten
    from veil.persona.schema import parse_persona
    from veil.persona.yamlio import load_yaml

    base = FIXTURE.read_text(encoding="utf-8")
    target = '  - { real: "+91 90000 00001", fake: "", policy: FPE }'
    second = '  - { real: "9000000001", fake: "", policy: FPE }'
    for pair in (f"{target}\n{second}", f"{second}\n{target}"):
        text = base.replace(target, pair)
        assert check_bytes(text.encode("utf-8")).errors == ()
        flat = flatten(parse_persona(load_yaml(text)))
        filled = fill_generated(flat, Vault(seed=b"s" * 32))
        assert validate_expanded(expand_all(filled)) == []
        build_lexicon(filled)


def test_derived_filter_rejects_cross_collision_between_real_and_fake():
    from tests.unit.test_matcher import FIXTURE, lexicon_from
    from veil.engine.compose import derived_entities
    from veil.engine.matcher import Engine
    from veil.engine.variants import expand_all, validate_expanded
    from veil.persona.entities import flatten
    from veil.persona.schema import parse_persona
    from veil.persona.yamlio import load_yaml

    text = (
        FIXTURE.read_text(encoding="utf-8")
        .replace("real: janed", "real: juser")
        .replace("fake: alexs", "fake: auser")
        .replace("/home/janed", "/home/juser")
        .replace("/home/alexs", "/home/auser")
        .replace(
            "  - { real: Ravi Kumar, fake: Om Prakash, relation: friend }",
            "  - { real: Ravi Kumar, fake: Om Prakash, relation: friend }\n"
            "  - { real: Alan Lexs, fake: Bob Jones, relation: friend }",
        )
    )
    flat = flatten(parse_persona(load_yaml(text)))
    declared = expand_all(flat)
    derived = derived_entities(flat, declared)
    assert validate_expanded([*declared, *derived]) == []

    engine = Engine(lexicon_from(text))
    assert engine.forward("janed") == "alexs"
    assert engine.reverse("alexs") == "janed"
    assert engine.forward("alexs") == "alexs"


def test_academic_year_fails_closed_when_institution_kept_and_degree_disabled():
    from tests.unit.test_matcher import FIXTURE, lexicon_from
    from veil.engine.matcher import Engine

    base = FIXTURE.read_text(encoding="utf-8")
    for aliases_line in (
        "    aliases:     { real: [XYZIT, XYZ-IT], fake: [] }",
        "    aliases:     { real: [XYZIT, XYZ-IT], fake: [ABCU, ABC-U] }",
    ):
        text = (
            base.replace(
                "  - institution: { real: XYZ Institute of Technology, fake: ABC University }",
                "  - institution: { real: XYZ Institute of Technology, policy: KEEP }",
            )
            .replace("    aliases:     { real: [XYZIT, XYZ-IT], fake: [ABCU, ABC-U] }", aliases_line)
            .replace("    degree:\n      enabled: true", "    degree:\n      enabled: false")
        )
        engine = Engine(lexicon_from(text))
        assert engine.forward("I am an MS student in 2nd year.") == "I am an MS student in 2nd year."
        assert (
            engine.forward("2nd year at XYZ Institute of Technology")
            == "2nd year at XYZ Institute of Technology"
        )
        assert engine.reverse("Her 3rd year was elsewhere.") == "Her 3rd year was elsewhere."



