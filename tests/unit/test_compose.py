"""engine/compose.py + lexicon.py + reference.py (M1.2): compound forms translate part by part.

Synthetic persona only (Jane Doe → Alex Smith). The reference translator is the oracle the
production matcher (M1.4) will be checked against.
"""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from veil.engine import compose
from veil.engine.lexicon import build_lexicon
from veil.engine.reference import forward, reverse
from veil.engine.variants import expand_all
from veil.errors import ValidationFailed
from veil.persona.entities import flatten
from veil.persona.schema import parse_persona
from veil.persona.yamlio import load_yaml
from veil.text.normalize import canon

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic_jane.yaml"


def persona_from(text: str):
    return flatten(parse_persona(load_yaml(text)))


@pytest.fixture(scope="module")
def flat():
    return persona_from(FIXTURE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def lex(flat):
    return build_lexicon(flat)


def both_ways(text: str, expected: str, lex) -> None:
    assert forward(text, lex) == expected
    assert reverse(expected, lex) == text


# ── per compound form (M1.2 DoD) ──────────────────────────────────────────────


class TestEmails:
    @pytest.mark.parametrize(
        ("real", "fake"),
        [
            ("jane.doe@xyz.example.test", "alex.smith@abc.example.test"),  # declared
            ("jane.doe@research.xyz.example.test", "alex.smith@research.abc.example.test"),
            ("jdoe@xyz.example.test", "asmith@abc.example.test"),  # derived local part
            ("JDoe@XYZ.example.test", "ASmith@ABC.example.test"),
            ("jane.doe04@gmail.example", "alex.smith04@gmail.example"),  # digits pass through
            ("janedoe2001@mail.example.test", "alexsmith2001@mail.example.test"),
            ("doe.jane@xyz.example.test", "smith.alex@abc.example.test"),
            ("<jane.doe@xyz.example.test>", "<alex.smith@abc.example.test>"),
            ("mailto:janed@xyz.example.test", "mailto:alexs@abc.example.test"),
        ],
    )
    def test_email_forms(self, real, fake, lex):
        both_ways(real, fake, lex)

    def test_unknown_local_part_keeps_domain_translated(self, lex):
        assert forward("hr@xyz.example.test", lex) == "hr@abc.example.test"

    def test_longest_domain_wins(self, lex):
        out = forward("research.xyz.example.test", lex)
        assert out == "research.abc.example.test"


class TestPaths:
    @pytest.mark.parametrize(
        ("real", "fake"),
        [
            ("/home/janed/notes.txt", "/home/alexs/notes.txt"),
            (
                "/home/janed/projects/jane-thesis/main.tex",
                "/home/alexs/projects/alex-thesis/main.tex",
            ),
            ("~/jane-thesis/", "~/alex-thesis/"),
            ("C:\\Users\\janed\\Desktop", "C:\\Users\\alexs\\Desktop"),
            ("/srv/vision_lab/data", "/srv/signal_grp/data"),
            ("/home/janed/Jane_Doe_CV.pdf", "/home/alexs/Alex_Smith_CV.pdf"),
        ],
    )
    def test_path_segments(self, real, fake, lex):
        both_ways(real, fake, lex)


class TestUrlsAndHandles:
    @pytest.mark.parametrize(
        ("real", "fake"),
        [
            (
                "https://github.com/jane-doe-dev/jane-thesis",
                "https://github.com/alex-smith-dev/alex-thesis",
            ),
            ("https://janedoe.example.test/blog", "https://alexsmith.example.test/blog"),
            ("linkedin.com/in/jane-doe-01", "linkedin.com/in/alex-smith-01"),
            ("@janed please review", "@alexs please review"),
            ("git@github.com:jane-doe-dev/x.git", "git@github.com:alex-smith-dev/x.git"),
            ("https://xyz.example.test/~janed/", "https://abc.example.test/~alexs/"),
        ],
    )
    def test_url_and_handle_forms(self, real, fake, lex):
        both_ways(real, fake, lex)


class TestUpi:
    @pytest.mark.parametrize(
        ("real", "fake"),
        [
            ("janed@bank", "alexs@bank"),  # declared
            ("jdoe@okaxis", "asmith@okaxis"),  # derived local part, bank suffix kept
            ("doej@ybl", "smitha@ybl"),
        ],
    )
    def test_upi(self, real, fake, lex):
        both_ways(real, fake, lex)


# ── derivations ───────────────────────────────────────────────────────────────


class TestDerivations:
    def derived(self, flat):
        declared = expand_all(flat)
        return {
            canon(v.real): canon(v.fake)
            for e in compose.derived_entities(flat, declared)
            for v in e.variants
        }

    def test_owner_wins_over_family_with_same_initials(self, flat):
        derived = self.derived(flat)
        # Jane, John and Joan Doe all derive "jdoe"; the owner's mapping is kept.
        assert derived["jdoe"] == "asmith"
        assert "ssmith" not in derived.values()  # John's would-be fake is dropped
        assert "ksmith" not in derived.values()  # Joan's too

    def test_declared_forms_are_not_re_derived(self, flat):
        derived = self.derived(flat)
        assert "janed" not in derived  # linux_user declares it
        assert "jane.doe" not in derived  # cluster username declares it

    def test_other_people_get_derivations(self, flat):
        derived = self.derived(flat)
        assert derived["rkumar"] == "oprakash"
        assert derived["kumarr"] == "prakasho"
        assert "kumarravi" not in derived  # spells out "Om" (2 letters)

    def test_titles_and_initials_are_skipped(self, flat):
        derived = self.derived(flat)
        assert derived.get("mmajor", "aminor") == "aminor"  # declared already; never "pmajor"
        assert not any(k.startswith("p") and "major" in k for k in derived)

    def test_short_fake_part_blocks_shapes_spelling_it(self, flat):
        derived = self.derived(flat)
        assert "ravik" not in derived  # Ravi → "Om": 2 letters, too short to spell out
        assert "rkumar" in derived  # the surname is long enough on both sides

    def test_minimum_length(self):
        flat = persona_from(
            'version: "1"\nperson:\n'
            "  first_name: { real: Li, fake: Wu, allow_short: true }\n"
            "  last_name: { real: Ng, fake: Ho, allow_short: true }\n"
        )
        assert compose.derived_entities(flat, expand_all(flat)) == []

    def test_two_other_people_deriving_differently_are_both_dropped(self):
        flat = persona_from(
            'version: "1"\npeople:\n'
            "  - { real: Ravi Kumar, fake: Omar Prakash, relation: friend }\n"
            "  - { real: Rita Kumar, fake: Uma Prakash, relation: friend }\n"
        )
        derived = {
            canon(v.real)
            for e in compose.derived_entities(flat, expand_all(flat))
            for v in e.variants
        }
        assert "rkumar" not in derived
        assert "kumarravi" in derived  # unambiguous derivations survive

    def test_derived_form_colliding_with_a_declared_fake_is_dropped(self):
        flat = persona_from(
            'version: "1"\nperson:\n'
            "  first_name: { real: Jane, fake: Alex }\n"
            "  last_name: { real: Doe, fake: Smith, allow_short: true }\n"
            "handles:\n  github: { real: someone-else, fake: asmith }\n"
        )
        derived = {
            canon(v.real)
            for e in compose.derived_entities(flat, expand_all(flat))
            for v in e.variants
        }
        assert "jdoe" not in derived

    def test_pascal_spellings(self, lex):
        both_ways("JDoe DoeJane JaneD DoeJ", "ASmith SmithAlex AlexS SmithA", lex)

    def test_derived_entities_are_marked(self, flat):
        for e in compose.derived_entities(flat, expand_all(flat)):
            assert e.entity.id.startswith("derived:")
            assert e.entity.meta_value("derived") == "true"
            assert "Jane" not in repr(e)


# ── lexicon ───────────────────────────────────────────────────────────────────


class TestLexicon:
    def test_fails_closed_on_expanded_bijection_errors(self):
        flat = persona_from(
            'version: "1"\nperson:\n  full_name: { real: Jane Doe, fake: Alex Smith }\n'
            "handles:\n  kaggle: { real: jd-kaggle, fake: alexsmith }\n"
        )
        with pytest.raises(ValidationFailed, match="veil persona check") as info:
            build_lexicon(flat)
        assert "Jane" not in str(info.value)

    def test_reverse_skips_one_way_entities(self):
        flat = persona_from(
            'version: "1"\nfootprint:\n'
            "  thesis_title: { real: Deep Readers of Old Scripts, fake: a thesis on OCR }\n"
        )
        lex = build_lexicon(flat)
        assert len(lex.forward) == 1
        assert lex.reverse == ()

    def test_repr_is_value_free(self, lex):
        assert "Jane" not in repr(lex)
        assert "Jane" not in repr(lex.forward[0])


# ── reference translator semantics ────────────────────────────────────────────


class TestReference:
    def test_leftmost_longest(self, lex):
        assert forward("Jane Doe", lex) == "Alex Smith"  # not "Alex Smith" via Jane + Doe pieces
        assert forward("Jane Doe's", lex) == "Alex Smith's"

    def test_boundaries(self, lex):
        assert forward("Janet", lex) == "Janet"
        assert forward("jane04", lex) == "alex04"
        assert forward("janeResume", lex) == "alexResume"

    def test_context_guard(self, lex):
        assert forward("ssh orion", lex) == "ssh kepler"
        assert forward("Orion is a constellation", lex) == "Orion is a constellation"

    def test_never_translate(self):
        flat = persona_from(
            'version: "1"\nperson:\n  first_name: { real: Ruby, fake: Opal }\n'
            "never_translate: [Ruby]\n"
        )
        lex = build_lexicon(flat)
        assert forward("Ruby wrote Ruby code", lex) == "Ruby wrote Ruby code"

    def test_never_reverse(self):
        flat = persona_from(
            'version: "1"\nperson:\n  first_name: { real: Jane, fake: Alex }\n'
            "never_reverse: [Alex]\n"
        )
        lex = build_lexicon(flat)
        assert forward("Jane", lex) == "Alex"
        assert reverse("Alex", lex) == "Alex"

    def test_unicode_scripts(self, lex):
        assert forward("জেন লিখেছে", lex) == "অ্যালেক্স লিখেছে"
        assert forward("जेन ने लिखा", lex) == "एलेक्स ने लिखा"

    def test_text_without_forms_is_unchanged(self, lex):
        text = "nothing personal here: 42 apples, /tmp/x, https://example.org"
        assert forward(text, lex) == text


FILLER = st.sampled_from(["the", "quick", "report", "42", "/srv/x", "and", "zq", "notes.txt", "ok"])
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
        "janedoe2001@mail.example.test",
    ]
)
SEPARATORS = st.sampled_from([" ", "\n", ", ", " (", ") ", ": "])


@settings(max_examples=150)
@given(st.lists(st.tuples(st.one_of(FILLER, REAL_BITS), SEPARATORS), max_size=12))
def test_property_round_trip_without_fake_forms(lex, parts):
    """spec §5.5: reverse(forward(x)) == x for text that contains no fake forms."""
    text = "".join(a + b for a, b in parts)
    assert reverse(forward(text, lex), lex) == text
