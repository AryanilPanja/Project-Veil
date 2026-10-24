"""persona/canary.py: format, randomness, insertion that preserves the user's file."""

import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.unit.test_check_cli import FIXTURE
from veil.errors import ValidationFailed
from veil.persona import canary
from veil.persona.check import check_bytes
from veil.persona.schema import parse_persona
from veil.persona.yamlio import load_yaml

C = "VEIL-CANARY-" + "A" * 26
D = "VEIL-CANARY-" + "B" * 26


class TestFormat:
    def test_generated_format(self):
        token = canary.generate()
        assert re.fullmatch(r"VEIL-CANARY-[A-Z2-7]{26}", token)
        assert canary.is_canary(token)

    def test_128_bits_are_used(self):
        # 26 base32 chars = 130 bits; the last char carries only 3 bits, so it is from [AEIMQUY4].
        lasts = {canary.generate()[-1] for _ in range(400)}
        assert lasts <= set("AEIMQUY4")
        assert len(lasts) > 4

    def test_unique(self):
        assert len({canary.generate() for _ in range(500)}) == 500

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "VEIL-CANARY-",
            "VEIL-CANARY-" + "A" * 25,
            "VEIL-CANARY-" + "A" * 27,
            "veil-canary-" + "a" * 26,
            "VEIL-CANARY-" + "1" * 26,  # 0, 1, 8, 9 are not base32
            " " + C,
            C + "\n",
        ],
    )
    def test_is_canary_rejects(self, text):
        assert not canary.is_canary(text)

    def test_find_all_in_running_text(self):
        assert canary.find_all(f"x {C} y\n{D}") == [C, D]

    def test_pattern_is_generic(self):
        # Hooks and the proxy look for any canary without knowing the key or the value.
        assert canary.PATTERN.search(f"leak: {canary.generate()}!")


class TestInsert:
    BASE = 'version: "1"\nperson:\n  first_name: { real: Jane, fake: Alex }\n'

    def test_inserted_after_version_and_as_trailing_comment(self):
        out = canary.insert(self.BASE, C)
        lines = out.splitlines()
        assert lines[0] == 'version: "1"'
        assert lines[1] == f'veil_canary: "{C}"'
        assert lines[-1] == f"# veil_canary: {C}"
        assert out.count(C) == 2

    def test_rest_of_file_preserved_byte_for_byte(self):
        out = canary.insert(self.BASE, C)
        removed = out.replace(f'veil_canary: "{C}"\n', "").replace(f"# veil_canary: {C}\n", "")
        assert removed == self.BASE

    def test_parses_into_schema_field(self):
        assert parse_persona(load_yaml(canary.insert(self.BASE, C))).veil_canary == C

    def test_comments_and_blank_lines_kept(self):
        text = "# my notes\n\nversion: 1   # schema\n\n# A. YOU\nperson: {}\n"
        out = canary.insert(text, C)
        assert out.startswith("# my notes\n\nversion: 1   # schema\n")
        assert "# A. YOU\n" in out

    def test_crlf_line_endings_kept(self):
        text = self.BASE.replace("\n", "\r\n")
        out = canary.insert(text, C)
        assert f'version: "1"\r\nveil_canary: "{C}"\r\n' in out
        assert out.endswith(f"# veil_canary: {C}\r\n")
        assert "\r\r" not in out
        assert "\n" not in out.replace("\r\n", "")

    def test_missing_final_newline(self):
        out = canary.insert(self.BASE.rstrip("\n"), C)
        assert out.endswith(f"\n# veil_canary: {C}\n")

    def test_bom_is_dropped(self):
        out = canary.insert("\N{ZERO WIDTH NO-BREAK SPACE}" + self.BASE, C)
        assert out.startswith('version: "1"\n')

    def test_existing_canary_lines_are_replaced_not_duplicated(self):
        once = canary.insert(self.BASE, C)
        twice = canary.insert(once, D)
        assert C not in twice
        assert twice.count(D) == 2
        assert twice == canary.insert(self.BASE, D)

    def test_hand_written_canary_key_is_replaced(self):
        text = self.BASE + 'veil_canary: "whatever"\n'
        out = canary.insert(text, C)
        assert "whatever" not in out
        assert check_bytes(out.encode()).errors == ()

    def test_indented_version_is_not_top_level(self):
        with pytest.raises(ValidationFailed, match="version"):
            canary.insert("person:\n  version: 1\n", C)

    @pytest.mark.parametrize("text", ["", "{version: 1}\n", "# version: 1\n", "person: {}\n"])
    def test_no_block_version_line(self, text):
        with pytest.raises(ValidationFailed):
            canary.insert(text, C)

    def test_invalid_canary_argument(self):
        with pytest.raises(ValueError, match="not a veil canary"):
            canary.insert(self.BASE, "VEIL-CANARY-short")

    def test_version_line_mentioned_later_in_a_value_is_ignored(self):
        text = 'version: "1"\nnever_translate: ["version: 2"]\n'
        out = canary.insert(text, C)
        assert out.splitlines()[1] == f'veil_canary: "{C}"'

    def test_synthetic_fixture_stays_valid(self):
        text = FIXTURE.read_text(encoding="utf-8")
        out = canary.insert(text, canary.generate())
        assert check_bytes(out.encode()).errors == ()

    def test_unicode_content_preserved(self):
        text = 'version: "1"\nperson:\n  first_name: { real: জেন, fake: অ্যালেক্স }\n'
        out = canary.insert(text, C)
        assert "জেন" in out
        assert "অ্যালেক্স" in out

    @given(
        st.text(
            alphabet=st.characters(blacklist_categories=["Cs"], blacklist_characters="\r"),
            max_size=200,
        )
    )
    def test_property_body_preserved(self, body):
        text = 'version: "1"\n' + body.replace("veil_canary", "x")
        out = canary.insert(text, C)
        assert out.count(C) >= 2
        restored = out.replace(f'veil_canary: "{C}"\n', "", 1)
        restored = restored.removesuffix(f"# veil_canary: {C}\n")
        if not text.endswith("\n"):
            restored = restored.removesuffix("\n")
        assert restored == text
