"""The agent deny rules in .claude/settings.json keep the rules CLAUDE.md promises (P0.5, Q11, M2.2)."""

import json
from pathlib import Path

import pytest

SETTINGS = Path(__file__).resolve().parents[2] / ".claude" / "settings.json"


@pytest.fixture(scope="module")
def deny() -> list[str]:
    return json.loads(SETTINGS.read_text(encoding="utf-8"))["permissions"]["deny"]


@pytest.mark.parametrize(
    "rule",
    [
        # human-only or switching veil off (ADR-0018, ADR-0027)
        "Bash(*veil off*)", "Bash(*veil toggle*)", "Bash(*veil disable*)",
        "Bash(*veil reverse*)", "Bash(*veil persona edit*)", "Bash(*veil diff*)",
        "Bash(*veil vault review*)",
        # guess oracles (Q11)
        "Bash(*veil translate*)", "Bash(*veil audit*)",
        # the clipboard: restore puts real values there, sanitize is a guess oracle, and the
        # owner's clipboard holds real text (M2.2)
        "Bash(*veil clip*)", "Bash(*wl-paste*)", "Bash(*xsel*)", "Bash(*xclip*)",
        "Bash(*klipper*)", "Bash(*Klipper*)",
        # the key (ADR-0025)
        "Bash(*secret-tool*)", "Bash(*kwallet-query*)",
    ],
)  # fmt: skip
def test_rule_present(deny, rule):
    assert rule in deny


def test_no_duplicates(deny):
    assert len(deny) == len(set(deny))
