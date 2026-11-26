"""The agent guard (contrib/agent-guard/claude-settings.json) keeps the rules veil promises.

The template is tracked so a fresh clone and CI test the same rules; `.claude/` stays
git-ignored and holds the installed copy (P0.5, Q11, M2.2).
"""

import json
from pathlib import Path

import pytest

SETTINGS = Path(__file__).resolve().parents[2] / "contrib" / "agent-guard" / "claude-settings.json"


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
        # veil ON / the copy watcher (ADR-0031; sweep 2026-10-26: stopping the service or
        # killing wl-paste was an unguarded way to switch veil OFF)
        "Bash(*veil on*)", "Bash(*veil-watch*)", "Bash(*kill-switch-timer*)",
        "Bash(*pkill*)", "Bash(*killall*)",
        # tools that type into the owner's windows
        "Bash(*paste_spike*)",
        # macOS: the clipboard, the Keychain item, AppleScript and the LaunchAgent
        "Bash(*pbpaste*)", "Bash(*pbcopy*)", "Bash(*osascript*)",
        "Bash(*security find-generic-password*)", "Bash(*security dump-keychain*)",
        "Bash(*launchctl*veil*)",
        # the key and persona files themselves
        "Read(~/Library/Keychains/**)", "Read(~/.config/veil/**)",
        "Read(~/Library/Application Support/veil/**)", "Read(**/*.age)",
    ],
)  # fmt: skip
def test_rule_present(deny, rule):
    assert rule in deny


def test_no_duplicates(deny):
    assert len(deny) == len(set(deny))


def test_shell_commands_run_sandboxed_with_no_escape_hatch():
    sandbox = json.loads(SETTINGS.read_text(encoding="utf-8"))["sandbox"]
    assert sandbox["enabled"] is True
    assert sandbox["allowUnsandboxedCommands"] is False


def test_bypass_mode_is_disabled():
    permissions = json.loads(SETTINGS.read_text(encoding="utf-8"))["permissions"]
    assert permissions["disableBypassPermissionsMode"] == "disable"
