"""The agent guard keeps the rules veil promises (P0.5, Q11, M2.2).

Checks both the tracked template (`contrib/agent-guard/claude-settings.json`) and, when
present, the local `.claude/settings.json`. That file is git-ignored, so a CI checkout has none
and the local check skips there; anywhere else a missing file fails, so the rules can't silently
disappear.
"""

import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "contrib" / "agent-guard" / "claude-settings.json"
LOCAL = ROOT / ".claude" / "settings.json"


def _load_settings(which: str) -> dict[str, object]:
    if which == "template":
        return json.loads(TEMPLATE.read_text(encoding="utf-8"))
    if not LOCAL.exists():
        if os.environ.get("CI"):
            pytest.skip(".claude/settings.json is local-only (git-ignored); not in a CI checkout")
        pytest.fail(".claude/settings.json is missing: run `veil agent-guard install`")
    return json.loads(LOCAL.read_text(encoding="utf-8"))


@pytest.fixture(scope="module", params=["template", "local"])
def settings_data(request: pytest.FixtureRequest) -> dict[str, object]:
    return _load_settings(request.param)


@pytest.fixture(scope="module", params=["template", "local"])
def deny(request: pytest.FixtureRequest) -> list[str]:
    permissions = _load_settings(request.param)["permissions"]
    assert isinstance(permissions, dict)
    rules = permissions["deny"]
    assert isinstance(rules, list)
    return rules


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
def test_rule_present(deny: list[str], rule: str):
    assert rule in deny


def test_no_duplicates(deny: list[str]):
    assert len(deny) == len(set(deny))


def test_shell_commands_run_sandboxed_with_no_escape_hatch(settings_data: dict[str, object]):
    sandbox = settings_data["sandbox"]
    assert isinstance(sandbox, dict)
    assert sandbox["enabled"] is True
    assert sandbox["allowUnsandboxedCommands"] is False


def test_bypass_mode_is_disabled(settings_data: dict[str, object]):
    permissions = settings_data["permissions"]
    assert isinstance(permissions, dict)
    assert permissions["disableBypassPermissionsMode"] == "disable"
