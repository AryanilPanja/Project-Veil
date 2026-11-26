"""Tests for `veil agent-guard install` and packaged claude-settings.json parity."""

import json
import stat
from pathlib import Path

import pytest

from veil import cli
from veil.exitcodes import ExitCode

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRIB_SETTINGS = REPO_ROOT / "contrib" / "agent-guard" / "claude-settings.json"
PACKAGE_SETTINGS = REPO_ROOT / "src" / "veil" / "agentguard" / "claude-settings.json"


def test_packaged_template_matches_contrib_identically():
    assert PACKAGE_SETTINGS.read_bytes() == CONTRIB_SETTINGS.read_bytes()


def test_install_fresh_project_creates_0600_settings_and_hooks(tmp_path, capsys):
    code = cli.main(["agent-guard", "install", "--project", str(tmp_path)])
    assert code == ExitCode.OK
    out = capsys.readouterr().out
    assert "installed" in out

    settings_path = tmp_path / ".claude" / "settings.json"
    assert settings_path.is_file()
    mode = stat.S_IMODE(settings_path.lstat().st_mode)
    assert mode == 0o600

    data = json.loads(settings_path.read_text(encoding="utf-8"))
    template = json.loads(CONTRIB_SETTINGS.read_text(encoding="utf-8"))
    assert data["permissions"]["disableBypassPermissionsMode"] == "disable"
    for rule in template["permissions"]["deny"]:
        assert rule in data["permissions"]["deny"]
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "veil agent-guard hook pre"
    assert data["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == "veil agent-guard hook post"
    assert data["hooks"]["Stop"][0]["hooks"][0]["command"] == "veil agent-guard hook stop"


def test_install_merges_existing_keys_and_unions_arrays(tmp_path, capsys):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir(mode=0o700)
    settings_path = claude_dir / "settings.json"
    existing = {
        "customTopKey": {"keep": True},
        "permissions": {
            "customPerm": "preserved",
            "deny": ["Bash(*veil off*)", "Bash(*custom-deny*)"],
            "ask": ["Bash(*custom-ask*)"],
        },
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [{"type": "command", "command": "my-custom-hook"}],
                }
            ]
        },
    }
    settings_path.write_text(json.dumps(existing), encoding="utf-8")
    settings_path.chmod(0o644)

    code = cli.main(["agent-guard", "install", "--project", str(tmp_path)])
    assert code == ExitCode.OK
    capsys.readouterr()

    assert stat.S_IMODE(settings_path.lstat().st_mode) == 0o600
    merged = json.loads(settings_path.read_text(encoding="utf-8"))
    assert merged["customTopKey"] == {"keep": True}
    assert merged["permissions"]["customPerm"] == "preserved"
    assert "Bash(*custom-deny*)" in merged["permissions"]["deny"]
    assert merged["permissions"]["deny"].count("Bash(*veil off*)") == 1
    assert "Bash(*custom-ask*)" in merged["permissions"]["ask"]

    pre_cmds = [h["hooks"][0]["command"] for h in merged["hooks"]["PreToolUse"]]
    assert "my-custom-hook" in pre_cmds
    assert "veil agent-guard hook pre" in pre_cmds


def test_install_warn_replaces_block_hook_without_duplicating(tmp_path, capsys):
    assert (
        cli.main(["agent-guard", "install", "--project", str(tmp_path), "--block"]) == ExitCode.OK
    )
    assert cli.main(["agent-guard", "install", "--project", str(tmp_path), "--warn"]) == ExitCode.OK
    capsys.readouterr()

    data = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    pre_cmds = [h["hooks"][0]["command"] for h in data["hooks"]["PreToolUse"]]
    assert pre_cmds == ["veil agent-guard hook pre --warn"]


def test_install_print_outputs_without_writing(tmp_path, capsys):
    code = cli.main(["agent-guard", "install", "--project", str(tmp_path), "--warn", "--print"])
    assert code == ExitCode.OK
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert (
        parsed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        == "veil agent-guard hook pre --warn"
    )
    assert not (tmp_path / ".claude").exists()


def test_install_refuses_symlink_settings(tmp_path):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir(mode=0o700)
    target = tmp_path / "other.json"
    target.write_text("{}", encoding="utf-8")
    (claude_dir / "settings.json").symlink_to(target)

    code = cli.main(["agent-guard", "install", "--project", str(tmp_path)])
    assert code == ExitCode.UNSAFE_ENVIRONMENT


@pytest.mark.parametrize("flag", ["--block", "--warn"])
def test_install_mode_flags_accepted(tmp_path, flag, capsys):
    assert (
        cli.main(["agent-guard", "install", "--project", str(tmp_path), flag, "--print"])
        == ExitCode.OK
    )
    capsys.readouterr()
