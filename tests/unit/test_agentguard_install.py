"""Tests for `veil agent-guard install` and packaged claude-settings.json parity."""

import json
import stat
from pathlib import Path

import pytest

from veil import cli
from veil.agentguard import install as install_mod
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
    assert data["hooks"]["PreToolUse"][0]["matcher"] == ".*"
    assert data["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == install_mod._hook("pre")
    assert data["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == install_mod._hook("post")
    assert data["hooks"]["Stop"][0]["hooks"][0]["command"] == install_mod._hook("stop")


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
    assert install_mod._hook("pre") in pre_cmds


def test_install_warn_replaces_block_hook_without_duplicating(tmp_path, capsys):
    assert (
        cli.main(["agent-guard", "install", "--project", str(tmp_path), "--block"]) == ExitCode.OK
    )
    assert cli.main(["agent-guard", "install", "--project", str(tmp_path), "--warn"]) == ExitCode.OK
    capsys.readouterr()

    data = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    pre_cmds = [h["hooks"][0]["command"] for h in data["hooks"]["PreToolUse"]]
    assert pre_cmds == [install_mod._hook("pre --warn")]


def test_install_print_outputs_without_writing(tmp_path, capsys):
    code = cli.main(["agent-guard", "install", "--project", str(tmp_path), "--warn", "--print"])
    assert code == ExitCode.OK
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == install_mod._hook(
        "pre --warn"
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


def test_install_adds_session_start_hook_and_notice_blocks(tmp_path, capsys):
    code = cli.main(["agent-guard", "install", "--project", str(tmp_path)])
    assert code == ExitCode.OK
    capsys.readouterr()

    settings = json.loads((tmp_path / ".claude" / "settings.json").read_text(encoding="utf-8"))
    session_hooks = settings["hooks"]["SessionStart"]
    assert session_hooks[0]["hooks"][0]["command"] == install_mod._hook("session-start")

    for name in ("CLAUDE.md", "AGENTS.md"):
        doc = tmp_path / name
        assert doc.is_file()
        text = doc.read_text(encoding="utf-8")
        assert "<!-- veil:begin -->" in text
        assert "<!-- veil:end -->" in text
        inner = text.split("<!-- veil:begin -->", 1)[1].split("<!-- veil:end -->", 1)[0].strip()
        assert 1 <= len(inner.splitlines()) <= 8
        assert "pseudonym" in inner.lower()
        assert "tampering" in inner.lower()


def test_install_updates_marked_block_in_place_preserving_surrounding_text(tmp_path, capsys):
    claude_md = tmp_path / "CLAUDE.md"
    claude_md.write_text(
        "# Project Rules\n\nKeep tests green.\n\n"
        "<!-- veil:begin -->\nstale notice\n<!-- veil:end -->\n\n"
        "## Extra Section\nDo not erase me.\n",
        encoding="utf-8",
    )
    agents_md = tmp_path / "AGENTS.md"
    agents_md.write_text("# Agents\n\nFollow style.\n", encoding="utf-8")

    assert cli.main(["agent-guard", "install", "--project", str(tmp_path)]) == ExitCode.OK
    capsys.readouterr()

    updated_claude = claude_md.read_text(encoding="utf-8")
    assert updated_claude.count("<!-- veil:begin -->") == 1
    assert updated_claude.count("<!-- veil:end -->") == 1
    assert "stale notice" not in updated_claude
    assert updated_claude.startswith("# Project Rules\n\nKeep tests green.\n\n<!-- veil:begin -->")
    assert updated_claude.endswith("<!-- veil:end -->\n\n## Extra Section\nDo not erase me.\n")

    updated_agents = agents_md.read_text(encoding="utf-8")
    assert updated_agents.startswith("# Agents\n\nFollow style.\n")
    assert "<!-- veil:begin -->" in updated_agents
    assert "<!-- veil:end -->" in updated_agents


def test_install_print_does_not_write_notice_files(tmp_path, capsys):
    assert (
        cli.main(["agent-guard", "install", "--project", str(tmp_path), "--print"]) == ExitCode.OK
    )
    parsed = json.loads(capsys.readouterr().out)
    assert "SessionStart" in parsed["hooks"]
    assert not (tmp_path / "CLAUDE.md").exists()
    assert not (tmp_path / "AGENTS.md").exists()


def test_uninstall_removes_hooks_and_notice_blocks(tmp_path, capsys):
    # Fresh install -> uninstall removes veil hooks and veil-only markdown files
    assert cli.main(["agent-guard", "install", "--project", str(tmp_path)]) == ExitCode.OK
    capsys.readouterr()

    settings_path = tmp_path / ".claude" / "settings.json"
    data = json.loads(settings_path.read_text(encoding="utf-8"))
    data["customKeep"] = "yes"
    data["hooks"]["PreToolUse"].append(
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "custom-hook"}]}
    )
    settings_path.write_text(json.dumps(data), encoding="utf-8")

    assert cli.main(["agent-guard", "uninstall", "--project", str(tmp_path)]) == ExitCode.OK
    capsys.readouterr()

    after = json.loads(settings_path.read_text(encoding="utf-8"))
    assert after["customKeep"] == "yes"
    assert "SessionStart" not in after["hooks"]
    assert "PostToolUse" not in after["hooks"]
    assert "Stop" not in after["hooks"]
    assert [h["hooks"][0]["command"] for h in after["hooks"]["PreToolUse"]] == ["custom-hook"]
    assert not (tmp_path / "CLAUDE.md").exists()
    assert not (tmp_path / "AGENTS.md").exists()

    # Existing content in CLAUDE.md / AGENTS.md is preserved cleanly
    (tmp_path / "CLAUDE.md").write_text("# My Repo\n\nNotes here.\n", encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text("# Custom Agents\n", encoding="utf-8")
    assert cli.main(["agent-guard", "install", "--project", str(tmp_path)]) == ExitCode.OK
    assert cli.main(["agent-guard", "uninstall", "--project", str(tmp_path)]) == ExitCode.OK
    capsys.readouterr()

    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == "# My Repo\n\nNotes here.\n"
    assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8") == "# Custom Agents\n"


def test_uninstall_on_uninstalled_project_is_noop(tmp_path, capsys):
    assert cli.main(["agent-guard", "uninstall", "--project", str(tmp_path)]) == ExitCode.OK
    capsys.readouterr()
    assert not (tmp_path / ".claude").exists()


def test_pre_hook_that_cannot_start_blocks():
    """A missing interpreter exits 127, which Claude Code would treat as allow."""
    import subprocess

    command = install_mod._hook("pre", python="/nonexistent/python3")
    done = subprocess.run(["/bin/sh", "-c", command], input=b"{}", capture_output=True, check=False)
    assert done.returncode == 2


def test_hook_path_with_spaces_is_quoted():
    assert install_mod._hook("post", python="/opt/my py/python").startswith(
        "'/opt/my py/python' -m"
    )
