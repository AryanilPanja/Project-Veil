"""Tests for `veil agent-guard hook {pre,post,stop}` and hook latency."""

import hashlib
import io
import json
import os
import shutil
import stat
import statistics
import subprocess
import sys
import time
from pathlib import Path

import pytest

from veil import cli
from veil.agentguard import hook
from veil.exitcodes import ExitCode

REPO_ROOT = Path(__file__).resolve().parents[2]


def _run_hook(monkeypatch, argv: list[str], payload: dict) -> int:
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(payload)))
    return cli.main(argv)


def _init_git_repo(repo: Path) -> str:
    git_bin = shutil.which("git") or "git"
    subprocess.run([git_bin, "init", "-q"], cwd=repo, check=True)
    subprocess.run([git_bin, "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run([git_bin, "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / "src").mkdir(exist_ok=True)
    (repo / "tests").mkdir(exist_ok=True)
    (repo / "src" / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (repo / "tests" / "test_app.py").write_text(
        "from src.app import add\n\ndef test_add():\n    assert add(1, 2) == 3\n",
        encoding="utf-8",
    )
    subprocess.run([git_bin, "add", "."], cwd=repo, check=True)
    subprocess.run([git_bin, "commit", "-q", "-m", "init"], cwd=repo, check=True)
    proc = subprocess.run(
        [git_bin, "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=True
    )
    return proc.stdout.strip()


@pytest.mark.parametrize(
    ("tool_name", "path_key", "rel_path"),
    [
        ("Edit", "file_path", "tests/test_app.py"),
        ("Write", "file_path", "src/test_helper.py"),
        ("Edit", "file_path", "src/helper_test.py"),
        ("Write", "file_path", "web/app.spec.ts"),
        ("Edit", "file_path", "conftest.py"),
        ("Write", "file_path", ".github/workflows/ci.yml"),
        ("Edit", "file_path", "uv.lock"),
        ("Edit", "file_path", "pyproject.toml"),
        ("Write", "file_path", ".claude/settings.json"),
        ("Edit", "file_path", ".claude/settings.local.json"),
        ("Edit", "file_path", "contrib/agent-guard/claude-settings.json"),
        ("Write", "file_path", ".pre-commit-config.yaml"),
        ("Write", "file_path", ".git/hooks/pre-commit"),
        ("Edit", "file_path", ".veil-agent-guard.toml"),
        ("NotebookEdit", "notebook_path", "tests/eval_nb.ipynb"),
    ],
)
def test_hook_pre_blocks_protected_file_tools(
    monkeypatch, tmp_path, capsys, tool_name, path_key, rel_path
):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {
        "session_id": "sess-1",
        "tool_name": tool_name,
        "tool_input": {path_key: str(tmp_path / rel_path)},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == 2
    captured = capsys.readouterr()
    out_json = json.loads(captured.out)
    assert out_json["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out_json["hookSpecificOutput"]["permissionDecision"] == "deny"
    reason = out_json["hookSpecificOutput"]["permissionDecisionReason"]
    assert reason.startswith("veil agent-guard: ")
    assert reason in captured.err


def test_hook_pre_warn_returns_ask_and_exit_0(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {
        "session_id": "sess-warn",
        "tool_name": "Edit",
        "tool_input": {"file_path": str(tmp_path / "tests" / "test_x.py")},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre", "--warn"], payload)
    assert code == ExitCode.OK
    captured = capsys.readouterr()
    out_json = json.loads(captured.out)
    assert out_json["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "veil agent-guard:" in out_json["hookSpecificOutput"]["permissionDecisionReason"]
    assert captured.err == ""


def test_hook_pre_allows_normal_source_edit(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {
        "session_id": "sess-ok",
        "tool_name": "Edit",
        "tool_input": {"file_path": str(tmp_path / "src" / "app.py")},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == ExitCode.OK
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def _assert_deny_json(capsys) -> str:
    captured = capsys.readouterr()
    out_json = json.loads(captured.out)
    assert out_json["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert out_json["hookSpecificOutput"]["permissionDecision"] == "deny"
    reason = out_json["hookSpecificOutput"]["permissionDecisionReason"]
    assert reason.startswith("veil agent-guard: ")
    return reason


@pytest.mark.parametrize(
    "raw_stdin",
    [
        "",
        "   \n\t",
        "{invalid json",
        "[]",
        "[1, 2, 3]",
        '"just a string"',
        "42",
        "null",
        "true",
    ],
)
def test_hook_pre_denies_with_json_on_bad_stdin(monkeypatch, tmp_path, capsys, raw_stdin):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(sys, "stdin", io.StringIO(raw_stdin))
    code = cli.main(["agent-guard", "hook", "pre"])
    assert code == 2
    _assert_deny_json(capsys)


@pytest.mark.parametrize(
    "tool_input",
    [
        None,
        "string",
        123,
        ["tests/test_app.py"],
    ],
)
def test_hook_pre_denies_non_object_tool_input(monkeypatch, tmp_path, capsys, tool_input):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {"session_id": "sess-bad", "tool_name": "Edit", "cwd": str(tmp_path)}
    if tool_input is not None:
        payload["tool_input"] = tool_input
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == 2
    _assert_deny_json(capsys)


def test_hook_pre_denies_nul_byte_in_file_path(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {
        "session_id": "sess-nul",
        "tool_name": "Edit",
        "tool_input": {"file_path": str(tmp_path / "src" / "app.py\x00")},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == 2
    _assert_deny_json(capsys)


def test_hook_pre_fails_closed_on_unexpected_exception(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

    def boom(_payload):
        raise RuntimeError("secret-persona-value-should-not-leak")

    monkeypatch.setattr(hook, "evaluate_pre", boom)
    payload = {
        "session_id": "sess-exc",
        "tool_name": "Edit",
        "tool_input": {"file_path": "src/app.py"},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == 2
    reason = _assert_deny_json(capsys)
    assert "secret-persona-value-should-not-leak" not in reason


@pytest.mark.parametrize(
    "tool_name",
    ["Read", "Glob", "Grep", "LS", "WebSearch", "WebFetch", "TodoWrite", "Task", "Agent"],
)
def test_hook_pre_allows_readonly_tools_on_repo_and_tests(monkeypatch, tmp_path, capsys, tool_name):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {
        "session_id": "sess-ro",
        "tool_name": tool_name,
        "tool_input": {"file_path": str(tmp_path / "tests" / "test_app.py"), "path": "tests"},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == ExitCode.OK
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("field", "target"),
    [
        ("file_path", "tests/test_app.py"),
        ("path", "pyproject.toml"),
        ("notebook_path", "tests/nb.ipynb"),
        ("destination", ".github/workflows/ci.yml"),
        ("target", "uv.lock"),
    ],
)
def test_hook_pre_checks_path_fields_on_unknown_tools(monkeypatch, tmp_path, capsys, field, target):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {
        "session_id": "sess-unk",
        "tool_name": "CustomMcpFileTool",
        "tool_input": {field: target},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == 2
    _assert_deny_json(capsys)


def test_hook_pre_allows_unknown_tool_without_protected_paths(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {
        "session_id": "sess-unk-ok",
        "tool_name": "CustomMcpFileTool",
        "tool_input": {"destination": "src/app.py", "query": "hello"},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == ExitCode.OK
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "command",
    [
        "sed -i 's/1/2/' tests/test_app.py",
        "perl -pi -e 's/1/2/' pyproject.toml",
        "echo hacked | tee tests/conftest.py",
        "echo x > tests/test_app.py",
        "echo x >> uv.lock",
        "rm tests/test_app.py",
        "rm -rf tests",
        "mv tests/test_app.py /tmp/moved.py",
        "cp fake.py tests/test_app.py",
        "git rm tests/test_app.py",
        "git checkout -- tests/test_app.py",
        "truncate -s 0 pyproject.toml",
        "git commit --no-verify -m 'bypass'",
        "git push --force origin main",
        "git reset --hard HEAD~1",
        "rm -rf /tmp/outside-dir",
        "rm -rf ../escape-cwd",
        "pytest --deselect tests/test_app.py::test_add",
        # Bug 3: newline / CR / comment-newline separators
        "echo hi\nrm tests/test_app.py",
        "echo hi\rrm tests/test_app.py",
        "echo hi\r\nrm tests/test_app.py",
        "echo hi # comment\nrm tests/test_app.py",
        'echo "unclosed\nrm tests/test_app.py',
        # Bug 4: wrappers, short-flag -c, command substitution, $VAR, globs, cd
        "env -u FOO rm tests/test_app.py",
        "env -i PATH=/usr/bin FOO=1 rm tests/test_app.py",
        'env -S "rm tests/test_app.py"',
        "nice -n 5 rm tests/test_app.py",
        "nice -5 rm tests/test_app.py",
        "timeout 5 rm tests/test_app.py",
        "timeout -s KILL 5 rm tests/test_app.py",
        "nohup rm tests/test_app.py",
        "xargs rm",
        "xargs -I{} rm {}",
        "command rm tests/test_app.py",
        "exec rm tests/test_app.py",
        "sudo -u root rm tests/test_app.py",
        "time rm tests/test_app.py",
        "stdbuf -o0 rm tests/test_app.py",
        "stdbuf -o L rm tests/test_app.py",
        "bash -ec 'rm tests/test_app.py'",
        "sh -xec 'rm tests/test_app.py'",
        "zsh -lc 'rm tests/test_app.py'",
        "dash -ce 'rm tests/test_app.py'",
        "echo $(rm tests/test_app.py)",
        'echo "$(rm tests/test_app.py)"',
        "echo `rm tests/test_app.py`",
        'echo "`rm tests/test_app.py`"',
        "T=tests; rm $T/a.py",
        "rm ${T}/a.py",
        "rm t*s/a.py",
        "cd tests && rm helpers.py",
        "cd tests && echo x > a.py",
        "cd tests; sed -i 's/1/2/' a.py",
        "mv $T/a.py /tmp/x",
        "truncate -s 0 t*s/a.py",
        "echo x > $OUT",
        "echo x > t*s/a.py",
        # Bug 5: unlisted writers & inline interpreters
        "find tests -delete",
        "find . -delete",
        "find -delete",
        "find tests -exec rm {} +",
        "find tests -execdir rm -f {} ;",
        "dd if=/dev/zero of=tests/a.py",
        "dd of=pyproject.toml",
        "ln -sf /dev/null tests/a.py",
        "ln -f fake.py tests/a.py",
        "ln -s /dev/null tests/a.py",
        "truncate -s0 tests/a.py",
        "python -c \"open('tests/a.py','w')\"",
        "python3 -c \"import pathlib; pathlib.Path('pyproject.toml').unlink()\"",
        "node -e \"require('fs').writeFileSync('tests/a.py', '')\"",
        "perl -e \"unlink 'tests/a.py'\"",
        "ruby -e \"File.delete('tests/a.py')\"",
        # Bug 6: veil commands, clipboard, keychains, quote stripping
        "pbpaste",
        "pbcopy",
        "p''bpaste",
        '"pb"paste',
        "osascript -e 'the clipboard'",
        "wl-paste",
        "wl-copy",
        "xclip -o",
        "xsel -ob",
        "security find-generic-password -s veil",
        "security find-internet-password -s example",
        "security dump-keychain",
        "security export -k login.keychain",
        "security delete-generic-password -s veil",
        "security unlock-keychain",
        'security "find-generic-password" -s veil',
        "secret-tool lookup service veil",
        "kwallet-query kdewallet -r veil",
        "veil off",
        "veil toggle",
        "veil disable",
        "veil reverse",
        "veil persona edit",
        "veil vault review",
        "veil diff",
        "veil translate",
        "veil audit",
        "veil clip sanitize",
        "veil on",
        '"v"eil "o"ff',
        "launchctl stop io.github.veil.watch",
        "launchctl unload ~/Library/LaunchAgents/veil.plist",
        "systemctl --user stop veil-watch",
        # Bug 6: veil secret paths via Bash read/write
        "cat ~/.config/veil/persona.yaml",
        "cat ~/Library/Application\\ Support/veil/key.age",
        "cat $XDG_CONFIG_HOME/veil/store.age",
        "cat secrets/persona.yaml",
        "head keys/vault.age",
        "cat config/matrix-slots.txt",
        "cat ~/Library/Keychains/login.keychain-db",
        "cat ~/.ssh/id_rsa",
        "cat ~/.gnupg/secring.gpg",
        # Bug 7: guard and trail writes via Bash
        "rm ~/.claude/settings.json",
        "echo {} > ~/.claude/settings.local.json",
        "sed -i 's/a/b/' src/veil/agentguard/hook.py",
        "echo x > .git/config",
        "rm .git/hooks/pre-commit",
        # Bug 9: destructive git
        "git checkout -- .",
        "git checkout .",
        "git restore .",
        "git restore -- .",
        "git restore -SW .",
        "git clean -f",
        "git clean -fd",
        "git clean -fx",
        "git clean --force",
        "git push -uf origin main",
        "git push --force-with-lease origin main",
        "git push --force-if-includes",
        "git push origin +main",
        "git push origin +HEAD:main",
        "rm -rf *",
        "rm -rf .",
    ],
)
def test_hook_pre_blocks_dangerous_bash(monkeypatch, tmp_path, capsys, command):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    (tmp_path / "tests").mkdir(exist_ok=True)
    payload = {
        "session_id": "sess-bash",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == 2
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert data["hookSpecificOutput"]["permissionDecisionReason"] in captured.err


@pytest.mark.parametrize(
    "command",
    [
        "pytest tests/test_app.py",
        'uv run python -m pytest -k "test_add"',
        "cat tests/test_app.py",
        "git diff tests/test_app.py",
        "rm -rf build/",
        "echo ok > /dev/null",
        "cd tests && pytest",
        "ls tests/*.py",
        "git checkout main",
        "git checkout -b feature/x",
        "git clean -n",
        "git push origin main",
        "veil status",
        "veil agent-guard review",
        "find tests -name '*.py'",
        "pytest -p no:cov",
        "uv run python -m pytest -q -p no:testmon tests/test_app.py",
        'pytest -k "not slow"',
        'uv run python -m pytest -k "not slow"',
    ],
)
def test_hook_pre_allows_safe_bash(monkeypatch, tmp_path, capsys, command):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {
        "session_id": "sess-bash-ok",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == ExitCode.OK
    captured = capsys.readouterr()
    assert captured.out == ""


def test_hook_pre_blocks_pytest_k_excluding_removed_test(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    # Remove test_add from tests/test_app.py
    (repo / "tests" / "test_app.py").write_text(
        "from src.app import add\n\ndef test_other():\n    assert add(0, 0) == 0\n",
        encoding="utf-8",
    )
    payload = {
        "session_id": "sess-pytest-k",
        "tool_name": "Bash",
        "tool_input": {"command": 'pytest -k "not test_add"'},
        "cwd": str(repo),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == 2
    _assert_deny_json(capsys)


@pytest.mark.parametrize("tool_name", ["Read", "Glob", "Grep", "Edit", "Write"])
@pytest.mark.parametrize(
    "secret_path",
    [
        "~/.config/veil/store.age",
        "~/Library/Application Support/veil/keys.age",
        "persona.yaml",
        "nested/dir/persona.yaml",
        "vault/key.age",
        "matrix-slots.txt",
        "~/Library/Keychains/login.keychain-db",
        "~/.ssh/id_ed25519",
        "~/.gnupg/private-keys-v1.d/key",
    ],
)
def test_hook_pre_blocks_veil_secrets_read_and_write(
    monkeypatch, tmp_path, capsys, tool_name, secret_path
):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {
        "session_id": "sess-sec",
        "tool_name": tool_name,
        "tool_input": {"file_path": secret_path, "path": secret_path},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == 2
    _assert_deny_json(capsys)


def test_hook_pre_blocks_xdg_config_home_veil_secret(monkeypatch, tmp_path, capsys):
    xdg_cfg = tmp_path / "xdg-cfg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_cfg))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {
        "session_id": "sess-xdg",
        "tool_name": "Read",
        "tool_input": {"file_path": str(xdg_cfg / "veil" / "store.bin")},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == 2
    _assert_deny_json(capsys)


@pytest.mark.parametrize(
    "guard_path",
    [
        ".claude/settings.json",
        ".claude/settings.local.json",
        "~/.claude/settings.json",
        "~/.claude/settings.local.json",
        "src/veil/agentguard/hook.py",
        "src/veil/agentguard/install.py",
        "~/Library/Logs/veil/agent-log.jsonl",
        ".git/config",
        ".git/hooks/post-commit",
    ],
)
def test_hook_pre_blocks_guard_and_trail_writes(monkeypatch, tmp_path, capsys, guard_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    payload = {
        "session_id": "sess-guard-write",
        "tool_name": "Write",
        "tool_input": {"file_path": guard_path},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
    assert code == 2
    _assert_deny_json(capsys)


def test_hook_pre_blocks_state_dir_writes(monkeypatch, tmp_path, capsys):
    state_home = tmp_path / "custom-state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))
    for target in (
        state_home / "veil" / "agent-log.jsonl",
        state_home / "veil" / "sessions" / "abc.json",
    ):
        payload = {
            "session_id": "sess-state-write",
            "tool_name": "Edit",
            "tool_input": {"file_path": str(target)},
            "cwd": str(tmp_path),
        }
        code = _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], payload)
        assert code == 2
        _assert_deny_json(capsys)


def test_hook_pre_respects_toml_protected_and_allow(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    (tmp_path / ".veil-agent-guard.toml").write_text(
        'protected = ["evals/**"]\nallow = ["tests/fixtures/**"]\n',
        encoding="utf-8",
    )

    blocked = {
        "session_id": "s-cfg",
        "tool_name": "Write",
        "tool_input": {"file_path": str(tmp_path / "evals" / "score.py")},
        "cwd": str(tmp_path),
    }
    assert _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], blocked) == 2
    capsys.readouterr()

    allowed = {
        "session_id": "s-cfg",
        "tool_name": "Write",
        "tool_input": {"file_path": str(tmp_path / "tests" / "fixtures" / "sample.json")},
        "cwd": str(tmp_path),
    }
    assert _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], allowed) == ExitCode.OK


def test_hook_post_logs_metadata_0600_without_contents(monkeypatch, tmp_path):
    state_home = tmp_path / "xdg-state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state_home))

    target = tmp_path / "src_mod.py"
    secret_body = "TOP_SECRET_FILE_CONTENT_DO_NOT_LOG\n"
    target.write_text(secret_body, encoding="utf-8")

    payload = {
        "session_id": "sess-post",
        "tool_name": "Write",
        "tool_input": {"file_path": str(target), "content": secret_body},
        "tool_response": {"output": "SUPER_SECRET_TOOL_RESPONSE"},
        "cwd": str(tmp_path),
    }
    code = _run_hook(monkeypatch, ["agent-guard", "hook", "post"], payload)
    assert code == ExitCode.OK

    log_file = state_home / "veil" / "agent-log.jsonl"
    assert log_file.is_file()
    assert stat.S_IMODE(log_file.lstat().st_mode) == 0o600

    raw = log_file.read_text(encoding="utf-8")
    assert "TOP_SECRET_FILE_CONTENT_DO_NOT_LOG" not in raw
    assert "SUPER_SECRET_TOOL_RESPONSE" not in raw

    entry = json.loads(raw.splitlines()[0])
    assert entry["session_id"] == "sess-post"
    assert entry["tool_name"] == "Write"
    assert entry["paths"] == [str(target)]
    assert entry["sha256"] == hashlib.sha256(secret_body.encode("utf-8")).hexdigest()
    assert "timestamp" in entry


def test_hook_stop_blocks_on_high_findings_and_notifies(
    monkeypatch, tmp_path, capsys, notifications
):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)

    # First pre hook records HEAD
    pre_payload = {
        "session_id": "sess-stop-1",
        "tool_name": "Edit",
        "tool_input": {"file_path": str(repo / "src" / "app.py")},
        "cwd": str(repo),
    }
    assert _run_hook(monkeypatch, ["agent-guard", "hook", "pre"], pre_payload) == ExitCode.OK

    # Tamper with test file afterwards
    (repo / "tests" / "test_app.py").unlink()

    stop_payload = {"session_id": "sess-stop-1", "cwd": str(repo)}
    assert _run_hook(monkeypatch, ["agent-guard", "hook", "stop"], stop_payload) == ExitCode.OK

    out = capsys.readouterr().out
    decision = json.loads(out)
    assert decision["decision"] == "block"
    assert decision["reason"].startswith("veil agent-guard:")
    assert "test-deleted" in decision["reason"]
    assert len(notifications) == 1

    # The agent stops again after the block: flag it, but don't loop (stop_hook_active).
    again = {**stop_payload, "stop_hook_active": True}
    assert _run_hook(monkeypatch, ["agent-guard", "hook", "stop"], again) == ExitCode.OK
    assert capsys.readouterr().out == ""
    assert len(notifications) == 2


def test_hook_stop_runs_test_command_and_blocks_on_failure(
    monkeypatch, tmp_path, capsys, notifications
):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / ".veil-agent-guard.toml").write_text(
        f'test_command = "{sys.executable} -c \\"import sys; sys.exit(1)\\""\n',
        encoding="utf-8",
    )
    git_bin = shutil.which("git") or "git"
    subprocess.run([git_bin, "add", ".veil-agent-guard.toml"], cwd=repo, check=True)
    subprocess.run([git_bin, "commit", "-q", "-m", "add config"], cwd=repo, check=True)

    assert (
        _run_hook(
            monkeypatch,
            ["agent-guard", "hook", "pre"],
            {
                "session_id": "sess-tc",
                "tool_name": "Edit",
                "tool_input": {"file_path": "src/app.py"},
                "cwd": str(repo),
            },
        )
        == ExitCode.OK
    )

    assert (
        _run_hook(
            monkeypatch,
            ["agent-guard", "hook", "stop"],
            {"session_id": "sess-tc", "cwd": str(repo)},
        )
        == ExitCode.OK
    )

    decision = json.loads(capsys.readouterr().out)
    assert decision["decision"] == "block"
    assert "test_command failed (exit 1)" in decision["reason"]
    assert len(notifications) == 1


def test_hook_stop_passes_when_clean_and_test_command_succeeds(
    monkeypatch, tmp_path, capsys, notifications
):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_git_repo(repo)
    (repo / ".veil-agent-guard.toml").write_text(
        f'test_command = "{sys.executable} -c \\"import sys; sys.exit(0)\\""\n',
        encoding="utf-8",
    )
    git_bin = shutil.which("git") or "git"
    subprocess.run([git_bin, "add", ".veil-agent-guard.toml"], cwd=repo, check=True)
    subprocess.run([git_bin, "commit", "-q", "-m", "add config"], cwd=repo, check=True)

    assert (
        _run_hook(
            monkeypatch,
            ["agent-guard", "hook", "pre"],
            {
                "session_id": "sess-clean",
                "tool_name": "Edit",
                "tool_input": {"file_path": "src/app.py"},
                "cwd": str(repo),
            },
        )
        == ExitCode.OK
    )

    assert (
        _run_hook(
            monkeypatch,
            ["agent-guard", "hook", "stop"],
            {"session_id": "sess-clean", "cwd": str(repo)},
        )
        == ExitCode.OK
    )

    assert capsys.readouterr().out == ""
    assert notifications == []


def test_hook_session_start_outputs_notice_json(capsys):
    code = cli.main(["agent-guard", "hook", "session-start"])
    assert code == ExitCode.OK
    out = capsys.readouterr().out
    data = json.loads(out)
    hso = data["hookSpecificOutput"]
    assert hso["hookEventName"] == "SessionStart"
    notice = hso["additionalContext"]
    lines = [ln for ln in notice.splitlines() if ln.strip()]
    assert 1 <= len(lines) <= 8
    low = notice.lower()
    assert "veil" in low
    assert "active" in low
    assert "pseudonym" in low
    assert "verbatim" in low
    assert "recover" in low or "guess" in low
    assert "never ask" in low
    assert "real personal details" in low
    assert "clipboard" in low
    assert "veil commands" in low
    assert "agent-guard" in low
    assert "tampering" in low


def test_cli_parser_does_not_eagerly_import_agentguard():
    code = (
        "import sys; from veil import cli; cli.build_parser(); "
        "assert not any(m.startswith('veil.agentguard') for m in sys.modules)"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=REPO_ROOT, check=False)
    assert proc.returncode == 0


def test_hook_pre_in_process_latency_under_40ms(tmp_path):
    payload = {
        "session_id": "perf-inproc",
        "tool_name": "Bash",
        "tool_input": {"command": "sed -i 's/a/b/' tests/test_app.py"},
        "cwd": str(tmp_path),
    }
    timings = []
    for _ in range(10):
        t0 = time.perf_counter()
        decision = hook.evaluate_pre(payload)
        timings.append((time.perf_counter() - t0) * 1000)
        assert not decision.allowed
    assert statistics.median(timings) < 40.0


def test_hook_pre_subprocess_latency_within_budget(tmp_path):
    budget = float(os.environ.get("VEIL_PERF_BUDGET_MS", "150"))
    payload = json.dumps(
        {
            "session_id": "perf-sub",
            "tool_name": "Edit",
            "tool_input": {"file_path": str(tmp_path / "tests" / "test_x.py")},
            "cwd": str(tmp_path),
        }
    )
    env = {**os.environ, "XDG_STATE_HOME": str(tmp_path / "state")}
    timings = []
    for _ in range(5):
        t0 = time.perf_counter()
        proc = subprocess.run(
            [sys.executable, "-m", "veil", "agent-guard", "hook", "pre"],
            input=payload,
            text=True,
            capture_output=True,
            env=env,
            cwd=REPO_ROOT,
            check=False,
            timeout=30,
        )
        timings.append((time.perf_counter() - t0) * 1000)
        assert proc.returncode == 2
    median = statistics.median(timings)
    assert median < budget, f"hook pre median {median:.1f} ms >= {budget:.1f} ms"
