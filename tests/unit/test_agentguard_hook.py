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
        "pytest -p no:cov",
        "pytest --deselect tests/test_app.py::test_add",
        'pytest -k "not slow"',
        'uv run python -m pytest -k "not slow"',
    ],
)
def test_hook_pre_blocks_dangerous_bash(monkeypatch, tmp_path, capsys, command):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
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
