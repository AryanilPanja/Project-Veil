"""`veil agent-guard review`: scan git diffs for tests, check, ML, security, and guard tampering."""

import ast
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath

from veil import ui
from veil.clip import notify
from veil.errors import VeilError
from veil.exitcodes import ExitCode

_MAX_UNTRACKED_BYTES = 1_048_576
_GIT_TIMEOUT = 30
_NOTIFY_TIMEOUT = 3.0
_GIT_BIN = shutil.which("git") or "git"


class Severity(StrEnum):
    HIGH = "high"
    MED = "med"
    LOW = "low"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    family: str
    path: str
    line: int
    reason: str


@dataclass(frozen=True)
class DiffLine:
    kind: str  # "+", "-", " "
    old_lineno: int | None
    new_lineno: int | None
    text: str


@dataclass(frozen=True)
class DiffHunk:
    old_start: int
    new_start: int
    lines: tuple[DiffLine, ...]


@dataclass(frozen=True)
class FileDiff:
    old_path: str | None
    new_path: str | None
    is_new: bool = False
    is_deleted: bool = False
    is_renamed: bool = False
    hunks: tuple[DiffHunk, ...] = ()

    @property
    def display_path(self) -> str:
        return self.new_path or self.old_path or ""


@dataclass(frozen=True)
class ReviewResult:
    base_ref: str | None
    findings: tuple[Finding, ...]

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.HIGH)

    @property
    def med_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.MED)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity is Severity.LOW)

    @property
    def exit_code(self) -> int:
        if self.high_count > 0:
            return int(ExitCode.HIGH_FINDINGS)
        if self.med_count > 0 or self.low_count > 0:
            return int(ExitCode.FINDINGS)
        return int(ExitCode.OK)


# ── Path classification ──────────────────────────────────────────────────────


def _is_test_file(path: str) -> bool:
    p = PurePosixPath(path)
    parts = p.parts
    if any(part in ("tests", "test") for part in parts[:-1]):
        return True
    name = p.name
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or ".spec." in name
        or ".test." in name
        or name == "conftest.py"
    )


def _is_ci_file(path: str) -> bool:
    p = PurePosixPath(path)
    if len(p.parts) >= 2 and p.parts[0] == ".github" and p.parts[1] == "workflows":
        return True
    if p.parts[0] == ".circleci":
        return True
    return p.name in (".gitlab-ci.yml", "Jenkinsfile", ".pre-commit-config.yaml")


def _is_env_cred_file(path: str) -> bool:
    if _is_ci_file(path):
        return True
    p = PurePosixPath(path)
    if p.suffix.lower() in (".sh", ".bash", ".zsh", ".ksh", ".mk"):
        return True
    return p.name in ("Makefile", "makefile", "GNUmakefile")


def _is_guard_file(path: str) -> bool:
    p = PurePosixPath(path)
    if p.parts[0] == ".claude":
        return True
    if len(p.parts) >= 2 and p.parts[0] == "contrib" and p.parts[1] == "agent-guard":
        return True
    if len(p.parts) >= 3 and p.parts[:3] == ("src", "veil", "agentguard"):
        return True
    if len(p.parts) >= 2 and p.parts[:2] == (".git", "hooks"):
        return True
    return p.name == ".veil-agent-guard.toml"


_ML_EVAL_RE = re.compile(r"(eval|metric|benchmark|score|leaderboard)", re.IGNORECASE)
_TRAIN_PATH_RE = re.compile(r"(train|finetune|fine_tune)", re.IGNORECASE)
_ML_IMPORT_RE = re.compile(
    r"(?:^\s*(?:import|from)\s+(?:torch|sklearn|scikit_learn|numpy|jax|tensorflow|tf|"
    r"datasets|transformers|keras|scipy|lightgbm|xgboost|catboost|evaluate|torchmetrics)\b|"
    r"\b(?:torch|sklearn|numpy|jax|tensorflow|datasets)\.)",
    re.MULTILINE,
)


def _has_ml_import(path: str, *, repo: Path | None, diff: FileDiff | None) -> bool:
    if diff is not None:
        for hunk in diff.hunks:
            for dl in hunk.lines:
                if _ML_IMPORT_RE.search(dl.text):
                    return True
    if repo is not None and (diff is None or not diff.is_deleted):
        full = repo / path
        try:
            if full.is_file() and full.stat().st_size <= _MAX_UNTRACKED_BYTES:
                content = full.read_text(encoding="utf-8", errors="replace")
                if _ML_IMPORT_RE.search(content):
                    return True
        except OSError:
            pass
    return False


def _is_ml_eval_file(path: str, *, repo: Path | None = None, diff: FileDiff | None = None) -> bool:
    if _is_test_file(path) or _is_guard_file(path):
        return False
    p = PurePosixPath(path)
    if any(part.lower() in ("eval", "evals", "metric", "metrics") for part in p.parts[:-1]):
        return True
    if not _ML_EVAL_RE.search(p.name):
        return False
    return _has_ml_import(path, repo=repo, diff=diff)


# ── Git helpers ──────────────────────────────────────────────────────────────


def _git(repo: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed git executable with controlled flags
        [
            _GIT_BIN,
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "--no-pager",
            *args,
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=_GIT_TIMEOUT,
    )


def resolve_base_ref(repo: Path, base: str | None = None) -> str | None:
    """Resolve the git comparison base ref (merge-base with remote default, fallback HEAD~1)."""
    if base is not None:
        mb = _git(repo, ["merge-base", base, "HEAD"])
        if mb.returncode == 0 and mb.stdout.strip():
            return mb.stdout.strip()
        rev = _git(repo, ["rev-parse", "--verify", "--quiet", base])
        if rev.returncode == 0 and rev.stdout.strip():
            return rev.stdout.strip()
        raise VeilError("invalid git base ref", exit_code=ExitCode.USAGE)

    head_check = _git(repo, ["rev-parse", "--verify", "--quiet", "HEAD"])
    if head_check.returncode != 0:
        return None  # unborn repository

    sym = _git(repo, ["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"])
    remote_default: str | None = None
    if sym.returncode == 0 and sym.stdout.strip():
        ref = sym.stdout.strip()
        prefix = "refs/remotes/"
        remote_default = ref[len(prefix) :] if ref.startswith(prefix) else ref
    else:
        for candidate in ("origin/main", "origin/master"):
            check = _git(repo, ["rev-parse", "--verify", "--quiet", candidate])
            if check.returncode == 0:
                remote_default = candidate
                break

    if remote_default is not None:
        mb = _git(repo, ["merge-base", remote_default, "HEAD"])
        if mb.returncode == 0 and mb.stdout.strip():
            return mb.stdout.strip()

    parent = _git(repo, ["rev-parse", "--verify", "--quiet", "HEAD~1"])
    if parent.returncode == 0:
        return "HEAD~1"
    return "HEAD"


_HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_C_ESCAPES = {
    "a": 0x07,
    "b": 0x08,
    "f": 0x0C,
    "n": 0x0A,
    "r": 0x0D,
    "t": 0x09,
    "v": 0x0B,
    "\\": ord("\\"),
    '"': ord('"'),
}


def _unquote_git_path(raw: str) -> str:
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        buf = bytearray()
        i = 1
        end = len(raw) - 1
        while i < end:
            ch = raw[i]
            if ch == "\\" and i + 1 < end:
                nxt = raw[i + 1]
                if nxt in _C_ESCAPES:
                    buf.append(_C_ESCAPES[nxt])
                    i += 2
                    continue
                if i + 3 < end and all(c in "01234567" for c in raw[i + 1 : i + 4]):
                    buf.append(int(raw[i + 1 : i + 4], 8))
                    i += 4
                    continue
            buf.extend(ch.encode("utf-8"))
            i += 1
        return buf.decode("utf-8", errors="replace")
    return raw


def _read_git_header_token(text: str, pos: int) -> tuple[str, int] | None:
    if pos >= len(text) or text[pos] != '"':
        return None
    i = pos + 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == '"':
            return _unquote_git_path(text[pos : i + 1]), i + 1
        i += 1
    return None


def parse_unified_diff(diff_text: str) -> list[FileDiff]:
    """Parse `git diff -M --unified=3` output into structured `FileDiff` entries."""
    files: list[FileDiff] = []
    cur_old: str | None = None
    cur_new: str | None = None
    is_new = False
    is_deleted = False
    is_renamed = False
    hunks: list[DiffHunk] = []
    cur_hunk_old = 0
    cur_hunk_new = 0
    old_ln = 0
    new_ln = 0
    hunk_lines: list[DiffLine] = []
    in_hunk = False

    def flush_hunk() -> None:
        nonlocal in_hunk, hunk_lines
        if in_hunk:
            hunks.append(DiffHunk(cur_hunk_old, cur_hunk_new, tuple(hunk_lines)))
            hunk_lines = []
            in_hunk = False

    def flush_file() -> None:
        nonlocal cur_old, cur_new, is_new, is_deleted, is_renamed, hunks
        flush_hunk()
        if cur_old is not None or cur_new is not None:
            files.append(
                FileDiff(
                    old_path=cur_old,
                    new_path=cur_new,
                    is_new=is_new,
                    is_deleted=is_deleted,
                    is_renamed=is_renamed,
                    hunks=tuple(hunks),
                )
            )
        cur_old = None
        cur_new = None
        is_new = False
        is_deleted = False
        is_renamed = False
        hunks = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            flush_file()
            parts = _parse_diff_git_paths(line)
            if parts is not None:
                cur_old, cur_new = parts
            continue
        if line.startswith("new file mode "):
            is_new = True
            cur_old = None
            continue
        if line.startswith("deleted file mode "):
            is_deleted = True
            cur_new = None
            continue
        if line.startswith("rename from "):
            is_renamed = True
            cur_old = _unquote_git_path(line[len("rename from ") :].rstrip("\r\n"))
            continue
        if line.startswith("rename to "):
            is_renamed = True
            cur_new = _unquote_git_path(line[len("rename to ") :].rstrip("\r\n"))
            continue
        if line.startswith("--- "):
            raw = _unquote_git_path(line[4:].rstrip("\r\n").rstrip("\t"))
            if raw == "/dev/null":
                is_new = True
                cur_old = None
            elif raw.startswith("a/"):
                cur_old = raw[2:]
            continue
        if line.startswith("+++ "):
            raw = _unquote_git_path(line[4:].rstrip("\r\n").rstrip("\t"))
            if raw == "/dev/null":
                is_deleted = True
                cur_new = None
            elif raw.startswith("b/"):
                cur_new = raw[2:]
            continue
        m = _HUNK_HEADER_RE.match(line)
        if m:
            flush_hunk()
            in_hunk = True
            cur_hunk_old = int(m.group(1))
            cur_hunk_new = int(m.group(2))
            old_ln = cur_hunk_old
            new_ln = cur_hunk_new
            continue
        if not in_hunk:
            continue
        if line.startswith("+"):
            hunk_lines.append(DiffLine("+", None, new_ln, line[1:]))
            new_ln += 1
        elif line.startswith("-"):
            hunk_lines.append(DiffLine("-", old_ln, None, line[1:]))
            old_ln += 1
        elif line.startswith(" "):
            hunk_lines.append(DiffLine(" ", old_ln, new_ln, line[1:]))
            old_ln += 1
            new_ln += 1
        elif line.startswith("\\ No newline at end of file"):
            continue

    flush_file()
    return files


def _parse_diff_git_paths(header: str) -> tuple[str, str] | None:
    rest = header[len("diff --git ") :]
    if rest.startswith('"'):
        tok1 = _read_git_header_token(rest, 0)
        if tok1 is None:
            return None
        first, pos = tok1
        if pos >= len(rest) or rest[pos] != " ":
            return None
        second_raw = rest[pos + 1 :]
        if second_raw.startswith('"'):
            tok2 = _read_git_header_token(second_raw, 0)
            if tok2 is None:
                return None
            second = tok2[0]
        else:
            second = second_raw
        if first.startswith("a/") and second.startswith("b/"):
            return first[2:], second[2:]
        return None
    if not rest.startswith("a/"):
        return None
    quoted_b_idx = rest.find(' "b/')
    if quoted_b_idx != -1:
        tok2 = _read_git_header_token(rest, quoted_b_idx + 1)
        if tok2 is not None and tok2[0].startswith("b/"):
            return rest[2:quoted_b_idx], tok2[0][2:]
    marker = " b/"
    idx = rest.find(marker)
    if idx != -1:
        return rest[2:idx], rest[idx + len(marker) :]
    return None


def collect_diffs(repo: Path, base_ref: str | None) -> list[FileDiff]:
    """Collect diffs from `base_ref` to working tree, plus untracked non-ignored files."""
    common = ["--no-ext-diff", "--no-textconv", "-M", "--no-color", "--unified=3"]
    if base_ref is not None:
        proc = _git(repo, ["diff", *common, base_ref])
    else:
        proc = _git(repo, ["diff", *common, "--cached"])
    if proc.returncode != 0:
        raise VeilError("git diff failed", exit_code=ExitCode.USAGE)
    diffs = parse_unified_diff(proc.stdout)

    untracked = _git(repo, ["ls-files", "--others", "--exclude-standard", "-z"])
    if untracked.returncode == 0 and untracked.stdout:
        for rel in untracked.stdout.split("\0"):
            if not rel:
                continue
            full = repo / rel
            if full.is_symlink() or not full.is_file():
                continue
            hunks: tuple[DiffHunk, ...] = ()
            try:
                if full.stat().st_size <= _MAX_UNTRACKED_BYTES:
                    raw_bytes = full.read_bytes()
                    if b"\0" not in raw_bytes:
                        text = raw_bytes.decode("utf-8", errors="replace")
                        lines = tuple(
                            DiffLine("+", None, idx, ln)
                            for idx, ln in enumerate(text.splitlines(), start=1)
                        )
                        if lines:
                            hunks = (DiffHunk(0, 1, lines),)
            except OSError:
                pass
            diffs.append(FileDiff(old_path=None, new_path=rel, is_new=True, hunks=hunks))
    return diffs


# ── Rule patterns ────────────────────────────────────────────────────────────

_ASSERT_RE = re.compile(r"\bassert\b|\bself\.assert[A-Z]\w*\(|\bpytest\.raises\(|\bexpect\(")
_LITERAL_RE = re.compile(
    r"""(?<![A-Za-z0-9_])(?:True|False|None|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"""
)
_SKIP_RE = re.compile(
    r"(?:pytest\.skip\b|@pytest\.mark\.skip\b|@pytest\.mark\.skipif\b|@pytest\.mark\.xfail\b|"
    r"pytest\.xfail\b|unittest\.skip\b|@unittest\.skip\b|@unittest\.skipIf\b|"
    r"@unittest\.skipUnless\b|\b(?:it|test|describe)\.skip\s*\()"
)
_SKIPIF_DECORATOR_RE = re.compile(
    r"(?:@pytest\.mark\.skipif|@unittest\.skipIf|@unittest\.skipUnless)\s*\("
)
_PLATFORM_COND_RE = re.compile(
    r"\b(?:sys\.platform|sys\.version_info|sys\.implementation|os\.name|"
    r"platform\.(?:system|machine|release|version|python_version|platform))\b"
)
_TAUTOLOGY_RE = re.compile(r"^\s*assert\s+(?:True|1|not\s+False)\s*(?:#.*)?$")
_MOCK_RE = re.compile(
    r"(?:unittest\.mock\.patch|(?<![A-Za-z0-9_.])patch(?:\.object)?\s*\(|"
    r"mock\.patch\s*\(|mocker\.patch\s*\(|monkeypatch\.setattr\s*\(|MagicMock\s*\()"
)
_PROD_READ_TESTS_RE = re.compile(
    r"""(?:open|Path|read_text|read_bytes|load|read)\s*\([^)]*["'](?:\./)?tests/"""
)

_TOLERANCE_RE = re.compile(
    r"\b(atol|rtol|epsilon|eps|threshold|budget|timeout|max_wait|tol|default_budget_ms)\b"
    r"\s*[:=]\s*([0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)",
    re.IGNORECASE,
)
_TOL_STR_RE = re.compile(
    r"\b(default_budget_ms|budget|timeout)\s*[:=]\s*['\"]([0-9]+(?:\.[0-9]+)?)['\"]",
    re.IGNORECASE,
)
_SWALLOW_ONE_LINE_RE = re.compile(r"^\s*except\b[^:]*:\s*(?:pass|\.\.\.)\s*(?:#.*)?$")
_BARE_EXCEPT_RE = re.compile(r"^\s*except\s*:\s*(?:#.*)?$")
_EXCEPT_HEADER_RE = re.compile(r"^\s*except\b[^:]*:\s*(?:#.*)?$")
_PASS_LINE_RE = re.compile(r"^\s*(?:pass|\.\.\.)\s*(?:#.*)?$")
_SUPPRESS_RE = re.compile(r"#\s*(?:noqa\b|type:\s*ignore\b|pragma:\s*no\s+cover\b)")
_EXIT_ZERO_RE = re.compile(r"\b(?:sys\.exit|os\._exit)\s*\(\s*0\s*\)")
_SH_EXIT_ZERO_RE = re.compile(r"(?:^|[;&|]\s*)exit\s+0\b")

_CI_CONTINUE_ERR_RE = re.compile(r"^\s*continue-on-error\s*:\s*true\b", re.IGNORECASE)
_CI_OR_TRUE_RE = re.compile(r"\|\|\s*(?:true\b|:)")
_CI_IF_FALSE_RE = re.compile(r"^\s*if\s*:\s*(?:\$\{\{\s*)?false\b", re.IGNORECASE)
_CI_STEP_RE = re.compile(r"^\s*-\s+(?:name|run|uses)\s*:")
_CI_CHECK_CMD_RE = re.compile(r"\b(?:pytest|ruff|mypy|flake8|unittest)\b")

_PYPROJECT_IGNORE_RE = re.compile(r"^\s*(?:ignore|extend-ignore)\s*=")
_PYPROJECT_FILTERWARN_RE = re.compile(r'["\']ignore(?::[^"\']*)?["\']')
_PYPROJECT_STRICT_DROP_RE = re.compile(
    r"(?:xfail_strict\s*=\s*true|--strict-markers|--strict-config|\"error\"|'error'|banned-api)"
)

_ML_SEED_RE = re.compile(
    r"\b(?:random\.seed|np\.random\.seed|numpy\.random\.seed|torch\.manual_seed|"
    r"torch\.cuda\.manual_seed(?:_all)?|set_seed|seed_everything|tf\.random\.set_seed|"
    r"jax\.random\.PRNGKey)\s*\("
)
_ML_HYPERPARAM_RE = re.compile(
    r"""(?:["']|\b)(lr|learning_rate|epochs|num_epochs|max_epochs|batch_size|"""
    r"""per_device_train_batch_size|weight_decay|dropout)(?:["'])?\s*[:=]"""
)
_ML_SPLIT_RE = re.compile(
    r"\b(?:train_test_split|test_size|val_size|split_ratio|val_split|validation_split|"
    r"random_state|dataset_path|data_dir|train_path|val_path|test_path|eval_path|"
    r"data_files|load_dataset)\b"
)
_ML_EVAL_MODE_RE = re.compile(
    r"(?:\.eval\s*\(\s*\)|torch\.no_grad\s*\(|torch\.inference_mode\s*\()"
)
_ML_TRAIN_CUE_RE = re.compile(
    r"(?:optimizer\.step|loss\.backward|model\.train\s*\(|\bTrainer\s*\()"
)
_ML_LEAKAGE_RE = re.compile(
    r"""(?:test_path|val_path|test_set|val_set|test_loader|val_loader|"""
    r"""split\s*=\s*["'](?:test|val|validation)["']|"""
    r"""["'][^"']*(?:/|\\)(?:test|val|validation)(?:/|\\|\.)[^"']*["']|"""
    r"""["'](?:test|val|validation)\.(?:csv|json|jsonl|parquet|pt|npy)["'])"""
)
_ML_METRIC_FN_RE = re.compile(
    r"(?:eval|metric|score|accuracy|f1|precision|recall|auc|bleu|rouge)", re.IGNORECASE
)

_SEC_CRED_PATH_RE = re.compile(
    r"(?:~/\.ssh|~/\.aws|~/\.gnupg|/\.ssh/|/\.aws/|Library/Keychains|"
    r"security\s+find-|secret-tool)"
)
_SEC_CRED_ENV_RE = re.compile(
    r"""(?:os\.(?:environ(?:\.get)?|getenv)\s*[\[(]\s*["'][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)[A-Z0-9_]*["']|"""
    r"""\$\{?[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)[A-Z0-9_]*\}?)"""
)
_SEC_SHELL_TRUE_RE = re.compile(r"\bshell\s*=\s*True\b")
_SEC_EVAL_EXEC_RE = re.compile(r"(?<!\.)\b(?:eval|exec)\s*\(")
_SEC_B64_RE = re.compile(
    r"(?:\bbase64\.b64decode\s*\(|\bb64decode\s*\(|\bbase64\s+(?:-d|--decode)\b)"
)
_SEC_NET_RE = re.compile(
    r"(?:^\s*(?:import|from)\s+(?:requests|httpx|urllib|socket)\b|"
    r"\b(?:requests|httpx)\.(?:get|post|put|delete|patch|head|request)\s*\(|"
    r"\burllib\.request\.urlopen\s*\(|\bsocket\.socket\s*\(|"
    r"(?:^|[;&|\s])(?:curl|wget)\s+)"
)


# ── Diff scanning ────────────────────────────────────────────────────────────


def scan_diffs(diffs: list[FileDiff], *, repo: Path | None = None) -> list[Finding]:
    """Analyze parsed diffs across all 5 agent-guard rule families."""
    findings: list[Finding] = []
    for diff in diffs:
        path = diff.display_path
        if not path:
            continue
        findings.extend(_check_guard_tampering(diff))
        findings.extend(_check_tests_family(diff, repo=repo))
        findings.extend(_check_weakened_checks(diff, repo=repo))
        findings.extend(_check_ml_integrity(diff, repo=repo))
        findings.extend(_check_security_family(diff))
    return _dedupe_findings(findings)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int]] = set()
    unique: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.path, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _check_guard_tampering(diff: FileDiff) -> list[Finding]:
    paths = [p for p in (diff.old_path, diff.new_path) if p]
    if any(_is_guard_file(p) for p in paths):
        return [
            Finding(
                rule_id="guard-tampering",
                severity=Severity.HIGH,
                family="guard-tampering",
                path=diff.display_path,
                line=1,
                reason="agent-guard, hook, or .claude configuration modified",
            )
        ]
    return []


def _check_tests_family(diff: FileDiff, *, repo: Path | None) -> list[Finding]:
    out: list[Finding] = []
    path = diff.display_path
    is_test = _is_test_file(path)

    if diff.is_deleted and diff.old_path and _is_test_file(diff.old_path):
        out.append(
            Finding(
                rule_id="test-deleted",
                severity=Severity.HIGH,
                family="tests",
                path=diff.old_path,
                line=1,
                reason="test file deleted",
            )
        )
        return out

    if (
        diff.is_renamed
        and diff.old_path
        and diff.new_path
        and _is_test_file(diff.old_path)
        and not _is_test_file(diff.new_path)
    ):
        out.append(
            Finding(
                rule_id="test-deleted",
                severity=Severity.HIGH,
                family="tests",
                path=diff.new_path,
                line=1,
                reason="test file renamed to non-test path",
            )
        )

    removed_asserts = 0
    added_asserts = 0
    first_removed_assert_line: int | None = None

    for hunk in diff.hunks:
        hunk_rem_asserts: list[DiffLine] = []
        hunk_add_asserts: list[DiffLine] = []

        for dl in hunk.lines:
            if dl.kind == "-":
                if is_test and _ASSERT_RE.search(dl.text):
                    removed_asserts += 1
                    hunk_rem_asserts.append(dl)
                    if first_removed_assert_line is None:
                        first_removed_assert_line = dl.old_lineno or hunk.new_start
                continue
            if dl.kind != "+":
                continue
            lineno = dl.new_lineno or 1
            stripped = dl.text.lstrip()
            is_comment = stripped.startswith("#")

            if is_test and _ASSERT_RE.search(dl.text):
                if not _TAUTOLOGY_RE.match(dl.text):
                    added_asserts += 1
                hunk_add_asserts.append(dl)

            if (
                not is_comment
                and _SKIP_RE.search(dl.text)
                and not _is_allowed_platform_skip(dl.text)
            ):
                out.append(
                    Finding(
                        rule_id="test-skipped",
                        severity=Severity.HIGH,
                        family="tests",
                        path=path,
                        line=lineno,
                        reason="skip/xfail marker added to test",
                    )
                )

            if is_test and _TAUTOLOGY_RE.match(dl.text):
                out.append(
                    Finding(
                        rule_id="test-tautology",
                        severity=Severity.HIGH,
                        family="tests",
                        path=path,
                        line=lineno,
                        reason="tautological assertion (assert True) added",
                    )
                )

            if not is_test and not is_comment and "PYTEST_CURRENT_TEST" in dl.text:
                out.append(
                    Finding(
                        rule_id="test-env-detect",
                        severity=Severity.HIGH,
                        family="tests",
                        path=path,
                        line=lineno,
                        reason="production code checks PYTEST_CURRENT_TEST",
                    )
                )

            if not is_test and not is_comment and _PROD_READ_TESTS_RE.search(dl.text):
                out.append(
                    Finding(
                        rule_id="prod-reads-tests",
                        severity=Severity.HIGH,
                        family="tests",
                        path=path,
                        line=lineno,
                        reason="production code reads file under tests/",
                    )
                )

            if is_test and not is_comment and _MOCK_RE.search(dl.text):
                out.append(
                    Finding(
                        rule_id="test-over-mocking",
                        severity=Severity.MED,
                        family="tests",
                        path=path,
                        line=lineno,
                        reason="new mock/patch added in test file",
                    )
                )

        # Detect changed expected literals in paired assertions
        if is_test and not diff.is_new and hunk_rem_asserts and hunk_add_asserts:
            for rem, add in zip(hunk_rem_asserts, hunk_add_asserts, strict=False):
                rem_lits = _LITERAL_RE.findall(_assert_expr_text(rem.text))
                add_lits = _LITERAL_RE.findall(_assert_expr_text(add.text))
                if rem_lits != add_lits and (rem_lits or add_lits):
                    out.append(
                        Finding(
                            rule_id="test-literal-changed",
                            severity=Severity.HIGH,
                            family="tests",
                            path=path,
                            line=add.new_lineno or hunk.new_start,
                            reason="expected literal in assertion changed",
                        )
                    )

    if is_test and not diff.is_new and removed_asserts > added_asserts:
        out.append(
            Finding(
                rule_id="test-assert-dropped",
                severity=Severity.HIGH,
                family="tests",
                path=path,
                line=first_removed_assert_line or 1,
                reason=(
                    f"assertion count dropped ({removed_asserts} removed, {added_asserts} added)"
                ),
            )
        )

    if is_test and repo is not None and path.endswith(".py") and not diff.is_deleted:
        out.extend(_ast_pass_only_tests(repo, diff))

    return out


def _ast_pass_only_tests(repo: Path, diff: FileDiff) -> list[Finding]:
    target = repo / diff.display_path
    try:
        source = target.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, UnicodeDecodeError, SyntaxError):
        return []
    added_lines = {
        dl.new_lineno
        for hunk in diff.hunks
        for dl in hunk.lines
        if dl.kind == "+" and dl.new_lineno is not None
    }
    if not added_lines:
        return []
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.name.startswith("test_"):
            continue
        end_line = node.end_lineno or node.lineno
        if not any(node.lineno <= ln <= end_line for ln in added_lines):
            continue
        if _is_pass_only_body(node.body):
            out.append(
                Finding(
                    rule_id="test-tautology",
                    severity=Severity.HIGH,
                    family="tests",
                    path=diff.display_path,
                    line=node.lineno,
                    reason="test function has pass-only body",
                )
            )
    return out


def _is_pass_only_body(body: list[ast.stmt]) -> bool:
    stmts = list(body)
    if (
        stmts
        and isinstance(stmts[0], ast.Expr)
        and isinstance(stmts[0].value, ast.Constant)
        and isinstance(stmts[0].value.value, str)
    ):
        stmts = stmts[1:]
    if not stmts:
        return True
    return all(
        isinstance(s, ast.Pass)
        or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is ...)
        for s in stmts
    )


def _is_allowed_platform_skip(line: str) -> bool:
    return bool(_SKIPIF_DECORATOR_RE.search(line) and _PLATFORM_COND_RE.search(line))


def _assert_expr_text(line: str) -> str:
    stripped = line.strip()
    if stripped.startswith("assert "):
        try:
            tree = ast.parse(stripped)
        except SyntaxError:
            return line
        if len(tree.body) == 1 and isinstance(tree.body[0], ast.Assert):
            return ast.unparse(tree.body[0].test)
    return line


def _check_weakened_checks(diff: FileDiff, *, repo: Path | None = None) -> list[Finding]:
    out: list[Finding] = []
    path = diff.display_path
    is_test = _is_test_file(path)
    is_eval = _is_ml_eval_file(path, repo=repo, diff=diff)
    is_ci = _is_ci_file(path)
    is_pyproject = PurePosixPath(path).name == "pyproject.toml"
    is_agentguard = _is_guard_file(path)

    ci_steps_removed = 0
    ci_steps_added = 0
    first_ci_removed_line = 1

    for hunk in diff.hunks:
        old_tols: dict[str, float] = {}
        new_tols: list[tuple[str, float, int]] = []
        added_lines = [dl for dl in hunk.lines if dl.kind == "+"]

        for dl in hunk.lines:
            if dl.kind == "-":
                for m in _TOLERANCE_RE.finditer(dl.text):
                    old_tols[m.group(1).lower()] = float(m.group(2))
                for m in _TOL_STR_RE.finditer(dl.text):
                    old_tols[m.group(1).lower()] = float(m.group(2))
                if is_ci and (_CI_STEP_RE.search(dl.text) or _CI_CHECK_CMD_RE.search(dl.text)):
                    ci_steps_removed += 1
                    if first_ci_removed_line == 1 and dl.old_lineno:
                        first_ci_removed_line = dl.old_lineno
                if is_pyproject and _PYPROJECT_STRICT_DROP_RE.search(dl.text):
                    out.append(
                        Finding(
                            rule_id="check-pyproject-weakened",
                            severity=Severity.HIGH,
                            family="weakened-checks",
                            path=path,
                            line=dl.old_lineno or hunk.new_start,
                            reason="strict check or banned-api rule removed in pyproject.toml",
                        )
                    )
                continue

            if dl.kind != "+":
                continue
            lineno = dl.new_lineno or 1
            stripped = dl.text.lstrip()

            for m in _TOLERANCE_RE.finditer(dl.text):
                new_tols.append((m.group(1).lower(), float(m.group(2)), lineno))
            for m in _TOL_STR_RE.finditer(dl.text):
                new_tols.append((m.group(1).lower(), float(m.group(2)), lineno))

            if _BARE_EXCEPT_RE.match(dl.text) or _SWALLOW_ONE_LINE_RE.match(dl.text):
                out.append(
                    Finding(
                        rule_id="check-swallowed-exception",
                        severity=Severity.MED,
                        family="weakened-checks",
                        path=path,
                        line=lineno,
                        reason="bare except or swallowed exception added",
                    )
                )

            if (
                not is_agentguard
                and not stripped.startswith(('r"', "r'", '"', "'"))
                and _SUPPRESS_RE.search(dl.text)
            ):
                out.append(
                    Finding(
                        rule_id="check-lint-suppressed",
                        severity=Severity.MED,
                        family="weakened-checks",
                        path=path,
                        line=lineno,
                        reason="lint/type/coverage suppression added",
                    )
                )

            if (is_test or is_ci) and (
                _EXIT_ZERO_RE.search(dl.text) or (is_ci and _SH_EXIT_ZERO_RE.search(dl.text))
            ):
                out.append(
                    Finding(
                        rule_id="check-forced-exit-zero",
                        severity=Severity.HIGH,
                        family="weakened-checks",
                        path=path,
                        line=lineno,
                        reason="forced zero exit status added in test or CI path",
                    )
                )

            if is_pyproject and (
                _PYPROJECT_IGNORE_RE.match(dl.text) or _PYPROJECT_FILTERWARN_RE.search(dl.text)
            ):
                out.append(
                    Finding(
                        rule_id="check-pyproject-weakened",
                        severity=Severity.HIGH,
                        family="weakened-checks",
                        path=path,
                        line=lineno,
                        reason="lint ignore or filterwarnings ignore added in pyproject.toml",
                    )
                )

            if is_ci:
                if _CI_STEP_RE.search(dl.text) or _CI_CHECK_CMD_RE.search(dl.text):
                    ci_steps_added += 1
                if (
                    _CI_CONTINUE_ERR_RE.match(dl.text)
                    or _CI_OR_TRUE_RE.search(dl.text)
                    or _CI_IF_FALSE_RE.match(dl.text)
                ):
                    out.append(
                        Finding(
                            rule_id="check-ci-weakened",
                            severity=Severity.HIGH,
                            family="weakened-checks",
                            path=path,
                            line=lineno,
                            reason="CI failure suppression (continue-on-error/|| true/if: false)",
                        )
                    )

        # Multi-line `except ...:\n    pass`
        for idx, dl in enumerate(added_lines[:-1]):
            if _EXCEPT_HEADER_RE.match(dl.text):
                nxt = added_lines[idx + 1]
                if _PASS_LINE_RE.match(nxt.text):
                    out.append(
                        Finding(
                            rule_id="check-swallowed-exception",
                            severity=Severity.MED,
                            family="weakened-checks",
                            path=path,
                            line=dl.new_lineno or hunk.new_start,
                            reason="except block with pass-only body added",
                        )
                    )

        if is_test or is_eval:
            for key, new_val, ln in new_tols:
                if key in old_tols and new_val > old_tols[key]:
                    reason = f"tolerance/timeout '{key}' raised ({old_tols[key]} -> {new_val})"
                    out.append(
                        Finding(
                            rule_id="check-tolerance-raised",
                            severity=Severity.HIGH,
                            family="weakened-checks",
                            path=path,
                            line=ln,
                            reason=reason,
                        )
                    )

    if is_ci and not diff.is_deleted and ci_steps_removed > ci_steps_added:
        out.append(
            Finding(
                rule_id="check-ci-weakened",
                severity=Severity.HIGH,
                family="weakened-checks",
                path=path,
                line=first_ci_removed_line,
                reason="CI check or step removed",
            )
        )

    return out


def _check_ml_integrity(diff: FileDiff, *, repo: Path | None) -> list[Finding]:
    out: list[Finding] = []
    path = diff.display_path
    is_test = _is_test_file(path)
    is_guard = _is_guard_file(path)
    if is_test or is_guard:
        return out

    if _is_ml_eval_file(path, repo=repo, diff=diff):
        out.append(
            Finding(
                rule_id="ml-eval-edited",
                severity=Severity.HIGH,
                family="ml-integrity",
                path=path,
                line=1,
                reason="ML evaluation, metric, benchmark, or leaderboard file modified",
            )
        )

    file_has_train_cue = bool(_TRAIN_PATH_RE.search(path))
    if not file_has_train_cue:
        for hunk in diff.hunks:
            if any(_ML_TRAIN_CUE_RE.search(dl.text) for dl in hunk.lines):
                file_has_train_cue = True
                break
        if (
            not file_has_train_cue
            and repo is not None
            and path.endswith(".py")
            and not diff.is_deleted
        ):
            try:
                content = (repo / path).read_text(encoding="utf-8", errors="replace")
                if _ML_TRAIN_CUE_RE.search(content):
                    file_has_train_cue = True
            except OSError:
                pass

    is_code_or_cfg = path.endswith((".py", ".yaml", ".yml", ".json", ".toml"))
    for hunk in diff.hunks:
        removed_eval_mode: list[DiffLine] = []
        added_eval_mode = 0

        for dl in hunk.lines:
            if dl.kind == "-":
                ln = dl.old_lineno or hunk.new_start
                if _ML_SEED_RE.search(dl.text):
                    out.append(
                        Finding(
                            rule_id="ml-seed-tampered",
                            severity=Severity.HIGH,
                            family="ml-integrity",
                            path=path,
                            line=ln,
                            reason="random seed call removed or modified",
                        )
                    )
                if is_code_or_cfg and _ML_HYPERPARAM_RE.search(dl.text):
                    out.append(
                        Finding(
                            rule_id="ml-hyperparam-changed",
                            severity=Severity.HIGH,
                            family="ml-integrity",
                            path=path,
                            line=ln,
                            reason="ML hyperparameter modified",
                        )
                    )
                if _ML_SPLIT_RE.search(dl.text):
                    out.append(
                        Finding(
                            rule_id="ml-split-or-dataset-changed",
                            severity=Severity.HIGH,
                            family="ml-integrity",
                            path=path,
                            line=ln,
                            reason="dataset path or split ratio modified",
                        )
                    )
                if _ML_EVAL_MODE_RE.search(dl.text):
                    removed_eval_mode.append(dl)
            elif dl.kind == "+":
                ln = dl.new_lineno or 1
                if _ML_EVAL_MODE_RE.search(dl.text):
                    added_eval_mode += 1
                if file_has_train_cue and _ML_LEAKAGE_RE.search(dl.text):
                    out.append(
                        Finding(
                            rule_id="ml-data-leakage",
                            severity=Severity.HIGH,
                            family="ml-integrity",
                            path=path,
                            line=ln,
                            reason="test/validation data path referenced in training code",
                        )
                    )

        if len(removed_eval_mode) > added_eval_mode:
            for dl in removed_eval_mode:
                out.append(
                    Finding(
                        rule_id="ml-eval-mode-removed",
                        severity=Severity.HIGH,
                        family="ml-integrity",
                        path=path,
                        line=dl.old_lineno or hunk.new_start,
                        reason=".eval() or torch.no_grad() removed",
                    )
                )

    if repo is not None and path.endswith(".py") and not diff.is_deleted:
        out.extend(_ast_constant_metrics(repo, diff))

    return out


def _ast_constant_metrics(repo: Path, diff: FileDiff) -> list[Finding]:
    path = diff.display_path
    try:
        source = (repo / path).read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, UnicodeDecodeError, SyntaxError):
        return []
    added_lines = {
        dl.new_lineno
        for hunk in diff.hunks
        for dl in hunk.lines
        if dl.kind == "+" and dl.new_lineno is not None
    }
    if not added_lines:
        return []

    in_eval_file = _is_ml_eval_file(path, repo=repo, diff=diff)
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not in_eval_file and not _ML_METRIC_FN_RE.search(node.name):
            continue
        end_line = node.end_lineno or node.lineno
        if not any(node.lineno <= ln <= end_line for ln in added_lines):
            continue
        if _returns_only_constants(node):
            out.append(
                Finding(
                    rule_id="ml-constant-metric",
                    severity=Severity.HIGH,
                    family="ml-integrity",
                    path=path,
                    line=node.lineno,
                    reason="metric/evaluation function returns constant value",
                )
            )
    return out


def _is_const_expr(expr: ast.expr | None) -> bool:
    if expr is None:
        return False
    if isinstance(expr, ast.Constant):
        return True
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, (ast.UAdd, ast.USub)):
        return _is_const_expr(expr.operand)
    if isinstance(expr, (ast.Tuple, ast.List)):
        return all(_is_const_expr(elt) for elt in expr.elts)
    if isinstance(expr, ast.Dict):
        return all(_is_const_expr(v) for v in expr.values)
    return False


def _returns_only_constants(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    if not returns:
        return False
    return all(_is_const_expr(r.value) for r in returns)


def _check_security_family(diff: FileDiff) -> list[Finding]:
    out: list[Finding] = []
    path = diff.display_path
    if _is_guard_file(path):
        return out

    filename = PurePosixPath(path).name
    is_dep_file = filename in ("pyproject.toml", "uv.lock", "package.json")
    is_env_cred = _is_env_cred_file(path)
    in_dep_section = False

    for hunk in diff.hunks:
        for dl in hunk.lines:
            if dl.kind != "+":
                if is_dep_file and dl.kind == " ":
                    in_dep_section = _update_dep_section(filename, dl.text, in_dep_section)
                continue
            lineno = dl.new_lineno or 1
            stripped = dl.text.lstrip()
            is_comment = stripped.startswith("#")

            if is_dep_file:
                in_dep_section = _update_dep_section(filename, dl.text, in_dep_section)
                if _is_new_dep_line(filename, dl.text, in_dep_section):
                    out.append(
                        Finding(
                            rule_id="sec-new-dependency",
                            severity=Severity.MED,
                            family="security",
                            path=path,
                            line=lineno,
                            reason=f"new dependency added in {filename}",
                        )
                    )
                if filename == "pyproject.toml" and stripped.endswith("]"):
                    in_dep_section = False
                continue

            if is_comment:
                continue

            if _SEC_CRED_PATH_RE.search(dl.text) or (
                is_env_cred and _SEC_CRED_ENV_RE.search(dl.text)
            ):
                out.append(
                    Finding(
                        rule_id="sec-credential-access",
                        severity=Severity.HIGH,
                        family="security",
                        path=path,
                        line=lineno,
                        reason="credential path, keychain, or secret env var access added",
                    )
                )

            if _SEC_SHELL_TRUE_RE.search(dl.text):
                out.append(
                    Finding(
                        rule_id="sec-shell-true",
                        severity=Severity.HIGH,
                        family="security",
                        path=path,
                        line=lineno,
                        reason="subprocess shell=True added",
                    )
                )

            if _SEC_EVAL_EXEC_RE.search(dl.text):
                out.append(
                    Finding(
                        rule_id="sec-eval-exec",
                        severity=Severity.HIGH,
                        family="security",
                        path=path,
                        line=lineno,
                        reason="dynamic eval()/exec() call added",
                    )
                )

            if _SEC_B64_RE.search(dl.text):
                out.append(
                    Finding(
                        rule_id="sec-base64-blob",
                        severity=Severity.HIGH,
                        family="security",
                        path=path,
                        line=lineno,
                        reason="base64 decoding added",
                    )
                )

            if _SEC_NET_RE.search(dl.text):
                out.append(
                    Finding(
                        rule_id="sec-network-call",
                        severity=Severity.MED,
                        family="security",
                        path=path,
                        line=lineno,
                        reason="new network client import or call added",
                    )
                )

    return out


def _update_dep_section(filename: str, line: str, current: bool) -> bool:
    stripped = line.strip()
    if filename == "pyproject.toml":
        if stripped.startswith("["):
            return stripped in ("[project.optional-dependencies]", "[dependency-groups]")
        if stripped.startswith("dependencies"):
            return True
        if stripped == "]":
            return False
    elif filename == "package.json":
        if '"dependencies"' in stripped or '"devDependencies"' in stripped:
            return True
        if stripped.startswith("}"):
            return False
    return current


def _is_new_dep_line(filename: str, line: str, in_section: bool) -> bool:
    stripped = line.strip()
    if filename == "uv.lock":
        return stripped == "[[package]]"
    if filename == "pyproject.toml":
        if re.match(r'^dependencies\s*=\s*\[.*["\'][A-Za-z0-9_.-]+', stripped):
            return True
        if not in_section or stripped.startswith(("#", "[", "]", "dependencies")):
            return False
        return bool(re.match(r'^["\'][A-Za-z0-9_.-]+', stripped))
    if filename == "package.json":
        if not in_section or stripped.startswith(("{", "}", '"dependencies"', '"devDependencies"')):
            return False
        return bool(re.match(r'^"[^"]+"\s*:', stripped))
    return False


# ── Output & Notifications ───────────────────────────────────────────────────


def format_table(result: ReviewResult) -> str:
    if not result.findings:
        return "veil agent-guard: no findings"
    rows = [
        (
            f.severity.value,
            f.rule_id,
            f"{f.path}:{f.line}",
            f.reason,
        )
        for f in result.findings
    ]
    w0 = max(len("SEVERITY"), *(len(r[0]) for r in rows))
    w1 = max(len("RULE"), *(len(r[1]) for r in rows))
    w2 = max(len("LOCATION"), *(len(r[2]) for r in rows))
    lines = [
        f"{'SEVERITY':<{w0}}  {'RULE':<{w1}}  {'LOCATION':<{w2}}  REASON",
        *(f"{r[0]:<{w0}}  {r[1]:<{w1}}  {r[2]:<{w2}}  {r[3]}" for r in rows),
        f"Summary: {result.high_count} high, {result.med_count} med, {result.low_count} low",
    ]
    return "\n".join(lines)


def format_json(result: ReviewResult) -> str:
    payload = {
        "base_ref": result.base_ref,
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "family": f.family,
                "path": f.path,
                "line": f.line,
                "reason": f.reason,
            }
            for f in result.findings
        ],
        "summary": {
            "high": result.high_count,
            "med": result.med_count,
            "low": result.low_count,
            "total": len(result.findings),
        },
    }
    return json.dumps(payload, indent=2)


class OsascriptNotifier:
    """macOS Notification Center via `osascript` (counts and rule ids only)."""

    def __init__(self, path: str, *, runner=subprocess.run) -> None:
        self._path = path
        self._runner = runner

    def script(self, message: notify.Message) -> str:
        safe_body = _applescript_escape(message.body)
        safe_title = _applescript_escape(notify.APP_NAME)
        return f'display notification "{safe_body}" with title "{safe_title}"'

    def notify(self, message: notify.Message) -> bool:
        try:
            proc = self._runner(
                [self._path, "-e", self.script(message)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=_NOTIFY_TIMEOUT,
            )
            return proc.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False


def _applescript_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", " ")


def send_notification(body: str) -> bool:
    """Send a high-severity alert using veil's notifier (Linux) or osascript (macOS)."""
    msg = notify.Message(
        summary="veil agent-guard",
        body=body,
        urgency=notify.Urgency.CRITICAL,
    )
    notifier = notify.detect()
    if not isinstance(notifier, notify.NullNotifier):
        return notifier.notify(msg)
    if sys.platform == "darwin":
        osascript = shutil.which("osascript")
        if osascript:
            return OsascriptNotifier(osascript).notify(msg)
    return False


def review_repo(repo: Path, *, base: str | None = None) -> ReviewResult:
    base_ref = resolve_base_ref(repo, base)
    diffs = collect_diffs(repo, base_ref)
    findings = scan_diffs(diffs, repo=repo)
    return ReviewResult(base_ref=base_ref, findings=tuple(findings))


def high_findings_summary(findings: tuple[Finding, ...]) -> str:
    highs = [f for f in findings if f.severity is Severity.HIGH]
    rules = sorted({f.rule_id for f in highs})
    return f"{len(highs)} high finding(s): {', '.join(rules)}"


def run_review(
    repo: Path,
    *,
    base: str | None = None,
    as_json: bool = False,
    notify_user: bool = False,
) -> int:
    """Run `veil agent-guard review` and return its ExitCode."""
    result = review_repo(repo, base=base)
    if as_json:
        ui.out(format_json(result))
    else:
        ui.out(format_table(result))
    if notify_user and result.high_count > 0:
        send_notification(high_findings_summary(result.findings))
    return result.exit_code
