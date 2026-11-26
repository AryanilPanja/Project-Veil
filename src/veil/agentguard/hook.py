"""`veil agent-guard hook {pre,post,stop}`: Claude Code lifecycle hooks."""

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from veil import ui
from veil.agentguard.config import (
    GuardConfig,
    agent_log_path,
    candidate_rel_paths,
    is_outside_cwd,
    is_protected_dir,
    is_protected_path,
    is_protected_secret_path,
    load_config,
    session_state_path,
)
from veil.exitcodes import ExitCode

_MAX_HASH_BYTES = 10_485_760
_TEST_CMD_TIMEOUT = 600
_GIT_HEAD_TIMEOUT = 5
_WRAPPER_COMMANDS = frozenset({"env", "command", "time", "nice", "nohup", "sudo"})
_SHELL_NAMES = frozenset({"sh", "bash", "zsh", "dash"})
_WRITE_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
_READ_ONLY_TOOLS = frozenset(
    {"Read", "Glob", "Grep", "LS", "WebSearch", "WebFetch", "TodoWrite", "Task", "Agent"}
)
_SECRET_READ_TOOLS = frozenset({"Read", "Glob", "Grep"})
_PATH_INPUT_FIELDS = ("file_path", "path", "notebook_path", "destination", "target")
_REDIR_TOKENS = frozenset({">", ">>", ">|", "&>", "&>>"})
_NOT_WORD_RE = re.compile(r"\bnot\b")
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_FD_REDIR_PREFIX_RE = re.compile(r"^[0-9]+$")


@dataclass(frozen=True)
class PreDecision:
    allowed: bool
    rule_id: str = ""
    target: str = ""

    @property
    def reason(self) -> str:
        return f"veil agent-guard: {self.rule_id}: {self.target}"


# ── Public entry points ──────────────────────────────────────────────────────


def _emit_pre_deny(reason: str, *, warn: bool = False) -> int:
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask" if warn else "deny",
            "permissionDecisionReason": reason,
        }
    }
    ui.out(json.dumps(out))
    if warn:
        return int(ExitCode.OK)
    ui.err(reason)
    return int(ExitCode.HOOK_BLOCK)


def run_pre(*, warn: bool = False) -> int:
    """Claude Code PreToolUse hook (fails closed on any parse error or exception)."""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return _emit_pre_deny("veil agent-guard: invalid-input: empty hook stdin")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return _emit_pre_deny("veil agent-guard: invalid-input: invalid hook JSON on stdin")
        if not isinstance(payload, dict):
            return _emit_pre_deny(
                "veil agent-guard: invalid-input: hook payload must be a JSON object"
            )

        _ensure_session_head(payload)
        decision = evaluate_pre(payload)
        if decision.allowed:
            return int(ExitCode.OK)
        if decision.rule_id in ("invalid-input", "invalid-path"):
            return _emit_pre_deny(decision.reason, warn=False)
        return _emit_pre_deny(decision.reason, warn=warn)
    except Exception:  # noqa: BLE001 - fail closed without leaking details
        return _emit_pre_deny("veil agent-guard: hook-error: failing closed")


def run_post() -> int:
    """Claude Code PostToolUse hook."""
    raw = sys.stdin.read()
    if not raw.strip():
        return int(ExitCode.OK)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return int(ExitCode.OK)
    if not isinstance(payload, dict):
        return int(ExitCode.OK)
    record_post(payload)
    return int(ExitCode.OK)


def run_stop() -> int:
    """Claude Code Stop hook."""
    raw = sys.stdin.read()
    payload: dict[str, Any] = {}
    if raw.strip():
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                payload = parsed
        except json.JSONDecodeError:
            payload = {}
    block_reason = evaluate_stop(payload)
    if block_reason is not None:
        ui.out(json.dumps({"decision": "block", "reason": block_reason}))
    return int(ExitCode.OK)


# ── PreToolUse evaluation ────────────────────────────────────────────────────


def evaluate_pre(payload: dict[str, Any]) -> PreDecision:
    tool_name = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return PreDecision(
            allowed=False, rule_id="invalid-input", target="tool_input must be a JSON object"
        )

    cwd = _resolve_cwd(payload.get("cwd"))
    config = load_config(cwd)

    for key in _PATH_INPUT_FIELDS:
        val = tool_input.get(key)
        if isinstance(val, str) and "\x00" in val:
            return PreDecision(allowed=False, rule_id="invalid-path", target="NUL byte in path")

    if tool_name == "Bash":
        command = tool_input.get("command")
        if isinstance(command, str):
            if "\x00" in command:
                return PreDecision(
                    allowed=False, rule_id="invalid-input", target="NUL byte in command"
                )
            if command.strip():
                return _check_bash_command(command, cwd, config)
        return PreDecision(allowed=True)

    if tool_name in _READ_ONLY_TOOLS:
        if tool_name in _SECRET_READ_TOOLS:
            for key in _PATH_INPUT_FIELDS:
                raw_path = tool_input.get(key)
                if (
                    isinstance(raw_path, str)
                    and raw_path.strip()
                    and is_protected_secret_path(raw_path, cwd) is not None
                ):
                    return PreDecision(
                        allowed=False,
                        rule_id="protected-secret-path",
                        target=_display_target(raw_path, cwd),
                    )
        return PreDecision(allowed=True)

    for key in _PATH_INPUT_FIELDS:
        raw_path = tool_input.get(key)
        if isinstance(raw_path, str) and raw_path.strip():
            matched = is_protected_path(raw_path, cwd, config)
            if matched is None:
                matched = is_protected_dir(raw_path, cwd, config)
            if matched is not None:
                return PreDecision(
                    allowed=False,
                    rule_id="protected-path",
                    target=_display_target(raw_path, cwd),
                )
    return PreDecision(allowed=True)


def _resolve_cwd(raw_cwd: object) -> Path:
    if isinstance(raw_cwd, str) and raw_cwd.strip():
        return Path(raw_cwd)
    return Path.cwd()


def _display_target(raw_path: str, cwd: Path) -> str:
    cands = candidate_rel_paths(raw_path, cwd)
    return cands[0] if cands else raw_path


def _tokenize_shell(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        # Fallback for unclosed quotes / complex heredocs: split line-by-line on whitespace
        return _fallback_tokenize(command)


def _fallback_tokenize(command: str) -> list[str]:
    tokens: list[str] = []
    for raw in command.split():
        # Split attached redirection operators like `foo>bar` or `foo>>bar`
        parts = re.split(r"(>>|>\|?|&&|\|\||[;|&()])", raw)
        tokens.extend(p for p in parts if p)
    return tokens


def _split_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        if tok in (";", "&&", "||", "|", "&", "(", ")"):
            if current:
                segments.append(current)
                current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)
    return segments


def _check_bash_command(command: str, cwd: Path, config: GuardConfig) -> PreDecision:
    tokens = _tokenize_shell(command)
    for seg in _split_segments(tokens):
        decision = _check_segment(seg, cwd, config)
        if not decision.allowed:
            return decision
    return PreDecision(allowed=True)


def _check_segment(seg: list[str], cwd: Path, config: GuardConfig) -> PreDecision:
    # 1. Check redirections (`>`, `>>`, `>|`, `&>`, `&>>`) anywhere in segment
    for idx, tok in enumerate(seg):
        if tok in _REDIR_TOKENS and idx + 1 < len(seg):
            target = seg[idx + 1]
            if target != "/dev/null" and is_protected_path(target, cwd, config) is not None:
                return PreDecision(
                    allowed=False,
                    rule_id="protected-path-write",
                    target=_display_target(target, cwd),
                )

    # Strip redirections and leading env assignments / command wrappers
    cleaned = _strip_redirections(seg)
    while cleaned and _ENV_ASSIGN_RE.match(cleaned[0]):
        cleaned = cleaned[1:]
    while cleaned and Path(cleaned[0]).name in _WRAPPER_COMMANDS:
        verb = Path(cleaned[0]).name
        cleaned = cleaned[1:]
        if verb == "env":
            while cleaned and (_ENV_ASSIGN_RE.match(cleaned[0]) or cleaned[0].startswith("-")):
                cleaned = cleaned[1:]
        elif verb in ("nice", "sudo"):
            while cleaned and cleaned[0].startswith("-"):
                cleaned = cleaned[1:]

    if not cleaned:
        return PreDecision(allowed=True)

    # Check `uv run` / `poetry run` prefix
    if (
        len(cleaned) >= 2
        and Path(cleaned[0]).name in ("uv", "poetry", "pipenv")
        and cleaned[1] == "run"
    ):
        cleaned = cleaned[2:]
        while cleaned and cleaned[0].startswith("-"):
            cleaned = cleaned[1:]
        if not cleaned:
            return PreDecision(allowed=True)

    cmd = Path(cleaned[0]).name
    args = cleaned[1:]

    # 2. Subshell `sh -c "..."` / `bash -c "..."`
    if cmd in _SHELL_NAMES:
        for idx, arg in enumerate(args):
            if arg in ("-c", "-lc", "-ic") and idx + 1 < len(args):
                sub = _check_bash_command(args[idx + 1], cwd, config)
                if not sub.allowed:
                    return sub

    # 3. `sed -i`
    if cmd == "sed":
        return _check_sed(args, cwd, config)

    # 4. `perl -pi` / `perl -i`
    if cmd == "perl":
        return _check_perl(args, cwd, config)

    # 5. `tee`
    if cmd == "tee":
        return _check_operands_protected(
            args, cwd, config, "protected-path-write", {"-a", "-i", "-p"}
        )

    # 6. `truncate`
    if cmd == "truncate":
        return _check_truncate(args, cwd, config)

    # 7. `rm` / `unlink`
    if cmd in ("rm", "unlink"):
        return _check_rm(args, cwd, config, allow_rf_check=(cmd == "rm"))

    # 8. `mv`
    if cmd == "mv":
        return _check_mv(args, cwd, config)

    # 9. `cp` / `install`
    if cmd in ("cp", "install"):
        return _check_cp(args, cwd, config)

    # 10. `git`
    if cmd == "git":
        return _check_git(args, cwd, config)

    # 11. `pytest` / `python -m pytest`
    if cmd in ("pytest", "py.test"):
        return _check_pytest(args)
    if cmd.startswith("python") and len(args) >= 2 and args[0] == "-m" and args[1] == "pytest":
        return _check_pytest(args[2:])

    return PreDecision(allowed=True)


def _strip_redirections(seg: list[str]) -> list[str]:
    out: list[str] = []
    skip_next = False
    for idx, tok in enumerate(seg):
        if skip_next:
            skip_next = False
            continue
        if tok in _REDIR_TOKENS or tok in ("<&", ">&", "<", "<<", "<<<"):
            # Drop optional preceding fd number like `2` before `>`
            if out and _FD_REDIR_PREFIX_RE.match(out[-1]) and idx > 0:
                out.pop()
            skip_next = True
            continue
        out.append(tok)
    return out


def _check_sed(args: list[str], cwd: Path, config: GuardConfig) -> PreDecision:
    in_place = False
    skip_next = False
    operands: list[str] = []
    has_expr_flag = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--in-place" or arg.startswith("--in-place="):
            in_place = True
            continue
        if arg in ("-e", "-f", "--expression", "--file"):
            has_expr_flag = True
            skip_next = True
            continue
        if arg.startswith("-") and arg != "-":
            if "i" in arg[1:]:
                in_place = True
            continue
        operands.append(arg)
    if not in_place:
        return PreDecision(allowed=True)
    # Without -e/-f, the first positional operand is the sed script unless it's a path itself
    candidates = operands if has_expr_flag else operands[1:]
    for op in candidates:
        if is_protected_path(op, cwd, config) is not None:
            return PreDecision(
                allowed=False,
                rule_id="protected-path-write",
                target=_display_target(op, cwd),
            )
    return PreDecision(allowed=True)


def _check_perl(args: list[str], cwd: Path, config: GuardConfig) -> PreDecision:
    in_place = False
    skip_next = False
    operands: list[str] = []
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg in ("-e", "-E"):
            skip_next = True
            continue
        if arg.startswith("-") and arg != "-":
            flags = arg[1:]
            # Ignore -I<dir> include path; catch -i, -pi, -pie, -i.bak
            if "i" in flags and not flags.startswith("I"):
                in_place = True
            continue
        operands.append(arg)
    if not in_place:
        return PreDecision(allowed=True)
    for op in operands:
        if is_protected_path(op, cwd, config) is not None:
            return PreDecision(
                allowed=False,
                rule_id="protected-path-write",
                target=_display_target(op, cwd),
            )
    return PreDecision(allowed=True)


def _check_operands_protected(
    args: list[str], cwd: Path, config: GuardConfig, rule_id: str, flags: set[str]
) -> PreDecision:
    after_dash = False
    for arg in args:
        if not after_dash and arg == "--":
            after_dash = True
            continue
        if not after_dash and arg.startswith("-") and arg in flags:
            continue
        if not after_dash and arg.startswith("-"):
            continue
        if is_protected_path(arg, cwd, config) is not None:
            return PreDecision(allowed=False, rule_id=rule_id, target=_display_target(arg, cwd))
    return PreDecision(allowed=True)


def _check_truncate(args: list[str], cwd: Path, config: GuardConfig) -> PreDecision:
    skip_next = False
    after_dash = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if not after_dash and arg == "--":
            after_dash = True
            continue
        if not after_dash and arg in ("-s", "-r", "--size", "--reference"):
            skip_next = True
            continue
        if not after_dash and arg.startswith("-"):
            continue
        if is_protected_path(arg, cwd, config) is not None:
            return PreDecision(
                allowed=False,
                rule_id="protected-path-write",
                target=_display_target(arg, cwd),
            )
    return PreDecision(allowed=True)


def _check_rm(
    args: list[str], cwd: Path, config: GuardConfig, *, allow_rf_check: bool
) -> PreDecision:
    recursive = False
    force = False
    operands: list[str] = []
    after_dash = False
    for arg in args:
        if not after_dash and arg == "--":
            after_dash = True
            continue
        if not after_dash and arg.startswith("-") and arg != "-":
            low = arg.lower()
            if arg == "--recursive":
                recursive = True
            elif arg == "--force":
                force = True
            elif not arg.startswith("--"):
                if "r" in low:
                    recursive = True
                if "f" in low:
                    force = True
            continue
        operands.append(arg)

    for op in operands:
        if (
            is_protected_path(op, cwd, config) is not None
            or is_protected_dir(op, cwd, config) is not None
        ):
            return PreDecision(
                allowed=False,
                rule_id="protected-path-delete",
                target=_display_target(op, cwd),
            )
        if allow_rf_check and recursive and force and is_outside_cwd(op, cwd):
            return PreDecision(allowed=False, rule_id="rm-rf-outside-cwd", target=op)
    return PreDecision(allowed=True)


def _check_mv(args: list[str], cwd: Path, config: GuardConfig) -> PreDecision:
    operands: list[str] = []
    after_dash = False
    skip_next = False
    target_dir: str | None = None
    for arg in args:
        if skip_next:
            target_dir = arg
            skip_next = False
            continue
        if not after_dash and arg == "--":
            after_dash = True
            continue
        if not after_dash and arg in ("-t", "--target-directory"):
            skip_next = True
            continue
        if not after_dash and arg.startswith("-"):
            continue
        operands.append(arg)

    for op in operands:
        if (
            is_protected_path(op, cwd, config) is not None
            or is_protected_dir(op, cwd, config) is not None
        ):
            return PreDecision(
                allowed=False,
                rule_id="protected-path-write",
                target=_display_target(op, cwd),
            )
    if target_dir is not None:
        for op in operands:
            dest = str(Path(target_dir) / Path(op).name)
            if is_protected_path(dest, cwd, config) is not None:
                return PreDecision(
                    allowed=False,
                    rule_id="protected-path-write",
                    target=_display_target(dest, cwd),
                )
    return PreDecision(allowed=True)


def _check_cp(args: list[str], cwd: Path, config: GuardConfig) -> PreDecision:
    operands: list[str] = []
    after_dash = False
    skip_next = False
    target_dir: str | None = None
    for arg in args:
        if skip_next:
            target_dir = arg
            skip_next = False
            continue
        if not after_dash and arg == "--":
            after_dash = True
            continue
        if not after_dash and arg in ("-t", "--target-directory"):
            skip_next = True
            continue
        if not after_dash and arg.startswith("-"):
            continue
        operands.append(arg)

    if target_dir is not None:
        for op in operands:
            dest = str(Path(target_dir) / Path(op).name)
            if is_protected_path(dest, cwd, config) is not None:
                return PreDecision(
                    allowed=False,
                    rule_id="protected-path-write",
                    target=_display_target(dest, cwd),
                )
        return PreDecision(allowed=True)

    if len(operands) >= 2:
        dest = operands[-1]
        if (
            is_protected_path(dest, cwd, config) is not None
            or is_protected_dir(dest, cwd, config) is not None
        ):
            return PreDecision(
                allowed=False,
                rule_id="protected-path-write",
                target=_display_target(dest, cwd),
            )
        # If dest is an existing directory, check dest/src_name
        dest_path = Path(dest) if Path(dest).is_absolute() else (cwd / dest)
        if dest_path.is_dir():
            for src in operands[:-1]:
                joined = str(Path(dest) / Path(src).name)
                if is_protected_path(joined, cwd, config) is not None:
                    return PreDecision(
                        allowed=False,
                        rule_id="protected-path-write",
                        target=_display_target(joined, cwd),
                    )
    return PreDecision(allowed=True)


def _check_git(args: list[str], cwd: Path, config: GuardConfig) -> PreDecision:
    idx = 0
    while idx < len(args):
        tok = args[idx]
        if tok in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
            idx += 2
            continue
        if tok.startswith("-"):
            idx += 1
            continue
        break
    if idx >= len(args):
        return PreDecision(allowed=True)

    sub = args[idx]
    rest = args[idx + 1 :]

    if sub == "commit":
        for tok in rest:
            short_n = tok.startswith("-") and not tok.startswith("--") and "n" in tok[1:]
            if tok == "--no-verify" or short_n:
                return PreDecision(
                    allowed=False, rule_id="git-no-verify", target="git commit --no-verify"
                )
    elif sub == "push":
        for tok in rest:
            if tok in ("--force", "-f") or tok.startswith("--force="):
                return PreDecision(
                    allowed=False, rule_id="git-push-force", target="git push --force"
                )
    elif sub == "reset":
        if "--hard" in rest:
            return PreDecision(allowed=False, rule_id="git-reset-hard", target="git reset --hard")
    elif sub in ("rm", "mv"):
        for tok in rest:
            if tok == "--" or tok.startswith("-"):
                continue
            if (
                is_protected_path(tok, cwd, config) is not None
                or is_protected_dir(tok, cwd, config) is not None
            ):
                return PreDecision(
                    allowed=False,
                    rule_id="protected-path-delete" if sub == "rm" else "protected-path-write",
                    target=_display_target(tok, cwd),
                )
    elif sub in ("checkout", "restore"):
        if "--" in rest:
            dash_idx = rest.index("--")
            targets = rest[dash_idx + 1 :]
        elif sub == "restore":
            targets = [t for t in rest if not t.startswith("-")]
        else:
            targets = []
        for tok in targets:
            if (
                is_protected_path(tok, cwd, config) is not None
                or is_protected_dir(tok, cwd, config) is not None
            ):
                return PreDecision(
                    allowed=False,
                    rule_id="protected-path-write",
                    target=_display_target(tok, cwd),
                )
    return PreDecision(allowed=True)


def _check_pytest(args: list[str]) -> PreDecision:
    idx = 0
    while idx < len(args):
        tok = args[idx]
        if tok == "--deselect" or tok.startswith("--deselect="):
            return PreDecision(allowed=False, rule_id="pytest-tamper", target="pytest --deselect")
        if tok == "-p" and idx + 1 < len(args):
            if args[idx + 1].startswith("no:"):
                return PreDecision(
                    allowed=False, rule_id="pytest-tamper", target=f"pytest -p {args[idx + 1]}"
                )
            idx += 2
            continue
        if tok.startswith("-pno:"):
            return PreDecision(allowed=False, rule_id="pytest-tamper", target=f"pytest {tok}")
        if tok == "-k" and idx + 1 < len(args):
            if _NOT_WORD_RE.search(args[idx + 1]):
                return PreDecision(
                    allowed=False, rule_id="pytest-tamper", target='pytest -k "not ..."'
                )
            idx += 2
            continue
        if tok.startswith("-k") and len(tok) > 2 and _NOT_WORD_RE.search(tok[2:]):
            return PreDecision(allowed=False, rule_id="pytest-tamper", target='pytest -k "not ..."')
        idx += 1
    return PreDecision(allowed=True)


# ── Session state & PostToolUse logging ──────────────────────────────────────


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise OSError("state path is not a directory")
    if stat.S_IMODE(info.st_mode) & 0o077:
        path.chmod(0o700)


def _ensure_session_head(payload: dict[str, Any]) -> None:
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return
    try:
        state_file = session_state_path(session_id)
        if state_file.exists():
            return
        _ensure_private_dir(state_file.parent)
        cwd = _resolve_cwd(payload.get("cwd"))
        head = _git_head(cwd)
        data = json.dumps({"session_id": session_id, "cwd": str(cwd), "head": head}) + "\n"
        fd = os.open(
            state_file,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.write(fd, data.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        return


def _git_head(cwd: Path) -> str | None:
    git_bin = shutil.which("git") or "git"
    try:
        proc = subprocess.run(  # noqa: S603 - fixed git command
            [git_bin, "rev-parse", "--verify", "--quiet", "HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=_GIT_HEAD_TIMEOUT,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def record_post(payload: dict[str, Any]) -> Path:
    """Append a metadata-only JSON line to agent-log.jsonl (mode 0600)."""
    tool_name = str(payload.get("tool_name") or "")
    session_id = str(payload.get("session_id") or "")
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    cwd = _resolve_cwd(payload.get("cwd"))

    paths = _extract_paths(tool_input)
    digest = _compute_new_sha256(tool_name, tool_input, paths, cwd)

    entry = {
        "timestamp": datetime.now(UTC).isoformat(),
        "session_id": session_id,
        "tool_name": tool_name,
        "paths": paths,
        "sha256": digest,
    }
    return _append_log_entry(entry)


def _extract_paths(tool_input: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for key in ("file_path", "notebook_path", "path"):
        val = tool_input.get(key)
        if isinstance(val, str) and val.strip() and val not in paths:
            paths.append(val)
    return paths


def _compute_new_sha256(
    tool_name: str, tool_input: dict[str, Any], paths: list[str], cwd: Path
) -> str | None:
    if tool_name not in _WRITE_TOOLS:
        return None
    for raw in paths:
        p = Path(raw)
        target = p if p.is_absolute() else (cwd / p)
        try:
            info = target.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_size <= _MAX_HASH_BYTES:
                return hashlib.sha256(target.read_bytes()).hexdigest()
        except OSError:
            pass
    for key in ("content", "new_string", "new_source"):
        val = tool_input.get(key)
        if isinstance(val, str):
            return hashlib.sha256(val.encode("utf-8")).hexdigest()
    return None


def _append_log_entry(entry: dict[str, Any]) -> Path:
    log_path = agent_log_path()
    _ensure_private_dir(log_path.parent)
    line = (json.dumps(entry) + "\n").encode("utf-8")
    fd = os.open(
        log_path,
        os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("agent-log.jsonl is not a regular file")
        if info.st_uid != os.getuid():
            raise OSError("agent-log.jsonl is not owned by current user")
        if stat.S_IMODE(info.st_mode) & 0o077:
            os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            os.write(fd, line)
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
    return log_path


# ── Stop hook ────────────────────────────────────────────────────────────────


def evaluate_stop(payload: dict[str, Any]) -> str | None:
    """Run review from session HEAD and optional test_command; return block reason or None."""
    from veil.agentguard.review import high_findings_summary, review_repo, send_notification

    session_id = payload.get("session_id")
    session_data = (
        _read_session_state(session_id) if isinstance(session_id, str) and session_id else {}
    )
    cwd_raw = payload.get("cwd") or session_data.get("cwd")
    cwd = _resolve_cwd(cwd_raw)
    base_head = session_data.get("head") if isinstance(session_data.get("head"), str) else None

    result = review_repo(cwd, base=base_head)
    config = load_config(cwd)

    test_exit: int | None = None
    if config.test_command:
        test_exit = _run_test_command(config.test_command, cwd)
        _record_test_run(session_id, config.test_command, test_exit, cwd)

    reasons: list[str] = []
    if result.high_count > 0:
        reasons.append(high_findings_summary(result.findings))
    if test_exit is not None and test_exit != 0:
        reasons.append(f"test_command failed (exit {test_exit})")

    if not reasons:
        return None

    full_reason = "veil agent-guard: " + "; ".join(reasons)
    send_notification(full_reason)
    return full_reason


def _read_session_state(session_id: str) -> dict[str, Any]:
    path = session_state_path(session_id)
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return {}


def _run_test_command(command: str, cwd: Path) -> int:
    try:
        proc = subprocess.run(  # noqa: S603 - owner-configured test_command in .veil-agent-guard.toml
            ["/bin/sh", "-c", command],
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=_TEST_CMD_TIMEOUT,
        )
        return proc.returncode
    except subprocess.TimeoutExpired:
        return 124
    except OSError:
        return 127


def _record_test_run(session_id: object, command: str, exit_code: int, cwd: Path) -> None:
    if isinstance(session_id, str) and session_id:
        path = session_state_path(session_id)
        with contextlib.suppress(OSError):
            _ensure_private_dir(path.parent)
            data = _read_session_state(session_id)
            data.update(
                {
                    "session_id": session_id,
                    "cwd": str(cwd),
                    "last_test_command": command,
                    "last_test_exit_code": exit_code,
                    "last_test_timestamp": datetime.now(UTC).isoformat(),
                }
            )
            fd = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            try:
                os.write(fd, (json.dumps(data) + "\n").encode("utf-8"))
            finally:
                os.close(fd)
    with contextlib.suppress(OSError):
        _append_log_entry(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "session_id": session_id if isinstance(session_id, str) else "",
                "tool_name": "stop_test_command",
                "paths": [],
                "sha256": None,
                "exit_code": exit_code,
            }
        )
