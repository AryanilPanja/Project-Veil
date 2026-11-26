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
    AGENT_NOTICE,
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
_GIT_BIN = shutil.which("git") or "git"
_WRAPPER_COMMANDS = frozenset(
    {"env", "nice", "timeout", "nohup", "xargs", "command", "exec", "sudo", "time", "stdbuf"}
)
_SHELL_NAMES = frozenset({"sh", "bash", "zsh", "dash"})
_WRITE_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
_READ_ONLY_TOOLS = frozenset(
    {"Read", "Glob", "Grep", "LS", "WebSearch", "WebFetch", "TodoWrite", "Task", "Agent"}
)
_SECRET_READ_TOOLS = frozenset({"Read", "Glob", "Grep"})
_PATH_INPUT_FIELDS = ("file_path", "path", "notebook_path", "destination", "target")
_REDIR_TOKENS = frozenset({">", ">>", ">|", "&>", "&>>"})
_BLOCKED_CLIP_KEYRING_CMDS = frozenset(
    {
        "pbpaste",
        "pbcopy",
        "osascript",
        "wl-paste",
        "wl-copy",
        "xclip",
        "xsel",
        "secret-tool",
        "kwallet-query",
    }
)
_BLOCKED_SECURITY_SUBCMDS = frozenset(
    {
        "find-generic-password",
        "find-internet-password",
        "dump-keychain",
        "export",
        "delete-generic-password",
        "unlock-keychain",
    }
)
_BLOCKED_VEIL_SUBCMDS = frozenset(
    {"off", "toggle", "disable", "reverse", "diff", "translate", "audit", "clip", "on"}
)
_BLOCKED_VEIL_TWO_WORD_SUBCMDS = frozenset({("persona", "edit"), ("vault", "review")})
_DESTRUCTIVE_EXEC_VERBS = frozenset(
    {"rm", "unlink", "mv", "truncate", "dd", "ln", "cp", "install", "tee", "sed", "perl"}
)
_NOT_WORD_RE = re.compile(r"\bnot\b")
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
_FD_REDIR_PREFIX_RE = re.compile(r"^[0-9]+$")
_UNEXPANDED_VAR_RE = re.compile(r"\$(?:[A-Za-z_0-9]+|\{[^}]+\})")
_INLINE_QUOTED_RE = re.compile(r"'([^']*)'|\"([^\"]*)\"")
_INLINE_TOKEN_RE = re.compile(r"[A-Za-z0-9_~.${}*?/-]+")


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


def run_session_start() -> int:
    """Claude Code SessionStart hook."""
    out = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": AGENT_NOTICE,
        }
    }
    ui.out(json.dumps(out))
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


def _strip_shell_comments(command: str) -> str:
    """Strip unquoted `#...` shell comments while keeping newlines intact."""
    out: list[str] = []
    i = 0
    n = len(command)
    in_single = False
    in_double = False
    escaped = False
    at_word_start = True

    while i < n:
        ch = command[i]
        if escaped:
            out.append(ch)
            escaped = False
            at_word_start = False
            i += 1
            continue
        if in_single:
            if ch == "'":
                in_single = False
            out.append(ch)
            at_word_start = False
            i += 1
            continue
        if in_double:
            if ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
            out.append(ch)
            at_word_start = False
            i += 1
            continue
        if ch == "\\":
            escaped = True
            out.append(ch)
            at_word_start = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            out.append(ch)
            at_word_start = False
            i += 1
            continue
        if ch == '"':
            in_double = True
            out.append(ch)
            at_word_start = False
            i += 1
            continue
        if ch == "#" and at_word_start:
            while i < n and command[i] not in ("\n", "\r"):
                i += 1
            at_word_start = True
            continue
        out.append(ch)
        at_word_start = ch in (" ", "\t", "\n", "\r", ";", "&", "|", "(", ")")
        i += 1
    return "".join(out)


def _extract_substitutions(command: str) -> list[str]:
    """Extract `$(...)` and backtick command substitutions outside single quotes."""
    subs: list[str] = []
    i = 0
    n = len(command)
    in_single = False
    in_double = False
    escaped = False

    while i < n:
        ch = command[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if ch == "\\":
            escaped = True
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = not in_double
            i += 1
            continue
        if ch == "$" and i + 1 < n and command[i + 1] == "(":
            inner, end_idx = _scan_cmd_subst(command, i + 2)
            if inner.strip():
                subs.append(inner)
            i = end_idx
            continue
        if ch == "`":
            inner, end_idx = _scan_backticks(command, i + 1)
            if inner.strip():
                subs.append(inner)
            i = end_idx
            continue
        i += 1
    return subs


def _scan_cmd_subst(command: str, start: int) -> tuple[str, int]:
    depth = 1
    i = start
    n = len(command)
    in_single = False
    in_double = False
    escaped = False
    while i < n:
        ch = command[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if ch == "\\":
            escaped = True
            i += 1
            continue
        if ch == "'" and not in_double:
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = not in_double
            i += 1
            continue
        if not in_double:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return command[start:i], i + 1
        i += 1
    return command[start:], n


def _scan_backticks(command: str, start: int) -> tuple[str, int]:
    out: list[str] = []
    i = start
    n = len(command)
    while i < n:
        ch = command[i]
        if ch == "\\" and i + 1 < n and command[i + 1] in ("`", "\\", "$"):
            out.append(command[i + 1])
            i += 2
            continue
        if ch == "`":
            return "".join(out), i + 1
        out.append(ch)
        i += 1
    return "".join(out), n


def _tokenize_shell(command: str) -> list[str]:
    stripped = _strip_shell_comments(command)
    try:
        lexer = shlex.shlex(stripped, posix=True, punctuation_chars="();<>|&\n\r")
        lexer.whitespace = " \t"
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        # Fallback for unclosed quotes / complex heredocs: split line-by-line on whitespace
        return _fallback_tokenize(stripped)


def _fallback_tokenize(command: str) -> list[str]:
    tokens: list[str] = []
    for chunk in re.split(r"(\r\n|\n|\r)", command):
        if chunk in ("\r\n", "\n", "\r"):
            tokens.append("\n")
            continue
        for raw in chunk.split():
            parts = re.split(r"(>>|>\|?|&&|\|\||[;|&()])", raw)
            for p in parts:
                if not p:
                    continue
                if len(p) >= 2 and p[0] == p[-1] and p[0] in ("'", '"'):
                    p = p[1:-1]
                tokens.append(p)
    return tokens


def _split_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        if tok in (";", "&&", "||", "|", "&", "(", ")") or (tok and set(tok) <= {"\r", "\n"}):
            if current:
                segments.append(current)
                current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)
    return segments


def _has_glob(arg: str) -> bool:
    return any(ch in arg for ch in "*?[")


def _has_unexpanded_var(arg: str) -> bool:
    return bool(_UNEXPANDED_VAR_RE.search(arg))


def _check_destructive_target(
    target: str,
    cwd: Path,
    config: GuardConfig,
    *,
    has_cd: bool,
    rule_id: str = "protected-path-write",
    check_dir: bool = True,
) -> PreDecision | None:
    if has_cd:
        return PreDecision(allowed=False, rule_id="cd-before-destructive", target=target)
    if _has_unexpanded_var(target):
        return PreDecision(allowed=False, rule_id="unexpanded-var-destructive", target=target)
    if _has_glob(target):
        return PreDecision(allowed=False, rule_id="glob-destructive", target=target)
    if is_protected_path(target, cwd, config) is not None or (
        check_dir and is_protected_dir(target, cwd, config) is not None
    ):
        return PreDecision(allowed=False, rule_id=rule_id, target=_display_target(target, cwd))
    return None


def _check_bash_command(
    command: str, cwd: Path, config: GuardConfig, *, has_cd: bool = False
) -> PreDecision:
    for sub in _extract_substitutions(command):
        sub_decision = _check_bash_command(sub, cwd, config, has_cd=has_cd)
        if not sub_decision.allowed:
            return sub_decision

    tokens = _tokenize_shell(command)
    cd_seen = has_cd
    for seg in _split_segments(tokens):
        decision, is_cd = _check_segment(seg, cwd, config, has_cd=cd_seen)
        if not decision.allowed:
            return decision
        if is_cd:
            cd_seen = True
    return PreDecision(allowed=True)


def _strip_wrappers(
    tokens: list[str], cwd: Path, config: GuardConfig, *, has_cd: bool
) -> tuple[list[str], bool, PreDecision | None]:
    cleaned = list(tokens)
    via_xargs = False
    while cleaned:
        while cleaned and _ENV_ASSIGN_RE.match(cleaned[0]):
            cleaned = cleaned[1:]
        if not cleaned:
            break
        verb = Path(cleaned[0]).name
        if verb in ("uv", "poetry", "pipenv") and len(cleaned) >= 2 and cleaned[1] == "run":
            cleaned = cleaned[2:]
            while cleaned and cleaned[0].startswith("-"):
                cleaned = cleaned[1:]
            continue
        if verb not in _WRAPPER_COMMANDS:
            break
        cleaned = cleaned[1:]
        if verb == "env":
            while cleaned:
                tok = cleaned[0]
                if tok == "--":
                    cleaned = cleaned[1:]
                    break
                if tok in ("-u", "--unset", "-C", "--chdir"):
                    cleaned = cleaned[2:]
                    continue
                if tok in ("-S", "--split-string"):
                    if len(cleaned) >= 2:
                        sub = _check_bash_command(cleaned[1], cwd, config, has_cd=has_cd)
                        if not sub.allowed:
                            return ([], via_xargs, sub)
                    cleaned = cleaned[2:]
                    continue
                if tok.startswith("--split-string="):
                    sub = _check_bash_command(tok.split("=", 1)[1], cwd, config, has_cd=has_cd)
                    if not sub.allowed:
                        return ([], via_xargs, sub)
                    cleaned = cleaned[1:]
                    continue
                if _ENV_ASSIGN_RE.match(tok) or tok.startswith("-"):
                    cleaned = cleaned[1:]
                    continue
                break
        elif verb == "nice":
            while cleaned and cleaned[0].startswith("-"):
                tok = cleaned[0]
                if tok == "--":
                    cleaned = cleaned[1:]
                    break
                cleaned = cleaned[2:] if tok in ("-n", "--adjustment") else cleaned[1:]
        elif verb == "timeout":
            while cleaned and cleaned[0].startswith("-"):
                tok = cleaned[0]
                if tok == "--":
                    cleaned = cleaned[1:]
                    break
                cleaned = (
                    cleaned[2:] if tok in ("-k", "--kill-after", "-s", "--signal") else cleaned[1:]
                )
            if cleaned:
                cleaned = cleaned[1:]  # skip DURATION
        elif verb == "stdbuf":
            while cleaned and cleaned[0].startswith("-"):
                tok = cleaned[0]
                if tok == "--":
                    cleaned = cleaned[1:]
                    break
                cleaned = (
                    cleaned[2:]
                    if tok in ("-i", "--input", "-o", "--output", "-e", "--error")
                    else cleaned[1:]
                )
        elif verb == "xargs":
            via_xargs = True
            xargs_arg_opts = {
                "-a",
                "--arg-file",
                "-d",
                "--delimiter",
                "-E",
                "--eof",
                "-I",
                "-L",
                "-l",
                "-n",
                "--max-args",
                "-P",
                "--max-procs",
                "-s",
                "--max-chars",
                "-J",
                "-R",
                "-S",
            }
            while cleaned and cleaned[0].startswith("-"):
                tok = cleaned[0]
                if tok == "--":
                    cleaned = cleaned[1:]
                    break
                cleaned = cleaned[2:] if tok in xargs_arg_opts else cleaned[1:]
        elif verb == "sudo":
            sudo_arg_opts = {
                "-u",
                "-g",
                "-C",
                "-h",
                "-p",
                "-r",
                "-t",
                "-U",
                "-T",
                "-D",
                "-R",
                "--user",
                "--group",
                "--prompt",
            }
            while cleaned and cleaned[0].startswith("-"):
                tok = cleaned[0]
                if tok == "--":
                    cleaned = cleaned[1:]
                    break
                cleaned = cleaned[2:] if tok in sudo_arg_opts else cleaned[1:]
        elif verb == "exec":
            while cleaned and cleaned[0].startswith("-"):
                tok = cleaned[0]
                if tok == "--":
                    cleaned = cleaned[1:]
                    break
                cleaned = cleaned[2:] if tok == "-a" else cleaned[1:]
        elif verb == "time":
            while cleaned and cleaned[0].startswith("-"):
                tok = cleaned[0]
                if tok == "--":
                    cleaned = cleaned[1:]
                    break
                cleaned = cleaned[2:] if tok in ("-f", "-o") else cleaned[1:]
        elif verb == "command":
            query_only = False
            while cleaned and cleaned[0].startswith("-"):
                tok = cleaned[0]
                if tok == "--":
                    cleaned = cleaned[1:]
                    break
                if tok in ("-v", "-V"):
                    query_only = True
                cleaned = cleaned[1:]
            if query_only:
                return ([], via_xargs, PreDecision(allowed=True))
        elif verb == "nohup":
            while cleaned and cleaned[0].startswith("-"):
                tok = cleaned[0]
                if tok == "--":
                    cleaned = cleaned[1:]
                    break
                cleaned = cleaned[1:]
    return (cleaned, via_xargs, None)


def _check_secret_tokens(seg: list[str], cwd: Path) -> PreDecision | None:
    for tok in seg:
        candidates = [tok]
        if "=" in tok and not tok.startswith("="):
            candidates.append(tok.split("=", 1)[1])
        for cand in candidates:
            if cand and is_protected_secret_path(cand, cwd) is not None:
                return PreDecision(
                    allowed=False,
                    rule_id="protected-secret-path",
                    target=_display_target(cand, cwd),
                )
    return None


def _check_segment(
    seg: list[str], cwd: Path, config: GuardConfig, *, has_cd: bool = False
) -> tuple[PreDecision, bool]:
    # 0. Any reference to veil secret paths (read or write) in Bash is denied
    sec_hit = _check_secret_tokens(seg, cwd)
    if sec_hit is not None:
        return (sec_hit, False)

    # 1. Check redirections (`>`, `>>`, `>|`, `&>`, `&>>`) anywhere in segment
    for idx, tok in enumerate(seg):
        if tok in _REDIR_TOKENS and idx + 1 < len(seg):
            target = seg[idx + 1]
            if target != "/dev/null":
                hit = _check_destructive_target(target, cwd, config, has_cd=has_cd)
                if hit is not None:
                    return (hit, False)

    # Strip redirections and command wrappers
    stripped_redir = _strip_redirections(seg)
    cleaned, via_xargs, early = _strip_wrappers(stripped_redir, cwd, config, has_cd=has_cd)
    if early is not None:
        return (early, False)
    if not cleaned:
        return (PreDecision(allowed=True), False)

    cmd = Path(cleaned[0]).name
    args = cleaned[1:]

    if cmd in ("cd", "pushd"):
        return (PreDecision(allowed=True), True)

    # 2. Protected clipboard / keychain / veil / service commands (quotes already stripped by shlex)
    cmd_hit = _check_blocked_commands(cmd, args)
    if cmd_hit is not None:
        return (cmd_hit, False)

    # 3. Subshell `sh -c "..."` / `bash -ec "..."`
    if cmd in _SHELL_NAMES:
        for idx, arg in enumerate(args):
            is_c_flag = arg in ("-c", "--command") or (
                arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]
            )
            if is_c_flag and idx + 1 < len(args):
                sub = _check_bash_command(args[idx + 1], cwd, config, has_cd=has_cd)
                if not sub.allowed:
                    return (sub, False)

    # 4. Inline interpreter code (`python -c`, `node -e`, `perl -e`, `ruby -e`)
    inline_hit = _check_inline_interpreter(cmd, args, cwd, config)
    if inline_hit is not None:
        return (inline_hit, False)

    # 5. `sed -i`
    if cmd == "sed":
        return (_check_sed(args, cwd, config, has_cd=has_cd, via_xargs=via_xargs), False)

    # 6. `perl -pi` / `perl -i`
    if cmd == "perl":
        return (_check_perl(args, cwd, config, has_cd=has_cd, via_xargs=via_xargs), False)

    # 7. `tee`
    if cmd == "tee":
        return (
            _check_operands_protected(
                args,
                cwd,
                config,
                "protected-path-write",
                {"-a", "-i", "-p"},
                has_cd=has_cd,
                via_xargs=via_xargs,
            ),
            False,
        )

    # 8. `truncate`
    if cmd == "truncate":
        return (_check_truncate(args, cwd, config, has_cd=has_cd, via_xargs=via_xargs), False)

    # 9. `rm` / `unlink`
    if cmd in ("rm", "unlink"):
        return (
            _check_rm(
                args,
                cwd,
                config,
                allow_rf_check=(cmd == "rm"),
                has_cd=has_cd,
                via_xargs=via_xargs,
            ),
            False,
        )

    # 10. `mv`
    if cmd == "mv":
        return (_check_mv(args, cwd, config, has_cd=has_cd, via_xargs=via_xargs), False)

    # 11. `cp` / `install`
    if cmd in ("cp", "install"):
        return (_check_cp(args, cwd, config, has_cd=has_cd, via_xargs=via_xargs), False)

    # 12. `dd`
    if cmd == "dd":
        return (_check_dd(args, cwd, config, has_cd=has_cd), False)

    # 13. `ln`
    if cmd == "ln":
        return (_check_ln(args, cwd, config, has_cd=has_cd, via_xargs=via_xargs), False)

    # 14. `find`
    if cmd == "find":
        return (_check_find(args, cwd, config, has_cd=has_cd, via_xargs=via_xargs), False)

    # 15. `git`
    if cmd == "git":
        return (_check_git(args, cwd, config), False)

    # 16. `pytest` / `python -m pytest`
    if cmd in ("pytest", "py.test"):
        return (_check_pytest(args, cwd), False)
    if cmd.startswith("python") and len(args) >= 2 and args[0] == "-m" and args[1] == "pytest":
        return (_check_pytest(args[2:], cwd), False)

    return (PreDecision(allowed=True), False)


def _check_blocked_commands(cmd: str, args: list[str]) -> PreDecision | None:
    if cmd in _BLOCKED_CLIP_KEYRING_CMDS:
        return PreDecision(allowed=False, rule_id="protected-command", target=cmd)
    if cmd == "security":
        for arg in args:
            if arg in _BLOCKED_SECURITY_SUBCMDS:
                return PreDecision(
                    allowed=False, rule_id="protected-command", target=f"security {arg}"
                )
    if cmd == "veil" and args:
        if args[0] in _BLOCKED_VEIL_SUBCMDS:
            return PreDecision(allowed=False, rule_id="protected-command", target=f"veil {args[0]}")
        if len(args) >= 2 and (args[0], args[1]) in _BLOCKED_VEIL_TWO_WORD_SUBCMDS:
            return PreDecision(
                allowed=False, rule_id="protected-command", target=f"veil {args[0]} {args[1]}"
            )
    if cmd == "launchctl" and any("veil" in a or "io.github.veil" in a for a in args):
        return PreDecision(allowed=False, rule_id="protected-command", target="launchctl veil")
    if cmd == "systemctl" and "--user" in args and any("veil" in a for a in args):
        return PreDecision(
            allowed=False, rule_id="protected-command", target="systemctl --user veil"
        )
    return None


def _check_inline_interpreter(
    cmd: str, args: list[str], cwd: Path, config: GuardConfig
) -> PreDecision | None:
    snippets: list[str] = []
    idx = 0
    if cmd.startswith("python"):
        while idx < len(args):
            arg = args[idx]
            if arg == "-c" and idx + 1 < len(args):
                snippets.append(args[idx + 1])
                idx += 2
                continue
            if arg.startswith("-c") and len(arg) > 2:
                snippets.append(arg[2:])
            idx += 1
    elif cmd in ("node", "nodejs"):
        while idx < len(args):
            arg = args[idx]
            if arg in ("-e", "--eval", "-p", "--print") and idx + 1 < len(args):
                snippets.append(args[idx + 1])
                idx += 2
                continue
            if arg.startswith("--eval="):
                snippets.append(arg.split("=", 1)[1])
            idx += 1
    elif cmd == "perl":
        while idx < len(args):
            arg = args[idx]
            if arg in ("-e", "-E") and idx + 1 < len(args):
                snippets.append(args[idx + 1])
                idx += 2
                continue
            idx += 1
    elif cmd == "ruby":
        while idx < len(args):
            arg = args[idx]
            if arg == "-e" and idx + 1 < len(args):
                snippets.append(args[idx + 1])
                idx += 2
                continue
            idx += 1
    else:
        return None

    for code in snippets:
        candidates: list[str] = []
        for m in _INLINE_QUOTED_RE.finditer(code):
            val = m.group(1) if m.group(1) is not None else m.group(2)
            if val:
                candidates.append(val)
        for m in _INLINE_TOKEN_RE.finditer(code):
            candidates.append(m.group(0))
        for cand in candidates:
            if (
                is_protected_path(cand, cwd, config) is not None
                or is_protected_dir(cand, cwd, config) is not None
            ):
                return PreDecision(
                    allowed=False,
                    rule_id="inline-code-protected-path",
                    target=_display_target(cand, cwd),
                )
    return None


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


def _check_sed(
    args: list[str],
    cwd: Path,
    config: GuardConfig,
    *,
    has_cd: bool = False,
    via_xargs: bool = False,
) -> PreDecision:
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
    if via_xargs and (not candidates or any("{}" in op for op in candidates)):
        return PreDecision(allowed=False, rule_id="xargs-destructive", target="xargs sed -i")
    for op in candidates:
        hit = _check_destructive_target(op, cwd, config, has_cd=has_cd, check_dir=False)
        if hit is not None:
            return hit
    return PreDecision(allowed=True)


def _check_perl(
    args: list[str],
    cwd: Path,
    config: GuardConfig,
    *,
    has_cd: bool = False,
    via_xargs: bool = False,
) -> PreDecision:
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
    if via_xargs and (not operands or any("{}" in op for op in operands)):
        return PreDecision(allowed=False, rule_id="xargs-destructive", target="xargs perl -i")
    for op in operands:
        hit = _check_destructive_target(op, cwd, config, has_cd=has_cd, check_dir=False)
        if hit is not None:
            return hit
    return PreDecision(allowed=True)


def _check_operands_protected(
    args: list[str],
    cwd: Path,
    config: GuardConfig,
    rule_id: str,
    flags: set[str],
    *,
    has_cd: bool = False,
    via_xargs: bool = False,
) -> PreDecision:
    after_dash = False
    operands: list[str] = []
    for arg in args:
        if not after_dash and arg == "--":
            after_dash = True
            continue
        if not after_dash and arg.startswith("-") and arg in flags:
            continue
        if not after_dash and arg.startswith("-"):
            continue
        operands.append(arg)
    if via_xargs and (not operands or any("{}" in op for op in operands)):
        return PreDecision(allowed=False, rule_id="xargs-destructive", target="xargs tee")
    for op in operands:
        hit = _check_destructive_target(op, cwd, config, has_cd=has_cd, rule_id=rule_id)
        if hit is not None:
            return hit
    return PreDecision(allowed=True)


def _check_truncate(
    args: list[str],
    cwd: Path,
    config: GuardConfig,
    *,
    has_cd: bool = False,
    via_xargs: bool = False,
) -> PreDecision:
    skip_next = False
    after_dash = False
    operands: list[str] = []
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
        operands.append(arg)
    if via_xargs and (not operands or any("{}" in op for op in operands)):
        return PreDecision(allowed=False, rule_id="xargs-destructive", target="xargs truncate")
    for op in operands:
        hit = _check_destructive_target(op, cwd, config, has_cd=has_cd)
        if hit is not None:
            return hit
    return PreDecision(allowed=True)


def _check_rm(
    args: list[str],
    cwd: Path,
    config: GuardConfig,
    *,
    allow_rf_check: bool,
    has_cd: bool = False,
    via_xargs: bool = False,
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

    if via_xargs and (not operands or any("{}" in op for op in operands)):
        return PreDecision(allowed=False, rule_id="xargs-destructive", target="xargs rm")

    has_tests_dir = (cwd / "tests").is_dir()
    for op in operands:
        if (
            allow_rf_check
            and recursive
            and force
            and has_tests_dir
            and (op in (".", "./") or _has_glob(op))
        ):
            return PreDecision(allowed=False, rule_id="rm-rf-tests-dir", target=op)
        hit = _check_destructive_target(
            op, cwd, config, has_cd=has_cd, rule_id="protected-path-delete"
        )
        if hit is not None:
            return hit
        if allow_rf_check and recursive and force and is_outside_cwd(op, cwd):
            return PreDecision(allowed=False, rule_id="rm-rf-outside-cwd", target=op)
    return PreDecision(allowed=True)


def _check_mv(
    args: list[str],
    cwd: Path,
    config: GuardConfig,
    *,
    has_cd: bool = False,
    via_xargs: bool = False,
) -> PreDecision:
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

    if via_xargs and (not operands or any("{}" in op for op in operands)):
        return PreDecision(allowed=False, rule_id="xargs-destructive", target="xargs mv")

    for op in operands:
        hit = _check_destructive_target(op, cwd, config, has_cd=has_cd)
        if hit is not None:
            return hit
    if target_dir is not None:
        hit = _check_destructive_target(target_dir, cwd, config, has_cd=has_cd)
        if hit is not None:
            return hit
        for op in operands:
            dest = str(Path(target_dir) / Path(op).name)
            hit = _check_destructive_target(dest, cwd, config, has_cd=has_cd)
            if hit is not None:
                return hit
    return PreDecision(allowed=True)


def _check_cp(
    args: list[str],
    cwd: Path,
    config: GuardConfig,
    *,
    has_cd: bool = False,
    via_xargs: bool = False,
) -> PreDecision:
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

    if via_xargs and (not operands or any("{}" in op for op in operands)):
        return PreDecision(allowed=False, rule_id="xargs-destructive", target="xargs cp")

    if target_dir is not None:
        hit = _check_destructive_target(target_dir, cwd, config, has_cd=has_cd)
        if hit is not None:
            return hit
        for op in operands:
            dest = str(Path(target_dir) / Path(op).name)
            hit = _check_destructive_target(dest, cwd, config, has_cd=has_cd)
            if hit is not None:
                return hit
        return PreDecision(allowed=True)

    if len(operands) >= 2:
        dest = operands[-1]
        hit = _check_destructive_target(dest, cwd, config, has_cd=has_cd)
        if hit is not None:
            return hit
        # If dest is an existing directory, check dest/src_name
        dest_path = Path(dest) if Path(dest).is_absolute() else (cwd / dest)
        if dest_path.is_dir():
            for src in operands[:-1]:
                joined = str(Path(dest) / Path(src).name)
                hit = _check_destructive_target(joined, cwd, config, has_cd=has_cd)
                if hit is not None:
                    return hit
    return PreDecision(allowed=True)


def _check_dd(
    args: list[str], cwd: Path, config: GuardConfig, *, has_cd: bool = False
) -> PreDecision:
    for arg in args:
        if arg.startswith("of="):
            target = arg[3:]
            if target and target != "/dev/null":
                hit = _check_destructive_target(target, cwd, config, has_cd=has_cd)
                if hit is not None:
                    return hit
    return PreDecision(allowed=True)


def _check_ln(
    args: list[str],
    cwd: Path,
    config: GuardConfig,
    *,
    has_cd: bool = False,
    via_xargs: bool = False,
) -> PreDecision:
    force = False
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
        if not after_dash and arg in ("-S", "--suffix"):
            skip_next = True
            continue
        if not after_dash and arg.startswith("-") and arg != "-":
            if arg == "--force" or (not arg.startswith("--") and "f" in arg[1:]):
                force = True
            continue
        operands.append(arg)

    if via_xargs and (not operands or any("{}" in op for op in operands)):
        return PreDecision(allowed=False, rule_id="xargs-destructive", target="xargs ln")

    if target_dir is not None:
        hit = _check_destructive_target(target_dir, cwd, config, has_cd=has_cd and force)
        if hit is not None:
            return hit
        for op in operands:
            dest = str(Path(target_dir) / Path(op).name)
            hit = _check_destructive_target(dest, cwd, config, has_cd=has_cd and force)
            if hit is not None:
                return hit
        return PreDecision(allowed=True)

    if operands:
        dest = operands[-1]
        if force:
            hit = _check_destructive_target(dest, cwd, config, has_cd=has_cd)
            if hit is not None:
                return hit
        elif (
            is_protected_path(dest, cwd, config) is not None
            or is_protected_dir(dest, cwd, config) is not None
        ):
            return PreDecision(
                allowed=False, rule_id="protected-path-write", target=_display_target(dest, cwd)
            )
    return PreDecision(allowed=True)


def _check_find(
    args: list[str],
    cwd: Path,
    config: GuardConfig,
    *,
    has_cd: bool = False,
    via_xargs: bool = False,
) -> PreDecision:
    search_paths: list[str] = []
    idx = 0
    while idx < len(args):
        tok = args[idx]
        if tok.startswith("-") or tok in ("!", "(", ")"):
            break
        search_paths.append(tok)
        idx += 1

    has_delete = False
    has_destructive_exec = False
    while idx < len(args):
        tok = args[idx]
        if tok == "-delete":
            has_delete = True
            idx += 1
            continue
        if tok in ("-exec", "-execdir", "-ok", "-okdir"):
            sub_tokens: list[str] = []
            idx += 1
            while idx < len(args) and args[idx] not in (";", "+"):
                sub_tokens.append(args[idx])
                idx += 1
            if sub_tokens:
                sub_dec, _ = _check_segment(sub_tokens, cwd, config, has_cd=has_cd)
                if not sub_dec.allowed:
                    return sub_dec
                sub_verb = Path(sub_tokens[0]).name
                if sub_verb in _DESTRUCTIVE_EXEC_VERBS or sub_verb in _SHELL_NAMES:
                    has_destructive_exec = True
            idx += 1
            continue
        idx += 1

    if not (has_delete or has_destructive_exec):
        return PreDecision(allowed=True)

    if via_xargs:
        return PreDecision(allowed=False, rule_id="xargs-destructive", target="xargs find")
    if has_cd:
        return PreDecision(allowed=False, rule_id="cd-before-destructive", target="find -delete")
    if not search_paths:
        return PreDecision(
            allowed=False, rule_id="protected-path-delete", target="find -delete (cwd)"
        )
    for sp in search_paths:
        hit = _check_destructive_target(
            sp, cwd, config, has_cd=has_cd, rule_id="protected-path-delete"
        )
        if hit is not None:
            return hit
    return PreDecision(allowed=True)


def _check_git(args: list[str], cwd: Path, config: GuardConfig) -> PreDecision:
    idx = 0
    git_cwd = cwd
    while idx < len(args):
        tok = args[idx]
        if tok == "-C" and idx + 1 < len(args):
            git_dir_arg = args[idx + 1]
            p = Path(git_dir_arg)
            git_cwd = p if p.is_absolute() else (git_cwd / p)
            idx += 2
            continue
        if tok in ("-c", "--git-dir", "--work-tree", "--namespace"):
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
        after_dash = False
        for tok in rest:
            if tok == "--":
                after_dash = True
                continue
            if not after_dash:
                short_f = tok.startswith("-") and not tok.startswith("--") and "f" in tok[1:]
                if tok.startswith("--force") or short_f:
                    return PreDecision(
                        allowed=False, rule_id="git-push-force", target="git push --force"
                    )
            if not tok.startswith("-") and tok.startswith("+"):
                return PreDecision(
                    allowed=False, rule_id="git-push-force", target=f"git push {tok}"
                )
    elif sub == "reset":
        if "--hard" in rest:
            return PreDecision(allowed=False, rule_id="git-reset-hard", target="git reset --hard")
    elif sub == "clean":
        for tok in rest:
            if tok == "--":
                break
            short_f = tok.startswith("-") and not tok.startswith("--") and "f" in tok[1:]
            if tok == "--force" or short_f:
                return PreDecision(allowed=False, rule_id="git-clean-force", target="git clean -f")
    elif sub in ("rm", "mv"):
        for tok in rest:
            if tok == "--" or tok.startswith("-"):
                continue
            if (
                is_protected_path(tok, git_cwd, config) is not None
                or is_protected_dir(tok, git_cwd, config) is not None
            ):
                return PreDecision(
                    allowed=False,
                    rule_id="protected-path-delete" if sub == "rm" else "protected-path-write",
                    target=_display_target(tok, git_cwd),
                )
    elif sub in ("checkout", "restore"):
        if "--" in rest:
            dash_idx = rest.index("--")
            targets = rest[dash_idx + 1 :]
        elif sub == "restore":
            targets = []
            skip_next = False
            for t in rest:
                if skip_next:
                    skip_next = False
                    continue
                if t in ("-s", "--source"):
                    skip_next = True
                    continue
                if t.startswith("-"):
                    continue
                targets.append(t)
        else:
            targets = []
            skip_next = False
            for t in rest:
                if skip_next:
                    skip_next = False
                    continue
                if t in ("-b", "-B", "--orphan", "-t", "--track"):
                    skip_next = True
                    continue
                if t.startswith("-"):
                    continue
                targets.append(t)
        for tok in targets:
            if (
                is_protected_path(tok, git_cwd, config) is not None
                or is_protected_dir(tok, git_cwd, config) is not None
            ):
                return PreDecision(
                    allowed=False,
                    rule_id="protected-path-write",
                    target=_display_target(tok, git_cwd),
                )
    return PreDecision(allowed=True)


_TEST_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(test_[A-Za-z0-9_]+)\b")
_TEST_CLASS_RE = re.compile(r"^\s*class\s+(Test[A-Za-z0-9_]+)\b")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _git_removed_test_names(cwd: Path) -> set[str]:
    base_cmd = [
        _GIT_BIN,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "--no-pager",
        "diff",
        "-U0",
    ]
    proc: subprocess.CompletedProcess[str] | None = None
    for ref in ("HEAD", "--cached"):
        try:
            res = subprocess.run(  # noqa: S603 - fixed git command
                [*base_cmd, ref],
                cwd=cwd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=_GIT_HEAD_TIMEOUT,
            )
        except (OSError, subprocess.TimeoutExpired):
            return set()
        if res.returncode == 0:
            proc = res
            break
    if proc is None or not proc.stdout:
        return set()

    removed: set[str] = set()
    added: set[str] = set()
    for line in proc.stdout.splitlines():
        if line.startswith("-") and not line.startswith("---"):
            body = line[1:]
            if m := (_TEST_DEF_RE.match(body) or _TEST_CLASS_RE.match(body)):
                removed.add(m.group(1))
        elif line.startswith("+") and not line.startswith("+++"):
            body = line[1:]
            if m := (_TEST_DEF_RE.match(body) or _TEST_CLASS_RE.match(body)):
                added.add(m.group(1))
    return removed - added


def _check_pytest(args: list[str], cwd: Path) -> PreDecision:
    idx = 0
    k_exprs: list[str] = []
    while idx < len(args):
        tok = args[idx]
        if tok == "--deselect" or tok.startswith("--deselect="):
            return PreDecision(allowed=False, rule_id="pytest-tamper", target="pytest --deselect")
        if tok == "-k" and idx + 1 < len(args):
            k_exprs.append(args[idx + 1])
            idx += 2
            continue
        if tok.startswith("-k="):
            k_exprs.append(tok[3:])
        elif tok.startswith("-k") and len(tok) > 2:
            k_exprs.append(tok[2:])
        idx += 1

    not_exprs = [expr for expr in k_exprs if _NOT_WORD_RE.search(expr)]
    if not_exprs:
        removed_tests = _git_removed_test_names(cwd)
        if removed_tests:
            for expr in not_exprs:
                idents = set(_IDENT_RE.findall(expr)) - {"not", "and", "or"}
                if idents & removed_tests:
                    return PreDecision(
                        allowed=False, rule_id="pytest-tamper", target='pytest -k "not ..."'
                    )
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
    try:
        proc = subprocess.run(  # noqa: S603 - fixed git command
            [
                _GIT_BIN,
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "--no-pager",
                "rev-parse",
                "--verify",
                "--quiet",
                "HEAD",
            ],
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
