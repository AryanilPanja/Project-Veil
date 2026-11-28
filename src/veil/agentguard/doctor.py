"""`veil agent-guard doctor`: check the guard and what Claude Code sends or keeps.

Reads the user, project and local Claude Code settings and the process environment. It
changes nothing. Each line is `ok`, `warn` or `info`; any `warn` gives exit code 1.
"""

import json
import os
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from veil import ui
from veil.agentguard.config import load_config
from veil.exitcodes import ExitCode

_MAX_SETTINGS_BYTES = 1_048_576
_HOOK_MARK = " -m veil agent-guard hook "
_VEIL_HOOK_PREFIX = "veil agent-guard hook "
_HOOK_EVENTS = ("SessionStart", "PreToolUse", "PostToolUse", "Stop")
_NOTICE_FILES = ("CLAUDE.md", "AGENTS.md")
_NOTICE_BEGIN = "<!-- veil:begin -->"
_DEFAULT_CLEANUP_DAYS = 30

# Each turns off one thing Claude Code sends to Anthropic (code.claude.com/docs/en/data-usage).
OPT_OUTS = {
    "DISABLE_TELEMETRY": "usage metrics",
    "DISABLE_ERROR_REPORTING": "error reports",
    "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "session survey (its 'share transcript' step)",
    "DISABLE_FEEDBACK_COMMAND": "/feedback, /bug and /share transcript uploads",
}
_ALL_OFF = "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"
_OTEL_CONTENT = ("OTEL_LOG_USER_PROMPTS", "OTEL_LOG_TOOL_DETAILS", "OTEL_LOG_TOOL_CONTENT")


@dataclass(frozen=True)
class Check:
    level: str  # "ok", "warn" or "info"
    message: str


def _user_config_dir() -> Path:
    value = os.environ.get("CLAUDE_CONFIG_DIR", "").strip()
    return Path(value).expanduser() if value else Path.home() / ".claude"


def _read_json(path: Path) -> dict[str, Any]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_SETTINGS_BYTES:
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _truthy(value: object) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def effective_env(layers: list[dict[str, Any]], environ: dict[str, str]) -> dict[str, str]:
    """Settings `env` blocks in load order (user, project, local), then the process env."""
    merged: dict[str, str] = {}
    for layer in layers:
        env = layer.get("env")
        if isinstance(env, dict):
            merged.update({str(k): str(v) for k, v in env.items()})
    merged.update(environ)
    return merged


def _veil_hook_commands(entries: object) -> list[str]:
    if not isinstance(entries, list):
        return []
    commands: list[str] = []
    for entry in entries:
        hooks = entry.get("hooks") if isinstance(entry, dict) else None
        if not isinstance(hooks, list):
            continue
        for h in hooks:
            if not isinstance(h, dict):
                continue
            cmd = str(h.get("command", ""))
            if _HOOK_MARK in cmd or cmd.startswith(_VEIL_HOOK_PREFIX):
                commands.append(cmd)
    return commands


def _hook_executable_ok(command: str) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if not tokens:
        return False
    exe = tokens[0]
    if "/" not in exe and "\\" not in exe:
        return shutil.which(exe) is not None
    return Path(exe).is_file()


def _table(settings: dict[str, Any], key: str) -> dict[str, Any]:
    value = settings.get(key)
    return value if isinstance(value, dict) else {}


def guard_checks(project: dict[str, Any]) -> list[Check]:
    hooks = _table(project, "hooks")
    by_event = {e: _veil_hook_commands(hooks.get(e)) for e in _HOOK_EVENTS}
    missing = [e for e, cmds in by_event.items() if not cmds]
    broken = [
        e for e, cmds in by_event.items() if cmds and not any(_hook_executable_ok(c) for c in cmds)
    ]
    checks = [
        Check("ok", "agent-guard hooks installed")
        if not missing
        else Check("warn", f"agent-guard hooks missing for {', '.join(missing)}: run install")
    ]
    if broken:
        checks.append(
            Check(
                "warn",
                f"agent-guard hook interpreter missing for {', '.join(broken)}: run install",
            )
        )
    sandbox = _table(project, "sandbox")
    if sandbox.get("enabled") is True and sandbox.get("allowUnsandboxedCommands") is False:
        checks.append(Check("ok", "shell commands run in the OS sandbox with no escape"))
    else:
        checks.append(Check("warn", "the OS sandbox is off or allows unsandboxed commands"))
    if _table(project, "permissions").get("disableBypassPermissionsMode") == "disable":
        checks.append(Check("ok", "bypass-permissions mode is disabled"))
    else:
        checks.append(Check("warn", "the agent can be switched to bypass-permissions mode"))
    return checks


def notice_checks(project_dir: Path, project: dict[str, Any]) -> list[Check]:
    hooks = _table(project, "hooks")
    if not any(_veil_hook_commands(hooks.get(e)) for e in _HOOK_EVENTS):
        return []
    missing_docs: list[str] = []
    for name in _NOTICE_FILES:
        doc = project_dir / name
        try:
            text = doc.read_text(encoding="utf-8") if doc.is_file() and not doc.is_symlink() else ""
        except (OSError, UnicodeDecodeError):
            text = ""
        if _NOTICE_BEGIN not in text:
            missing_docs.append(name)
    if missing_docs:
        return [
            Check(
                "warn",
                f"veil notice block missing in {', '.join(missing_docs)}: run install",
            )
        ]
    return [Check("ok", f"veil notice blocks present ({', '.join(_NOTICE_FILES)})")]


def privacy_checks(env: dict[str, str], cleanup_days: object) -> list[Check]:
    checks: list[Check] = []
    if _truthy(env.get(_ALL_OFF)):
        checks.append(Check("ok", f"{_ALL_OFF} turns off all non-essential traffic"))
    else:
        for name, what in OPT_OUTS.items():
            if _truthy(env.get(name)):
                checks.append(Check("ok", f"{what}: off ({name})"))
            else:
                checks.append(Check("warn", f"{what}: on; set {name}=1"))
    if _truthy(env.get("CLAUDE_CODE_ENABLE_TELEMETRY")):
        exported = [name for name in _OTEL_CONTENT if _truthy(env.get(name))]
        if exported:
            checks.append(
                Check(
                    "warn",
                    f"OpenTelemetry export includes prompt or tool content ({', '.join(exported)})",
                )
            )
        else:
            checks.append(Check("info", "OpenTelemetry export is on, without prompt content"))
    days = cleanup_days if isinstance(cleanup_days, int) else _DEFAULT_CLEANUP_DAYS
    if days > _DEFAULT_CLEANUP_DAYS:
        checks.append(
            Check(
                "warn",
                f"plaintext transcripts in ~/.claude/projects are kept {days} days "
                f"(cleanupPeriodDays); {_DEFAULT_CLEANUP_DAYS} is the default",
            )
        )
    else:
        checks.append(Check("ok", f"local transcripts are kept {days} days"))
    checks.append(
        Check(
            "info",
            "on Free, Pro, Max and Ultra, whether chats train models is set only at "
            "claude.ai/settings/data-privacy-controls",
        )
    )
    return checks


def second_review_checks(project_dir: Path) -> list[Check]:
    from veil.agentguard.second import find_agy

    settings = load_config(project_dir).second_review
    if not settings.enabled:
        return [Check("info", "second-model review is off ([second_review] in the guard config)")]
    agy = find_agy(settings)
    if agy is None:
        return [Check("warn", "second-model review is on but agy is not installed")]
    sent = "diff, requests and final message" if settings.send_task else "diff only"
    return [Check("ok", f"second-model review: {settings.model} via {agy} ({sent})")]


def run_doctor(project_dir: Path) -> int:
    user_dir = _user_config_dir()
    user = _read_json(user_dir / "settings.json")
    project = _read_json(project_dir / ".claude" / "settings.json")
    local = _read_json(project_dir / ".claude" / "settings.local.json")
    env = effective_env([user, project, local], dict(os.environ))
    cleanup: object = _DEFAULT_CLEANUP_DAYS
    for layer in (user, project, local):
        if "cleanupPeriodDays" in layer:
            cleanup = layer["cleanupPeriodDays"]

    checks = (
        guard_checks(project) + notice_checks(project_dir, project) + privacy_checks(env, cleanup)
    )
    checks += second_review_checks(project_dir)
    for check in checks:
        ui.out(f"{check.level:<4}  {check.message}")
    warns = sum(1 for c in checks if c.level == "warn")
    return int(ExitCode.FINDINGS) if warns else int(ExitCode.OK)
