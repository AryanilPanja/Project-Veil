"""`veil agent-guard install`: merge Claude Code guard settings and hooks safely."""

import json
import stat
from copy import deepcopy
from pathlib import Path
from typing import Any

from veil import fsutil, ui
from veil.agentguard.config import AGENT_NOTICE
from veil.errors import StorageError, UnsafeEnvironment, VeilError
from veil.exitcodes import ExitCode

_TEMPLATE_PATH = Path(__file__).with_name("claude-settings.json")
_MAX_SETTINGS_BYTES = 1_048_576
_VEIL_HOOK_PREFIX = "veil agent-guard hook "
_NOTICE_BEGIN = "<!-- veil:begin -->"
_NOTICE_END = "<!-- veil:end -->"
_NOTICE_FILES = ("CLAUDE.md", "AGENTS.md")


def load_template() -> dict[str, Any]:
    """Load the packaged claude-settings.json template."""
    return json.loads(_TEMPLATE_PATH.read_text(encoding="utf-8"))


def build_hooks(*, warn: bool = False) -> dict[str, list[dict[str, Any]]]:
    """Build the Claude Code hooks block for SessionStart, PreToolUse, PostToolUse, and Stop."""
    pre_cmd = f"{_VEIL_HOOK_PREFIX}pre --warn" if warn else f"{_VEIL_HOOK_PREFIX}pre"
    return {
        "SessionStart": [
            {
                "hooks": [{"type": "command", "command": f"{_VEIL_HOOK_PREFIX}session-start"}],
            }
        ],
        "PreToolUse": [
            {
                "matcher": ".*",
                "hooks": [{"type": "command", "command": pre_cmd}],
            }
        ],
        "PostToolUse": [
            {
                "matcher": "",
                "hooks": [{"type": "command", "command": f"{_VEIL_HOOK_PREFIX}post"}],
            }
        ],
        "Stop": [
            {
                "hooks": [{"type": "command", "command": f"{_VEIL_HOOK_PREFIX}stop"}],
            }
        ],
    }


def _union_lists(existing: list[Any], incoming: list[Any]) -> list[Any]:
    result = list(existing)
    for item in incoming:
        if item not in result:
            result.append(deepcopy(item))
    return result


def _is_veil_hook_entry(entry: object) -> bool:
    if not isinstance(entry, dict):
        return False
    inner = entry.get("hooks")
    if not isinstance(inner, list):
        return False
    return any(
        isinstance(h, dict)
        and isinstance(h.get("command"), str)
        and h["command"].startswith(_VEIL_HOOK_PREFIX)
        for h in inner
    )


def _merge_hooks(
    existing_hooks: dict[str, Any], desired_hooks: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    merged = deepcopy(existing_hooks)
    for event, entries in desired_hooks.items():
        current = merged.get(event)
        if not isinstance(current, list):
            merged[event] = deepcopy(entries)
            continue
        kept = [item for item in current if not _is_veil_hook_entry(item)]
        for entry in entries:
            if entry not in kept:
                kept.append(deepcopy(entry))
        merged[event] = kept
    return merged


def _deep_merge(existing: dict[str, Any], template: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(existing)
    for key, tmpl_val in template.items():
        if key not in merged:
            merged[key] = deepcopy(tmpl_val)
            continue
        cur_val = merged[key]
        if isinstance(cur_val, dict) and isinstance(tmpl_val, dict):
            merged[key] = _deep_merge(cur_val, tmpl_val)
        elif isinstance(cur_val, list) and isinstance(tmpl_val, list):
            merged[key] = _union_lists(cur_val, tmpl_val)
        else:
            merged[key] = deepcopy(tmpl_val)
    return merged


def merge_settings(
    existing: dict[str, Any], template: dict[str, Any], *, warn: bool = False
) -> dict[str, Any]:
    """Merge `template` and agent-guard hooks into `existing`, keeping existing keys & arrays."""
    merged = _deep_merge(existing, template)
    existing_hooks = merged.get("hooks")
    if not isinstance(existing_hooks, dict):
        existing_hooks = {}
    merged["hooks"] = _merge_hooks(existing_hooks, build_hooks(warn=warn))
    return merged


def _read_existing_settings(settings_path: Path) -> dict[str, Any]:
    try:
        info = settings_path.lstat()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise StorageError("cannot inspect existing .claude/settings.json") from exc
    if settings_path.is_symlink():
        raise UnsafeEnvironment(".claude/settings.json is a symbolic link; refusing to use it")
    if info.st_size > _MAX_SETTINGS_BYTES:
        raise StorageError("existing .claude/settings.json is too large")
    try:
        raw = settings_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise StorageError("cannot read existing .claude/settings.json") from exc
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        raise VeilError(
            "existing .claude/settings.json is not valid JSON", exit_code=ExitCode.USAGE
        ) from None
    if not isinstance(parsed, dict):
        raise VeilError(
            "existing .claude/settings.json must contain a JSON object", exit_code=ExitCode.USAGE
        )
    return parsed


def _read_doc_file(doc_path: Path, name: str) -> str | None:
    try:
        info = doc_path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StorageError(f"cannot inspect {name}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise UnsafeEnvironment(f"{name} is not a regular file; refusing to modify it")
    if info.st_size > _MAX_SETTINGS_BYTES:
        raise StorageError(f"{name} is too large")
    try:
        return doc_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise StorageError(f"cannot read {name}") from exc


def _upsert_notice_text(existing: str) -> str:
    block = f"{_NOTICE_BEGIN}\n{AGENT_NOTICE}\n{_NOTICE_END}"
    begin_idx = existing.find(_NOTICE_BEGIN)
    if begin_idx != -1:
        end_idx = existing.find(_NOTICE_END, begin_idx + len(_NOTICE_BEGIN))
        if end_idx != -1:
            return existing[:begin_idx] + block + existing[end_idx + len(_NOTICE_END) :]
    if not existing.strip():
        return f"{block}\n"
    return f"{existing.rstrip('\n')}\n\n{block}\n"


def _remove_notice_text(existing: str) -> str | None:
    begin_idx = existing.find(_NOTICE_BEGIN)
    if begin_idx == -1:
        return None
    end_idx = existing.find(_NOTICE_END, begin_idx + len(_NOTICE_BEGIN))
    if end_idx == -1:
        return None
    before = existing[:begin_idx]
    after = existing[end_idx + len(_NOTICE_END) :]
    if not before.strip() and not after.strip():
        return ""
    if not after.strip():
        return f"{before.rstrip('\n')}\n"
    if not before.strip():
        return after.lstrip("\n")
    return f"{before.rstrip('\n')}\n\n{after.lstrip('\n')}"


def _upsert_notice_blocks(project_dir: Path) -> None:
    for name in _NOTICE_FILES:
        doc_path = project_dir / name
        existing = _read_doc_file(doc_path, name) or ""
        updated = _upsert_notice_text(existing)
        fsutil.atomic_write(doc_path, updated.encode("utf-8"), what=f"the {name} file")


def _remove_notice_blocks(project_dir: Path) -> None:
    for name in _NOTICE_FILES:
        doc_path = project_dir / name
        existing = _read_doc_file(doc_path, name)
        if existing is None:
            continue
        updated = _remove_notice_text(existing)
        if updated is None:
            continue
        if updated == "":
            try:
                doc_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise StorageError(f"cannot remove empty {name}") from exc
        else:
            fsutil.atomic_write(doc_path, updated.encode("utf-8"), what=f"the {name} file")


def install_settings(project_dir: Path, *, warn: bool = False, print_only: bool = False) -> int:
    """Merge guard settings, hooks, and project notice blocks into `project_dir`."""
    settings_path = project_dir / ".claude" / "settings.json"
    existing = _read_existing_settings(settings_path)
    merged = merge_settings(existing, load_template(), warn=warn)
    rendered = json.dumps(merged, indent=2) + "\n"
    if print_only:
        ui.write(rendered)
        return int(ExitCode.OK)

    claude_dir = settings_path.parent
    fsutil.ensure_private_dir(claude_dir, "the .claude directory")
    fsutil.atomic_write(
        settings_path,
        rendered.encode("utf-8"),
        what="the Claude settings file",
    )
    _upsert_notice_blocks(project_dir)
    mode = "warn" if warn else "block"
    ui.out(f"veil agent-guard: installed into .claude/settings.json ({mode} mode)")
    return int(ExitCode.OK)


def uninstall_settings(project_dir: Path) -> int:
    """Remove agent-guard hooks from `.claude/settings.json` and notice blocks from docs."""
    settings_path = project_dir / ".claude" / "settings.json"
    if settings_path.exists() or settings_path.is_symlink():
        existing = _read_existing_settings(settings_path)
        hooks = existing.get("hooks")
        if isinstance(hooks, dict):
            changed = False
            for event in list(hooks.keys()):
                entries = hooks[event]
                if not isinstance(entries, list):
                    continue
                kept = [entry for entry in entries if not _is_veil_hook_entry(entry)]
                if len(kept) != len(entries):
                    changed = True
                if kept:
                    hooks[event] = kept
                else:
                    del hooks[event]
            if not hooks:
                del existing["hooks"]
            if changed:
                rendered = json.dumps(existing, indent=2) + "\n"
                fsutil.atomic_write(
                    settings_path,
                    rendered.encode("utf-8"),
                    what="the Claude settings file",
                )
    _remove_notice_blocks(project_dir)
    ui.out("veil agent-guard: uninstalled hooks and notice blocks")
    return int(ExitCode.OK)
