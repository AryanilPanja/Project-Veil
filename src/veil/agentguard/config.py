"""Configuration, path matching, and state paths for `veil agent-guard`."""

import hashlib
import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from veil.errors import VeilError
from veil.exitcodes import ExitCode

CONFIG_FILENAME = ".veil-agent-guard.toml"

DEFAULT_PROTECTED_PATTERNS: tuple[str, ...] = (
    "tests/**",
    "**/tests/**",
    "test_*.py",
    "*_test.py",
    "*.spec.*",
    "conftest.py",
    ".github/workflows/**",
    "uv.lock",
    "pyproject.toml",
    ".claude/settings*.json",
    "contrib/agent-guard/**",
    ".pre-commit-config.yaml",
    ".git/hooks/**",
    ".veil-agent-guard.toml",
)

PROTECTED_DIR_PREFIXES: tuple[str, ...] = (
    "tests",
    ".github",
    ".github/workflows",
    ".claude",
    "contrib/agent-guard",
    ".git",
    ".git/hooks",
)

_MAX_CONFIG_BYTES = 1_048_576


@dataclass(frozen=True)
class GuardConfig:
    protected: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()
    test_command: str | None = None

    @property
    def all_protected(self) -> tuple[str, ...]:
        return DEFAULT_PROTECTED_PATTERNS + self.protected


def state_dir() -> Path:
    """Where agent-guard stores logs and per-session state."""
    value = os.environ.get("XDG_STATE_HOME", "").strip()
    if value and Path(value).is_absolute():
        return Path(value) / "veil"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Logs" / "veil"
    return Path.home() / ".local" / "state" / "veil"


def agent_log_path() -> Path:
    return state_dir() / "agent-log.jsonl"


def session_state_path(session_id: str) -> Path:
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]
    return state_dir() / "sessions" / f"{digest}.json"


def load_config(project_dir: Path) -> GuardConfig:
    """Load optional `<project_dir>/.veil-agent-guard.toml`."""
    path = project_dir / CONFIG_FILENAME
    try:
        info = path.lstat()
    except FileNotFoundError:
        return GuardConfig()
    except OSError:
        return GuardConfig()
    if info.st_size > _MAX_CONFIG_BYTES:
        raise VeilError("agent-guard config file is too large", exit_code=ExitCode.USAGE)
    try:
        raw = path.read_text(encoding="utf-8")
        data = tomllib.loads(raw)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise VeilError("invalid .veil-agent-guard.toml", exit_code=ExitCode.USAGE) from None

    protected = _as_str_tuple(data.get("protected"), "protected")
    allow = _as_str_tuple(data.get("allow"), "allow")
    test_cmd_raw = data.get("test_command")
    if test_cmd_raw is not None and not isinstance(test_cmd_raw, str):
        raise VeilError("invalid test_command in .veil-agent-guard.toml", exit_code=ExitCode.USAGE)
    test_command = (
        test_cmd_raw.strip() if isinstance(test_cmd_raw, str) and test_cmd_raw.strip() else None
    )
    return GuardConfig(protected=protected, allow=allow, test_command=test_command)


def _as_str_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise VeilError(
            f"invalid {field_name} list in .veil-agent-guard.toml", exit_code=ExitCode.USAGE
        )
    return tuple(item.strip() for item in value if item.strip())


def candidate_rel_paths(raw_path: str, cwd: Path) -> list[str]:
    """Return normalized POSIX path candidates (lexical and resolved) relative to `cwd`."""
    cleaned = raw_path.strip()
    if not cleaned:
        return []
    path = Path(cleaned).expanduser() if cleaned.startswith("~") else Path(cleaned)

    candidates: list[str] = []
    # Lexical candidate (catches symlinks named inside protected dirs)
    if not path.is_absolute():
        lex = _lexical_norm(cleaned)
        if lex and not lex.startswith(".."):
            candidates.append(lex)
    else:
        try:
            rel_lex = path.relative_to(cwd).as_posix()
            candidates.append(rel_lex)
        except ValueError:
            pass

    # Resolved candidate (catches symlinks pointing into protected dirs & macOS /tmp)
    try:
        cwd_resolved = cwd.resolve()
        target = path if path.is_absolute() else (cwd / path)
        target_resolved = target.resolve()
        try:
            rel_res = target_resolved.relative_to(cwd_resolved).as_posix()
            if rel_res not in candidates:
                candidates.append(rel_res)
        except ValueError:
            abs_res = target_resolved.as_posix()
            if abs_res not in candidates:
                candidates.append(abs_res)
    except OSError:
        if cleaned not in candidates:
            candidates.append(cleaned)

    if not candidates:
        candidates.append(cleaned)
    return candidates


def _lexical_norm(raw: str) -> str:
    parts: list[str] = []
    for part in raw.replace("\\", "/").split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            else:
                parts.append("..")
        else:
            parts.append(part)
    return "/".join(parts)


def matches_pattern(rel_path: str, pattern: str) -> bool:
    """Match a POSIX path against a glob pattern (`/`-less patterns match any basename)."""
    norm = rel_path.lstrip("./")
    if not norm:
        return False
    p = PurePosixPath(norm)
    pat = pattern.lstrip("./").rstrip("/")
    if not pat:
        return False
    if "/" not in pat:
        return p.full_match(pat) or p.full_match(f"**/{pat}")
    return p.full_match(pat)


def matches_any(rel_path: str, patterns: tuple[str, ...]) -> str | None:
    """Return the first matching pattern, or None."""
    for pat in patterns:
        if matches_pattern(rel_path, pat):
            return pat
    return None


def is_protected_path(raw_path: str, cwd: Path, config: GuardConfig) -> str | None:
    """Return matching rule/pattern if `raw_path` is protected (and not allowed), else None."""
    candidates = candidate_rel_paths(raw_path, cwd)
    if not candidates:
        return None
    if config.allow and any(matches_any(cand, config.allow) for cand in candidates):
        return None
    for cand in candidates:
        matched = matches_any(cand, config.all_protected)
        if matched is not None:
            return matched
    return None


def is_protected_dir(raw_path: str, cwd: Path, config: GuardConfig) -> str | None:
    """Return reason if `raw_path` is a protected root directory (e.g. `tests`, `.github`)."""
    candidates = candidate_rel_paths(raw_path, cwd)
    if not candidates:
        return None
    if config.allow and any(matches_any(cand, config.allow) for cand in candidates):
        return None
    for cand in candidates:
        stripped = cand.strip("/")
        if stripped in PROTECTED_DIR_PREFIXES or stripped == ".":
            return stripped
        # Also match custom protected dir prefixes like "evals/**" -> "evals"
        for pat in config.protected:
            if pat.endswith("/**") and stripped == pat[:-3].strip("/"):
                return stripped
    return None


def is_outside_cwd(raw_path: str, cwd: Path) -> bool:
    """True if `raw_path` refers to a location outside `cwd` (or root/home)."""
    cleaned = raw_path.strip()
    if not cleaned:
        return False
    if cleaned.startswith(("~", "$HOME", "${HOME}", "$TMPDIR", "${TMPDIR}")):
        return True
    if cleaned.startswith("/") and cleaned == "/":
        return True
    try:
        cwd_resolved = cwd.resolve()
        p = Path(cleaned)
        target = p if p.is_absolute() else (cwd / p)
        target_resolved = target.resolve()
        return not target_resolved.is_relative_to(cwd_resolved)
    except OSError:
        return True
