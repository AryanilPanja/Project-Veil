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

AGENT_NOTICE = (
    "veil is active on this machine.\n"
    "Names, emails, phones, and other personal details you see may be pseudonyms from veil.\n"
    "Keep them verbatim and never try to guess or recover real ones.\n"
    "Never ask the user for real personal details.\n"
    "Never run veil commands, read veil files, or read the clipboard.\n"
    "agent-guard hooks review your edits and flag test or evaluation tampering."
)

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
    "src/veil/agentguard/**",
    ".pre-commit-config.yaml",
    ".git/hooks/**",
    ".git/config",
    ".veil-agent-guard.toml",
    "**/persona.yaml",
    "**/*.age",
    "**/matrix-slots.txt",
)

PROTECTED_DIR_PREFIXES: tuple[str, ...] = (
    "tests",
    ".github",
    ".github/workflows",
    ".claude",
    "contrib/agent-guard",
    "src/veil/agentguard",
    ".git",
    ".git/hooks",
)

_SECRET_BASENAME_PATTERNS: tuple[str, ...] = (
    "**/persona.yaml",
    "**/*.age",
    "**/matrix-slots.txt",
)

_SECRET_HOME_REL_DIRS: tuple[str, ...] = (
    ".config/veil",
    "Library/Application Support/veil",
    "Library/Keychains",
    ".ssh",
    ".gnupg",
)

_GUARD_HOME_REL_DIRS: tuple[str, ...] = (
    "Library/Logs/veil",
    ".local/state/veil",
)

_MAX_CONFIG_BYTES = 1_048_576


DEFAULT_SECOND_REVIEW_MODEL = "gemini-4-hydrogen-high"
DEFAULT_SECOND_REVIEW_TIMEOUT = 300
_MAX_SECOND_REVIEW_TIMEOUT = 1200


@dataclass(frozen=True)
class SecondReviewConfig:
    """`[second_review]`: a second model (Antigravity `agy`) reviews the session's diff."""

    enabled: bool = False
    command: str | None = None  # path to `agy`; None means look on PATH and in ~/.local/bin
    model: str = DEFAULT_SECOND_REVIEW_MODEL
    timeout: int = DEFAULT_SECOND_REVIEW_TIMEOUT
    send_task: bool = True  # include the user's requests and the agent's final message
    block: bool = True  # a HIGH finding sends the agent back once, like the diff review


@dataclass(frozen=True)
class GuardConfig:
    protected: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()
    test_command: str | None = None
    second_review: SecondReviewConfig = SecondReviewConfig()

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
    second_review = _parse_second_review(data.get("second_review"))
    return GuardConfig(
        protected=protected, allow=allow, test_command=test_command, second_review=second_review
    )


def _parse_second_review(value: object) -> SecondReviewConfig:
    if value is None:
        return SecondReviewConfig()
    if not isinstance(value, dict):
        raise _bad_second_review("[second_review] must be a table")
    known = {"enabled", "command", "model", "timeout", "send_task", "block"}
    unknown = sorted(set(value) - known)
    if unknown:
        raise _bad_second_review(f"unknown key {unknown[0]!r} in [second_review]")
    for key in ("enabled", "send_task", "block"):
        if key in value and not isinstance(value[key], bool):
            raise _bad_second_review(f"second_review.{key} must be true or false")
    command = value.get("command")
    if command is not None and (not isinstance(command, str) or not command.strip()):
        raise _bad_second_review("second_review.command must be a path")
    model = value.get("model", DEFAULT_SECOND_REVIEW_MODEL)
    if not isinstance(model, str) or not model.strip() or model.startswith("-"):
        raise _bad_second_review("second_review.model must be a model name")
    timeout = value.get("timeout", DEFAULT_SECOND_REVIEW_TIMEOUT)
    if (
        not isinstance(timeout, int)
        or isinstance(timeout, bool)
        or not 10 <= timeout <= _MAX_SECOND_REVIEW_TIMEOUT
    ):
        raise _bad_second_review(
            f"second_review.timeout must be 10 to {_MAX_SECOND_REVIEW_TIMEOUT} seconds"
        )
    return SecondReviewConfig(
        enabled=value.get("enabled", True),
        command=command.strip() if isinstance(command, str) else None,
        model=model.strip(),
        timeout=timeout,
        send_task=value.get("send_task", True),
        block=value.get("block", True),
    )


def _bad_second_review(message: str) -> VeilError:
    return VeilError(f"invalid .veil-agent-guard.toml: {message}", exit_code=ExitCode.USAGE)


def _as_str_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise VeilError(
            f"invalid {field_name} list in .veil-agent-guard.toml", exit_code=ExitCode.USAGE
        )
    return tuple(item.strip() for item in value if item.strip())


def _expand_env_vars(raw_path: str) -> str:
    cleaned = raw_path.strip()
    home = str(Path.home())
    for token in ("$HOME", "${HOME}"):
        if cleaned == token or cleaned.startswith(token + "/"):
            cleaned = home + cleaned[len(token) :]
            break
    xdg_cfg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if xdg_cfg:
        for token in ("$XDG_CONFIG_HOME", "${XDG_CONFIG_HOME}"):
            if cleaned == token or cleaned.startswith(token + "/"):
                cleaned = xdg_cfg.rstrip("/") + cleaned[len(token) :]
                break
    xdg_state = os.environ.get("XDG_STATE_HOME", "").strip()
    if xdg_state:
        for token in ("$XDG_STATE_HOME", "${XDG_STATE_HOME}"):
            if cleaned == token or cleaned.startswith(token + "/"):
                cleaned = xdg_state.rstrip("/") + cleaned[len(token) :]
                break
    return cleaned


def candidate_rel_paths(raw_path: str, cwd: Path) -> list[str]:
    """Return normalized POSIX path candidates (lexical and resolved) relative to `cwd`."""
    cleaned = _expand_env_vars(raw_path)
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
        lex_abs = path.as_posix()
        try:
            rel_lex = path.relative_to(cwd).as_posix()
            candidates.append(rel_lex)
        except ValueError:
            candidates.append(lex_abs)

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
    except (OSError, ValueError):
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


def _dir_bases_for_rel(rel_from_home: str) -> list[str]:
    bases: list[str] = []
    home = Path.home()
    for base_home in (home, home.resolve()):
        posix = (base_home / rel_from_home).as_posix()
        if posix not in bases:
            bases.append(posix)
    return bases


def _matches_dir_or_child(candidate: str, base_dir: str) -> bool:
    cand_norm = candidate.rstrip("/")
    base_norm = base_dir.rstrip("/")
    return cand_norm == base_norm or cand_norm.startswith(base_norm + "/")


def _abs_path_candidates(raw_path: str, cwd: Path) -> list[str]:
    cleaned = _expand_env_vars(raw_path)
    if not cleaned:
        return []
    p = Path(cleaned).expanduser() if cleaned.startswith("~") else Path(cleaned)
    target = p if p.is_absolute() else (cwd / p)
    out = [target.as_posix()]
    try:
        res = target.resolve().as_posix()
        if res not in out:
            out.append(res)
    except (OSError, ValueError):
        pass
    return out


def is_protected_secret_path(raw_path: str, cwd: Path) -> str | None:
    """Return matching rule if `raw_path` refers to a veil/credential secret path."""
    cleaned = raw_path.strip()
    if not cleaned:
        return None
    norm_raw = _lexical_norm(cleaned)
    for prefix in ("$XDG_CONFIG_HOME/veil", "${XDG_CONFIG_HOME}/veil"):
        if _matches_dir_or_child(norm_raw, prefix):
            return "$XDG_CONFIG_HOME/veil/**"
    for rel_dir in _SECRET_HOME_REL_DIRS:
        for prefix in (f"~/{rel_dir}", f"$HOME/{rel_dir}", f"${{HOME}}/{rel_dir}"):
            if _matches_dir_or_child(norm_raw, prefix):
                return f"~/{rel_dir}/**"

    candidates = candidate_rel_paths(cleaned, cwd)
    for cand in candidates:
        matched = matches_any(cand, _SECRET_BASENAME_PATTERNS)
        if matched is not None:
            return matched

    abs_dirs: list[tuple[str, str]] = []
    for rel_dir in _SECRET_HOME_REL_DIRS:
        for base in _dir_bases_for_rel(rel_dir):
            abs_dirs.append((base, f"~/{rel_dir}/**"))
    xdg_cfg = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if xdg_cfg and Path(xdg_cfg).is_absolute():
        for base in (Path(xdg_cfg) / "veil", Path(xdg_cfg).resolve() / "veil"):
            abs_dirs.append((base.as_posix(), "$XDG_CONFIG_HOME/veil/**"))

    for cand in _abs_path_candidates(cleaned, cwd):
        for base, label in abs_dirs:
            if _matches_dir_or_child(cand, base):
                return label
    return None


def _is_protected_guard_home_or_state(raw_path: str, cwd: Path) -> str | None:
    cleaned = raw_path.strip()
    if not cleaned:
        return None
    norm_raw = _lexical_norm(cleaned)
    for prefix in ("$XDG_STATE_HOME/veil", "${XDG_STATE_HOME}/veil"):
        if _matches_dir_or_child(norm_raw, prefix):
            return "$XDG_STATE_HOME/veil/**"
    for rel_dir in _GUARD_HOME_REL_DIRS:
        for prefix in (f"~/{rel_dir}", f"$HOME/{rel_dir}", f"${{HOME}}/{rel_dir}"):
            if _matches_dir_or_child(norm_raw, prefix):
                return f"~/{rel_dir}/**"

    abs_cands = _abs_path_candidates(cleaned, cwd)
    abs_dirs: list[tuple[str, str]] = []
    for rel_dir in _GUARD_HOME_REL_DIRS:
        for base in _dir_bases_for_rel(rel_dir):
            abs_dirs.append((base, f"~/{rel_dir}/**"))
    sdir = state_dir()
    for base in (sdir, sdir.resolve()):
        abs_dirs.append((base.as_posix(), "agent-guard-state/**"))

    claude_patterns: list[str] = []
    for base in _dir_bases_for_rel(".claude"):
        claude_patterns.append(f"{base}/settings*.json")

    for cand in abs_cands:
        for base, label in abs_dirs:
            if _matches_dir_or_child(cand, base):
                return label
        p = PurePosixPath(cand)
        for pat in claude_patterns:
            if p.full_match(pat):
                return "~/.claude/settings*.json"
    return None


def is_protected_path(raw_path: str, cwd: Path, config: GuardConfig) -> str | None:
    """Return matching rule/pattern if `raw_path` is protected (and not allowed), else None."""
    secret_match = is_protected_secret_path(raw_path, cwd)
    if secret_match is not None:
        return secret_match
    guard_home_match = _is_protected_guard_home_or_state(raw_path, cwd)
    if guard_home_match is not None:
        return guard_home_match
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
    if "\x00" in cleaned:
        return True
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
    except (OSError, ValueError):
        return True
