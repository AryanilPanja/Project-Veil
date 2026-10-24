"""The only module allowed to write to the terminal (ADR-0027).

Messages must contain field paths, codes and counts only, never persona values.
"""

import getpass
import sys

from veil.errors import UnsafeEnvironment, VeilError
from veil.exitcodes import ExitCode


def out(message: str) -> None:
    print(message)


def err(message: str) -> None:
    print(message, file=sys.stderr)


def report_error(error: VeilError) -> None:
    err(f"veil: {error.safe_message}")


def report_internal_error(exc_type: type[BaseException]) -> None:
    # Class name only: exception messages may contain persona values.
    err(f"veil: internal error ({exc_type.__name__}); details withheld to protect personal data")


def stdin_is_tty() -> bool:
    return _isatty(sys.stdin)


def stdout_is_tty() -> bool:
    return _isatty(sys.stdout)


def require_tty(command: str) -> None:
    """Refuse to run a human-only command without an interactive terminal (agents, pipes)."""
    if not (stdin_is_tty() and stdout_is_tty()):
        raise UnsafeEnvironment(f"'{command}' needs an interactive terminal (human-only command)")


def confirm_typed(prompt: str, expected: str) -> bool:
    """Ask the user to type `expected` exactly. Anything else (or EOF) means no."""
    require_tty("confirmation")
    print(f"{prompt} Type '{expected}' to confirm: ", end="", file=sys.stderr, flush=True)
    answer = sys.stdin.readline()
    if not answer:
        return False
    return answer.strip() == expected


def prompt_secret(prompt: str) -> str:
    """Read a secret without echo. Needs a terminal; never readable from a pipe (agents)."""
    require_tty("passphrase prompt")
    try:
        return getpass.getpass(f"{prompt}: ", stream=sys.stderr)
    except EOFError:
        return ""


def new_secret(prompt: str) -> str:
    """Ask twice for a new secret; a mismatch is an error (nothing is set up)."""
    first = prompt_secret(prompt)
    if prompt_secret(f"{prompt} (again)") != first:
        raise VeilError(
            "the passphrases did not match; nothing was changed", exit_code=ExitCode.USAGE
        )
    return first


def choose(prompt: str, options: dict[str, str], *, default: str, attempts: int = 5) -> str:
    """Ask for one of `options` (key → label) by its first letter. EOF or no valid answer → default.

    Prompts go to stderr; needs a terminal (never answerable from a pipe).
    """
    require_tty("choice")
    menu = ", ".join(f"[{key}] {label}" for key, label in options.items())
    for _ in range(attempts):
        print(f"{prompt} {menu}: ", end="", file=sys.stderr, flush=True)
        line = sys.stdin.readline()
        if not line:
            return default
        answer = line.strip().lower()[:1]
        if answer in options:
            return answer
    return default


def _isatty(stream: object) -> bool:
    isatty = getattr(stream, "isatty", None)
    if isatty is None:
        return False
    try:
        return bool(isatty())
    except ValueError:  # closed stream
        return False
