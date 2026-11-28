"""The banner shown by `veil` with no arguments and by `veil --help` (terminal only).

Plain text when stdout is not a terminal, when NO_COLOR is set (https://no-color.org), or when
TERM is "dumb". Never printed by the hotkey, clipboard or pipeline commands, so it costs them
nothing.
"""

import os

ART = (
    r"           _ _",
    r"__   _____(_) |",
    r"\ \ / / _ \ | |",
    r" \ V /  __/ | |",
    r"  \_/ \___|_|_|",
)
TAGLINE = "real details out, a consistent fake persona in"

_DIM, _BOLD, _CYAN, _RESET = "\x1b[2m", "\x1b[1m", "\x1b[36m", "\x1b[0m"


def use_color(is_tty: bool, env: dict[str, str] | None = None) -> bool:
    env = dict(os.environ) if env is None else env
    return is_tty and "NO_COLOR" not in env and env.get("TERM") != "dumb"


def render(version: str, *, color: bool) -> str:
    footer = f"{TAGLINE}  ·  v{version}"
    if not color:
        return "\n".join([*ART, "", footer, ""])
    art = [f"{_BOLD}{_CYAN}{line}{_RESET}" for line in ART]
    return "\n".join([*art, "", f"{_DIM}{footer}{_RESET}", ""])
