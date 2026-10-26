"""The copy watcher (ADR-0031): while veil is ON, every copy is sanitized right away.

`veil clip watch` (run by the `veil-watch` systemd user service) becomes
`wl-paste --watch <python> -m veil clip sanitize --auto`: wl-paste runs that command after every
change of the clipboard (through the compositor's data-control protocol; no window focus, no
key grabbing: Ctrl+C and Ctrl+V stay the applications' own). Each run is a normal sanitize with
`--auto`: veil's own writes are skipped, unchanged plain text isn't rewritten, and only real
news is notified (commands.py, messages.py).

wl-paste hands the new content to the command on stdin; veil reads the clipboard itself (to see
every offered type), so `drain_stdin` just empties that pipe.

Wayland only: on X11 there is no equivalent here; the explicit hotkeys still work.
"""

import os
import shutil
import sys
from collections.abc import Callable

from veil.errors import ClipboardError

DRAIN_LIMIT = 64 * 1024 * 1024  # stop reading a runaway pipe; the clipboard is read separately


def argv(wl_paste: str, python: str = sys.executable) -> list[str]:
    return [wl_paste, "--watch", python, "-m", "veil", "clip", "sanitize", "--auto"]


def run(
    which: Callable[[str], str | None] = shutil.which,
    env: dict[str, str] | None = None,
    execv: Callable[[str, list[str]], None] = os.execv,
) -> None:
    """Replace this process with the watcher (systemd then supervises wl-paste itself)."""
    env = dict(os.environ) if env is None else env
    wl_paste = which("wl-paste")
    if not env.get("WAYLAND_DISPLAY") or wl_paste is None:
        raise ClipboardError("the copy watcher needs a Wayland session and wl-clipboard")
    execv(wl_paste, argv(wl_paste))


def drain_stdin(stream=None, limit: int = DRAIN_LIMIT) -> None:
    """Read and discard what wl-paste --watch pipes in (never kept, never decoded)."""
    try:
        stream = sys.stdin.buffer if stream is None else stream
        if stream.isatty():
            return
        total = 0
        while total < limit:
            chunk = stream.read(min(1 << 16, limit - total))
            if not chunk:
                return
            total += len(chunk)
    except (OSError, ValueError, AttributeError):  # no usable stdin: nothing to drain
        return
