"""`veil clip paste`: sanitize, then paste for the user (M3.5, ADR-0030). Alt+V / Alt+Shift+V.

The paste is a Ctrl+V or Ctrl+Shift+V pressed through the desktop portal (portal.py), and only
after a fully successful sanitize: never for a skipped clipboard (nothing copied, an image or
file, rich text only, a password), after a Deny, or after an error (fail closed clears instead).

The hotkey's keys must be up before the paste, or a still-held Alt turns Ctrl+V into
Ctrl+Alt+V; Wayland can't tell veil, so the paste waits until RELEASE_WAIT after the key press.
"""

import contextlib
import time
from collections.abc import Callable
from pathlib import Path

from veil.clip import portal
from veil.clip.commands import Outcome, Pasted

RELEASE_WAIT = 0.35  # seconds after the key press before veil presses its own keys


def chord(terminal: bool) -> str:
    return "ctrl+shift+v" if terminal else "ctrl+v"


def should_paste(outcome: Outcome) -> bool:
    return outcome.changed


def inject(
    chord_name: str,
    *,
    config: Path,
    started: float,
    keyboard_factory: Callable[[], portal.RemoteKeyboard] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> Pasted:
    """Press `chord_name` through the portal. Never raises: the clipboard is already right, so a
    failed paste only means "press Ctrl+V yourself"."""
    keys = portal.CHORDS[chord_name]
    keyboard = (keyboard_factory or portal.RemoteKeyboard)()  # looked up now: tests replace it
    try:
        token = keyboard.open(portal.load_token(config))
        with contextlib.suppress(Exception):  # an unsaved token only means asking again
            portal.save_token(config, token)
        wait = started + RELEASE_WAIT - clock()
        if wait > 0:
            sleep(wait)
        keyboard.press(keys)
    except portal.Refused:
        return Pasted.REFUSED
    except Exception:  # noqa: BLE001 - portal or D-Bus trouble: report, don't raise
        return Pasted.FAILED
    finally:
        keyboard.close()
    return Pasted.PASTED
