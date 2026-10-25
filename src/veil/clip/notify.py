"""Desktop notifications (M2.3, spec §4.2 step 6): counts per category, never values.

`notify-send` with app name "veil", marked transient so the notification history doesn't keep
them. Messages are built in `messages.py` from value-free outcomes; this module only shows them.

Showing a notification is best effort: the clipboard work is already done (or already undone)
when it runs, and the same summary always goes to stderr too. A missing or failing notify-send
never changes the exit code.
"""

import shutil
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from veil.clip import proc
from veil.errors import ClipboardError

APP_NAME = "veil"
TIMEOUT_SECONDS = 3.0
EXPIRE_MS = 6000  # normal and low; critical ones stay until dismissed (the server decides)


class Urgency(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Message:
    summary: str
    body: str
    urgency: Urgency = Urgency.NORMAL
    icon: str = "security-high"


class Notifier(Protocol):
    def notify(self, message: Message) -> bool: ...


class NotifySend:
    def __init__(self, path: str, *, feed: Callable[..., int] = proc.feed) -> None:
        self._path = path
        self._feed = feed

    def argv(self, message: Message) -> list[str]:
        argv = [
            self._path,
            f"--app-name={APP_NAME}",
            f"--urgency={message.urgency.value}",
            f"--icon={message.icon}",
            "--transient",
        ]
        if message.urgency is not Urgency.CRITICAL:
            argv.append(f"--expire-time={EXPIRE_MS}")
        return [*argv, "--", message.summary, message.body]

    def notify(self, message: Message) -> bool:
        try:
            return self._feed(self.argv(message), b"", timeout=TIMEOUT_SECONDS) == 0
        except ClipboardError:  # proc's errors: could not start, timed out
            return False


class NullNotifier:
    def notify(self, message: Message) -> bool:
        return False


def detect(which: Callable[[str], str | None] = shutil.which) -> Notifier:
    path = which("notify-send")
    return NotifySend(path) if path else NullNotifier()


# ── questions: a notification with buttons (ask-before-send, the kill-switch hotkey) ─────

GRACE_SECONDS = 2  # notify-send gets this long after the timeout before it is killed
Actions = Sequence[tuple[str, str]]  # (reply name, button label)


def choice_argv(path: str, message: Message, actions: Actions, timeout: int) -> list[str]:
    """`notify-send --wait` with one `--action` per button; it prints the clicked name."""
    return [
        path,
        f"--app-name={APP_NAME}",
        f"--urgency={message.urgency.value}",
        f"--icon={message.icon}",
        "--transient",
        "--wait",
        f"--expire-time={timeout * 1000}",
        *(f"--action={name}={label}" for name, label in actions),
        "--",
        message.summary,
        message.body,
    ]


def choose(
    path: str,
    message: Message,
    actions: Actions,
    timeout: int,
    *,
    capture: Callable[..., proc.Captured] = proc.capture,
) -> str | None:
    """The clicked action's name, or None for every way of not answering: the timeout, closing
    the notification, notify-send failing or missing, an unknown or odd reply."""
    try:
        result = capture(
            choice_argv(path, message, actions, timeout),
            timeout=timeout + GRACE_SECONDS,
            limit=256,
        )
    except ClipboardError:  # proc's errors: could not start, timed out, too much output
        return None
    if result.returncode != 0:
        return None
    try:
        reply = result.stdout.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    return reply if reply in {name for name, _ in actions} else None
