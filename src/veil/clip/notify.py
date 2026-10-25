"""Desktop notifications (M2.3, spec §4.2 step 6): counts per category, never values.

`notify-send` with app name "veil", marked transient so the notification history doesn't keep
them. Messages are built in `messages.py` from value-free outcomes; this module only shows them.

Showing a notification is best effort: the clipboard work is already done (or already undone)
when it runs, and the same summary always goes to stderr too. A missing or failing notify-send
never changes the exit code.
"""

import shutil
from collections.abc import Callable
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
