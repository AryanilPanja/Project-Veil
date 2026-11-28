"""macOS notifications and questions through /usr/bin/osascript (no pyobjc, no helper app).

Every text goes in as an `on run argv` argument, never into the script source, so a message
can't inject AppleScript. Notifications appear under "Script Editor" in System Settings >
Notifications; that is where to allow or silence them.

Questions use `display dialog` (at most three buttons) with `giving up after`: an unanswered
dialog returns None, which callers treat as "no" (ask-before-send then denies).
"""

from collections.abc import Callable, Sequence

from veil.clip import proc
from veil.clip.notify import GRACE_SECONDS, TIMEOUT_SECONDS, Actions, Message
from veil.errors import ClipboardError

OSASCRIPT = "/usr/bin/osascript"
MAX_BUTTONS = 3  # display dialog's limit

_NOTIFY = (
    "on run argv",
    "display notification (item 2 of argv) with title (item 1 of argv)",
    "end run",
)


def _dialog_script(buttons: int) -> tuple[str, ...]:
    labels = ", ".join(f"item {3 + i} of argv" for i in range(buttons))
    return (
        "on run argv",
        f"set r to display dialog (item 2 of argv) with title (item 1 of argv) "
        f"buttons {{{labels}}} default button (item {2 + buttons} of argv) "
        f"giving up after ((item {3 + buttons} of argv) as integer) with icon caution",
        'if gave up of r then return ""',
        "return button returned of r",
        "end run",
    )


def _script_argv(lines: Sequence[str], args: Sequence[str]) -> list[str]:
    argv = [OSASCRIPT]
    for line in lines:
        argv += ["-e", line]
    return [*argv, "--", *args]


def notify_argv(message: Message) -> list[str]:
    return _script_argv(_NOTIFY, [message.summary, message.body])


def choice_argv(message: Message, actions: Actions, timeout: int) -> list[str]:
    if not 1 <= len(actions) <= MAX_BUTTONS:
        raise ValueError("display dialog takes one to three buttons")
    labels = [label for _, label in actions]
    return _script_argv(
        _dialog_script(len(actions)), [message.summary, message.body, *labels, str(timeout)]
    )


class OsascriptNotifier:
    def __init__(self, *, feed: Callable[..., int] = proc.feed) -> None:
        self._feed = feed

    def notify(self, message: Message) -> bool:
        try:
            return self._feed(notify_argv(message), b"", timeout=TIMEOUT_SECONDS) == 0
        except ClipboardError:
            return False


def choose(
    message: Message,
    actions: Actions,
    timeout: int,
    *,
    capture: Callable[..., proc.Captured] = proc.capture,
) -> str | None:
    """The clicked action's name; None for a timeout, an error, or an unknown reply."""
    try:
        result = capture(
            choice_argv(message, actions, timeout), timeout=timeout + GRACE_SECONDS, limit=256
        )
    except (ClipboardError, ValueError):
        return None
    if result.returncode != 0:
        return None
    try:
        label = result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    return next((name for name, shown in actions if shown == label), None)
