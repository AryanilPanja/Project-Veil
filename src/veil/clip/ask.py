"""Ask before send (M2.4, ADR-0012): Allow / Generalize / Deny for listed special categories.

The question names categories and counts ("health 1"), never the term. Every way of not
answering is Deny (fail closed): the timeout (the persona's `ask_timeout_seconds`, default 120 s),
closing the notification, notify-send failing or missing, an unknown reply.

Askers:
- NotifyAsker: a critical notification with three action buttons (`notify-send --wait --action`).
- TerminalAsker: a terminal prompt, used only with `--no-notify` when stdin/stdout are a TTY.
- deny_all: when there is no way to ask.
"""

import shutil
from collections.abc import Callable
from enum import StrEnum

from veil import ui
from veil.clip import notify, proc
from veil.clip.notify import Message, Urgency


class Decision(StrEnum):
    ALLOW = "allow"
    GENERALIZE = "generalize"
    DENY = "deny"


# categories ("health" → count), timeout in seconds → the decision
Asker = Callable[[dict[str, int], int], Decision]

ACTIONS = (
    (Decision.ALLOW, "Allow"),
    (Decision.GENERALIZE, "Generalize"),
    (Decision.DENY, "Deny"),
)
_BUTTONS = [(decision.value, label) for decision, label in ACTIONS]


def describe(categories: dict[str, int]) -> str:
    return ", ".join(f"{name} {count}" for name, count in sorted(categories.items()))


def prompt_message(categories: dict[str, int], timeout: int) -> Message:
    return Message(
        "veil: sensitive detail. Send it?",
        f"{describe(categories)}\n"
        "Allow: send as is. Generalize: use your generic phrase. Deny: clear the clipboard.\n"
        f"No answer in {timeout} s = Deny.",
        Urgency.CRITICAL,
        icon="dialog-question",
    )


class NotifyAsker:
    def __init__(self, path: str, *, capture: Callable[..., proc.Captured] = proc.capture):
        self._path = path
        self._capture = capture

    def argv(self, categories: dict[str, int], timeout: int) -> list[str]:
        return notify.choice_argv(
            self._path, prompt_message(categories, timeout), _BUTTONS, timeout
        )

    def __call__(self, categories: dict[str, int], timeout: int) -> Decision:
        reply = notify.choose(
            self._path,
            prompt_message(categories, timeout),
            _BUTTONS,
            timeout,
            capture=self._capture,
        )
        return Decision.DENY if reply is None else Decision(reply)


class TerminalAsker:
    """For `--no-notify` in a terminal. The person is at the keyboard; EOF means Deny."""

    def __call__(self, categories: dict[str, int], timeout: int) -> Decision:
        answer = ui.choose(
            f"veil: sensitive detail ({describe(categories)}). Send it?",
            {"a": "Allow", "g": "Generalize", "d": "Deny"},
            default="d",
        )
        return {"a": Decision.ALLOW, "g": Decision.GENERALIZE}.get(answer, Decision.DENY)


def deny_all(categories: dict[str, int], timeout: int) -> Decision:
    return Decision.DENY


def detect(which: Callable[[str], str | None] = shutil.which) -> Asker:
    path = which("notify-send")
    return NotifyAsker(path) if path else deny_all
