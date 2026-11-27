"""Remove the original from KDE's clipboard history after sanitizing (M2.6, board Q14, ADR-0023
amendment 2).

The clipboard history keeps every copy, so after `veil clip sanitize` its history shortcut would
paste the real original straight back. Its D-Bus interface (org.kde.klipper.klipper) has no call
to remove one entry, so the history is rebuilt (owner decision 2026-10-25):

1. read the history as text (row 0 = newest), via `getClipboardHistoryMenu`;
2. nothing equal to the original → done (NOT_FOUND);
3. `clearClipboardHistory`, then re-add every other text entry oldest first with
   `setClipboardContents` (re-adding moves an entry to the top, so the order is kept);
4. write the sanitized text to the clipboard again (plain text only, as before), so it is on top;
5. read the history again and check the original is gone.

Dropped on the way: the original, veil's own placeholders, and image entries (only their
"▨ WxH" label is readable over D-Bus; re-adding it would create a bogus text entry).

Best effort and value-free: the clipboard is already sanitized when this runs, so a failure here
never fails the command; it is reported as a warning (counts only, never entries). History text
stays in this process and goes over the bus, never into argv (other processes can read argv).
The bus is never asked to start the history service: if it isn't running, nothing is touched.
"""

import os
import re
from collections.abc import Callable, Sequence
from enum import Enum
from typing import Protocol

SERVICE = "org.kde.klipper"
OBJECT_PATH = "/klipper"
INTERFACE = "org.kde.klipper.klipper"
TIMEOUT_SECONDS = 2.0

_IMAGE_LABEL = re.compile(r"\A\u25a8 \d+\s*[x\u00d7]\s*\d+")  # "▨ 800x600": an image entry
VEIL_PREFIX = "[veil: "  # veil's own placeholders (commands.WAITING_/ERROR_PLACEHOLDER)


class Forget(Enum):
    REMOVED = "removed"
    PARTIAL = "partial"  # the original is gone, but some other entries could not be put back
    NOT_FOUND = "not found"  # the history doesn't hold the original (or history is off)
    NOT_RUNNING = "not running"  # no clipboard history service on the session bus
    FAILED = "failed"  # the original may still be in the history


class HistoryBus(Protocol):
    def running(self) -> bool: ...

    def entries(self) -> list[str]: ...

    def clear(self) -> None: ...

    def add(self, text: str) -> None: ...


Forgetter = Callable[[str, Callable[[], None]], Forget]


def same(entry: str, original: str) -> bool:
    """An entry holds the original: exactly, or up to surrounding whitespace."""
    if entry == original:
        return True
    stripped = original.strip()
    return bool(stripped) and entry.strip() == stripped


def keepable(entry: str) -> bool:
    return bool(entry) and not entry.startswith(VEIL_PREFIX) and not _IMAGE_LABEL.match(entry)


def forget(bus: HistoryBus, original: str, put_back: Callable[[], None]) -> Forget:
    """Rebuild the history without `original`; `put_back` rewrites the sanitized clipboard."""
    try:
        if not bus.running():
            return Forget.NOT_RUNNING
        entries = bus.entries()
        if not any(same(entry, original) for entry in entries):
            return Forget.NOT_FOUND
        keep = [e for e in entries if not same(e, original) and keepable(e)]
        bus.clear()
    except Exception:  # noqa: BLE001 - best effort; reported, never raised
        return Forget.FAILED
    lost = 0
    for entry in reversed(keep):  # oldest first: each add goes to the top
        try:
            bus.add(entry)
        except Exception:  # noqa: BLE001
            lost += 1
    try:
        put_back()
        remaining = bus.entries()
    except Exception:  # noqa: BLE001 - can't confirm
        return Forget.FAILED
    if any(same(entry, original) for entry in remaining):
        return Forget.FAILED
    return Forget.PARTIAL if lost else Forget.REMOVED


class JeepneyBus:
    """The session bus via jeepney (pure Python). One connection, opened on first use."""

    def __init__(self, address: str = "SESSION", *, timeout: float = TIMEOUT_SECONDS) -> None:
        self._address = address
        self._timeout = timeout
        self._connection = None

    def running(self) -> bool:
        from jeepney import message_bus

        reply = self._call(message_bus.NameHasOwner(SERVICE))
        return bool(reply[0])

    def entries(self) -> list[str]:
        return list(self._method("getClipboardHistoryMenu")[0])

    def clear(self) -> None:
        self._method("clearClipboardHistory")

    def add(self, text: str) -> None:
        self._method("setClipboardContents", "s", (text,))

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _method(self, name: str, signature: str | None = None, body: Sequence = ()) -> tuple:
        from jeepney import DBusAddress, new_method_call

        address = DBusAddress(OBJECT_PATH, bus_name=SERVICE, interface=INTERFACE)
        return self._call(new_method_call(address, name, signature, tuple(body)))

    def _call(self, message) -> tuple:
        from jeepney import HeaderFields, MessageType
        from jeepney.low_level import MessageFlag

        message.header.flags |= MessageFlag.no_auto_start
        if self._connection is None:
            from jeepney.io.blocking import open_dbus_connection

            self._connection = open_dbus_connection(self._address, auth_timeout=self._timeout)
        reply = self._connection.send_and_get_reply(message, timeout=self._timeout)
        if reply.header.message_type is MessageType.error:
            # The error name only: D-Bus error bodies can echo arguments.
            name = reply.header.fields.get(HeaderFields.error_name, "unknown")
            raise HistoryError(f"D-Bus error {name}")
        return reply.body


class HistoryError(Exception):
    """A D-Bus failure. Never shown: `forget` turns every failure into Forget.FAILED."""


def detect(env: dict[str, str] | None = None) -> Forgetter | None:
    """A forgetter for the session's clipboard history, or None without a session bus."""
    env = dict(os.environ) if env is None else env
    if not env.get("DBUS_SESSION_BUS_ADDRESS"):
        return None

    def forgetter(original: str, put_back: Callable[[], None]) -> Forget:
        bus = JeepneyBus()
        try:
            return forget(bus, original, put_back)
        finally:
            bus.close()

    return forgetter
