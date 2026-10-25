"""Press keys for the user through the XDG desktop portal (M3.5 spike, ADR-0030).

Wayland lets an ordinary program inject input only through `org.freedesktop.portal.RemoteDesktop`,
after the user agrees in the desktop's dialog. Flow (portal spec, each step answered by a
`Request.Response` signal on a predictable path):

1. CreateSession → session handle;
2. SelectDevices(types = keyboard only, persist_mode = until revoked, restore_token if we have one);
3. Start → the consent dialog (skipped when the restore token is still accepted); returns the
   granted devices and a new single-use restore token;
4. NotifyKeyboardKeysym press / release;
5. Session.Close.

The restore token is a capability ("veil may type"), so it lives in the agent-denied config dir
(0600). veil only ever presses the chords it is asked to (Ctrl+V, Ctrl+Shift+V, or the spike's
test letters). Errors are value-free; a refusal is `Refused`. Talks jeepney over the session bus,
never a command line.
"""

import contextlib
import secrets
import time
from collections.abc import Sequence
from pathlib import Path

from veil import fsutil

SERVICE = "org.freedesktop.portal.Desktop"
OBJECT_PATH = "/org/freedesktop/portal/desktop"
REMOTE_DESKTOP = "org.freedesktop.portal.RemoteDesktop"
REQUEST = "org.freedesktop.portal.Request"
SESSION = "org.freedesktop.portal.Session"

KEYBOARD = 1
PERSIST_UNTIL_REVOKED = 2
RELEASED, PRESSED = 0, 1

# X keysyms
CONTROL_L = 0xFFE3
SHIFT_L = 0xFFE1
CHORDS = {
    "ctrl+v": (CONTROL_L, ord("v")),
    "ctrl+shift+v": (CONTROL_L, SHIFT_L, ord("v")),
}

TOKEN_FILE = "paste-portal-token"  # noqa: S105 - a file name
MAX_TOKEN_BYTES = 512
CALL_TIMEOUT = 5.0
CONSENT_TIMEOUT = 120.0  # the user may take a while with the dialog


class PortalError(Exception):
    """A portal failure; the message is value-free."""


class Refused(PortalError):
    """The user cancelled the dialog, or didn't grant the keyboard."""


class RemoteKeyboard:
    def __init__(
        self,
        address: str = "SESSION",
        *,
        timeout: float = CALL_TIMEOUT,
        consent_timeout: float = CONSENT_TIMEOUT,
    ) -> None:
        self._address = address
        self._timeout, self._consent_timeout = timeout, consent_timeout
        self._connection = None
        self._session: str | None = None
        self.timings: dict[str, float] = {}  # step → seconds (for the spike)

    def open(self, restore_token: str | None = None) -> str | None:
        """Start a keyboard session; returns the new restore token (None if none was given)."""
        from jeepney.io.blocking import open_dbus_connection

        self._connection = open_dbus_connection(self._address, auth_timeout=self._timeout)
        started = time.monotonic()
        results = self._request(
            "CreateSession",
            "a{sv}",
            lambda token: (
                {"handle_token": ("s", token), "session_handle_token": ("s", _token())},
            ),
            self._timeout,
        )
        session = results.get("session_handle", (None, None))[1]
        if not isinstance(session, str) or not session:
            raise PortalError("the portal returned no session")
        self._session = session
        self.timings["create"] = time.monotonic() - started

        started = time.monotonic()
        options = {
            "types": ("u", KEYBOARD),
            "persist_mode": ("u", PERSIST_UNTIL_REVOKED),
        }
        if restore_token:
            options["restore_token"] = ("s", restore_token)
        self._request(
            "SelectDevices",
            "oa{sv}",
            lambda token: (session, {**options, "handle_token": ("s", token)}),
            self._timeout,
        )
        self.timings["select"] = time.monotonic() - started

        started = time.monotonic()
        results = self._request(
            "Start",
            "osa{sv}",
            lambda token: (session, "", {"handle_token": ("s", token)}),
            self._consent_timeout,
        )
        self.timings["start"] = time.monotonic() - started
        devices = results.get("devices", ("u", 0))[1]
        if not isinstance(devices, int) or not devices & KEYBOARD:
            raise Refused("keyboard access was not granted")
        token = results.get("restore_token", ("s", None))[1]
        return token if isinstance(token, str) and token else None

    def press(self, keysyms: Sequence[int]) -> None:
        """Press the keys in order, release them in reverse (a chord such as Ctrl+V)."""
        if self._session is None:
            raise PortalError("no portal session")
        started = time.monotonic()
        for keysym in keysyms:
            self._key(keysym, PRESSED)
        for keysym in reversed(keysyms):
            self._key(keysym, RELEASED)
        self.timings["press"] = time.monotonic() - started

    def close(self) -> None:
        if self._connection is None:
            return
        if self._session is not None:
            from jeepney import DBusAddress, new_method_call

            with contextlib.suppress(Exception):
                self._connection.send_and_get_reply(
                    new_method_call(DBusAddress(self._session, SERVICE, SESSION), "Close"),
                    timeout=self._timeout,
                )
            self._session = None
        self._connection.close()
        self._connection = None

    def __enter__(self) -> "RemoteKeyboard":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── internals ─────────────────────────────────────────────────────────────

    def _key(self, keysym: int, state: int) -> None:
        self._call("NotifyKeyboardKeysym", "oa{sv}iu", (self._session, {}, keysym, state))

    def _call(self, method: str, signature: str, body: tuple) -> tuple:
        from jeepney import DBusAddress, HeaderFields, MessageType, new_method_call
        from jeepney.low_level import MessageFlag

        message = new_method_call(
            DBusAddress(OBJECT_PATH, SERVICE, REMOTE_DESKTOP), method, signature, body
        )
        message.header.flags |= MessageFlag.no_auto_start
        reply = self._connection.send_and_get_reply(message, timeout=self._timeout)
        if reply.header.message_type is MessageType.error:
            name = reply.header.fields.get(HeaderFields.error_name, "unknown")
            raise PortalError(f"portal error {name}")
        return reply.body

    def _request(self, method: str, signature: str, body, timeout: float) -> dict:
        """Call a request-style method and wait for its Response (subscribed before the call,
        as the portal spec asks, so the answer can't be missed)."""
        from jeepney import HeaderFields, MatchRule, message_bus

        token = _token()
        rule = MatchRule(type="signal", interface=REQUEST, member="Response")
        self._connection.send_and_get_reply(message_bus.AddMatch(rule), timeout=self._timeout)
        with self._connection.filter(rule, bufsize=16) as queue:
            handle = self._call(method, signature, body(token))[0]
            deadline = time.monotonic() + timeout
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise PortalError(f"no answer from the portal ({method})")
                try:
                    signal = self._connection.recv_until_filtered(queue, timeout=left)
                except TimeoutError:
                    raise PortalError(f"no answer from the portal ({method})") from None
                if signal.header.fields.get(HeaderFields.path) == handle:
                    break
        response, results = signal.body
        if response == 1:
            raise Refused("cancelled in the dialog")
        if response != 0:
            raise Refused(f"the portal ended the request ({method})")
        return dict(results)


def _token() -> str:
    return "veil" + secrets.token_hex(8)


# ── the remembered consent ────────────────────────────────────────────────────


def token_path(config: Path) -> Path:
    return config / TOKEN_FILE


def load_token(config: Path) -> str | None:
    path = token_path(config)
    try:
        if not path.exists():
            return None
        raw = fsutil.read_private(path, MAX_TOKEN_BYTES, "the paste permission token")
        token = raw.decode("ascii").strip()
    except Exception:  # noqa: BLE001 - a bad token just means asking again
        return None
    return token if token.isprintable() and token else None


def save_token(config: Path, token: str | None) -> None:
    path = token_path(config)
    if token is None:
        path.unlink(missing_ok=True)
        return
    fsutil.ensure_private_dir(config, "the veil config directory")
    fsutil.atomic_write(path, token.encode("ascii") + b"\n", what="the paste permission token")
