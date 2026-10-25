"""The XDG RemoteDesktop portal client (M3.5 spike, ADR-0030), against a fake portal on a private
dbus-daemon: request/Response handshakes, keyboard-only + persistent consent, restore tokens,
refusals, timeouts, key chords. Never the real portal (it would type into the owner's windows).
"""

import pytest

from tests.helpers import privatebus
from veil import paths
from veil.clip import portal
from veil.clip.portal import (
    CHORDS,
    CONTROL_L,
    KEYBOARD,
    PERSIST_UNTIL_REVOKED,
    PRESSED,
    RELEASED,
    SHIFT_L,
    PortalError,
    Refused,
    RemoteKeyboard,
)

SESSION_PATH = "/org/freedesktop/portal/desktop/session/1_42/veil"


class FakePortal:
    """org.freedesktop.portal.RemoteDesktop + Session, answering requests with Response."""

    def __init__(self) -> None:
        self.selected: dict = {}
        self.keys: list[tuple[int, int]] = []
        self.closed = 0
        self.start_response = 0
        self.devices = KEYBOARD
        self.issued_token = "token-2"
        self.silent = set()  # methods whose Response never comes
        self.wrong_path_first = False
        self.service = None

    def _respond(self, token: str, code: int, results: dict):
        from jeepney import DBusAddress, HeaderFields, new_signal

        sender = self.service.current.header.fields[HeaderFields.sender]
        path = f"/org/freedesktop/portal/desktop/request/{sender[1:].replace('.', '_')}/{token}"
        signals = []
        if self.wrong_path_first:  # someone else's request finishing first
            other = DBusAddress(path + "x", interface=portal.REQUEST)
            signals.append(new_signal(other, "Response", "ua{sv}", (0, {})))
        address = DBusAddress(path, interface=portal.REQUEST)
        signals.append(new_signal(address, "Response", "ua{sv}", (code, results)))
        return path, signals

    def create(self, body):
        token = body[0]["handle_token"][1]
        path, signals = self._respond(token, 0, {"session_handle": ("s", SESSION_PATH)})
        return "o", (path,), [] if "CreateSession" in self.silent else signals

    def select(self, body):
        session, options = body
        assert session == SESSION_PATH
        self.selected = {k: v[1] for k, v in options.items() if k != "handle_token"}
        path, signals = self._respond(options["handle_token"][1], 0, {})
        return "o", (path,), [] if "SelectDevices" in self.silent else signals

    def start(self, body):
        _session, _parent, options = body
        results = {"devices": ("u", self.devices)}
        if self.issued_token:
            results["restore_token"] = ("s", self.issued_token)
        path, signals = self._respond(options["handle_token"][1], self.start_response, results)
        return "o", (path,), [] if "Start" in self.silent else signals

    def keysym(self, body):
        session, _options, keysym, state = body
        assert session == SESSION_PATH
        self.keys.append((keysym, state))
        return None, ()

    def close(self, body):
        self.closed += 1
        return None, ()

    def handlers(self):
        return {
            "CreateSession": self.create,
            "SelectDevices": self.select,
            "Start": self.start,
            "NotifyKeyboardKeysym": self.keysym,
            "Close": self.close,
        }


@pytest.fixture
def fake(tmp_path):
    state = FakePortal()
    with (
        privatebus.private_bus(tmp_path) as address,
        privatebus.fake_service(
            address, portal.SERVICE, {portal.REMOTE_DESKTOP, portal.SESSION}, state.handlers()
        ) as service,
    ):
        state.service, state.address = service, address
        yield state


def keyboard(fake, **kwargs) -> RemoteKeyboard:
    return RemoteKeyboard(fake.address, timeout=2, consent_timeout=2, **kwargs)


class TestSession:
    def test_open_asks_for_keyboard_only_and_persistence(self, fake):
        with keyboard(fake) as kb:
            assert kb.open() == "token-2"
        assert fake.selected == {"types": KEYBOARD, "persist_mode": PERSIST_UNTIL_REVOKED}
        assert fake.closed == 1

    def test_restore_token_is_passed(self, fake):
        with keyboard(fake) as kb:
            kb.open("token-1")
        assert fake.selected["restore_token"] == "token-1"

    def test_no_new_token(self, fake):
        fake.issued_token = None
        with keyboard(fake) as kb:
            assert kb.open() is None

    def test_timings_recorded(self, fake):
        with keyboard(fake) as kb:
            kb.open()
            kb.press(CHORDS["ctrl+v"])
            assert set(kb.timings) == {"create", "select", "start", "press"}

    def test_responses_for_other_requests_are_ignored(self, fake):
        fake.wrong_path_first = True
        with keyboard(fake) as kb:
            assert kb.open() == "token-2"


class TestRefusals:
    @pytest.mark.parametrize("code", [1, 2])
    def test_dialog_cancelled(self, fake, code):
        fake.start_response = code
        with keyboard(fake) as kb, pytest.raises(Refused):
            kb.open()

    @pytest.mark.parametrize("devices", [0, 2, 4])
    def test_keyboard_not_granted(self, fake, devices):
        fake.devices = devices
        with keyboard(fake) as kb, pytest.raises(Refused, match="keyboard"):
            kb.open()

    @pytest.mark.parametrize("method", ["CreateSession", "SelectDevices", "Start"])
    def test_no_answer_times_out(self, fake, method):
        fake.silent = {method}
        with keyboard(fake) as kb, pytest.raises(PortalError, match="no answer"):
            kb.open()

    def test_no_portal(self, tmp_path):
        with (
            privatebus.private_bus(tmp_path) as address,
            RemoteKeyboard(address, timeout=1) as kb,
            pytest.raises(PortalError),
        ):
            kb.open()

    def test_press_without_session(self, fake):
        with keyboard(fake) as kb, pytest.raises(PortalError, match="no portal session"):
            kb.press([1])

    def test_errors_are_value_free(self, fake):
        fake.start_response = 1
        with keyboard(fake) as kb, pytest.raises(Refused) as caught:
            kb.open("secret-token-value")
        assert "secret-token-value" not in str(caught.value)


class TestKeys:
    def test_ctrl_v(self, fake):
        with keyboard(fake) as kb:
            kb.open()
            kb.press(CHORDS["ctrl+v"])
        v = ord("v")
        assert fake.keys == [
            (CONTROL_L, PRESSED),
            (v, PRESSED),
            (v, RELEASED),
            (CONTROL_L, RELEASED),
        ]

    def test_ctrl_shift_v(self, fake):
        with keyboard(fake) as kb:
            kb.open()
            kb.press(CHORDS["ctrl+shift+v"])
        pressed = [k for k, s in fake.keys if s == PRESSED]
        released = [k for k, s in fake.keys if s == RELEASED]
        assert pressed == [CONTROL_L, SHIFT_L, ord("v")]
        assert released == list(reversed(pressed))

    def test_only_two_chords_exist(self):
        assert set(CHORDS) == {"ctrl+v", "ctrl+shift+v"}


class TestToken:
    def test_round_trip_private(self):
        config = paths.config_dir()
        portal.save_token(config, "abc-123")
        assert portal.load_token(config) == "abc-123"
        assert portal.token_path(config).stat().st_mode & 0o777 == 0o600

    def test_forget(self):
        config = paths.config_dir()
        portal.save_token(config, "abc")
        portal.save_token(config, None)
        assert portal.load_token(config) is None
        portal.save_token(config, None)  # twice is fine

    @pytest.mark.parametrize("content", [b"", b"\xff\xfe", b"a\x00b", b"x" * 1000])
    def test_bad_token_means_ask_again(self, content):
        config = paths.config_dir()
        config.mkdir(parents=True, mode=0o700)
        portal.token_path(config).write_bytes(content)
        portal.token_path(config).chmod(0o600)
        assert portal.load_token(config) is None

    def test_missing(self):
        assert portal.load_token(paths.config_dir()) is None


def test_spike_script_is_denied_to_agents():
    import json
    from pathlib import Path

    deny = json.loads(Path(".claude/settings.json").read_text(encoding="utf-8"))["permissions"][
        "deny"
    ]
    assert "Bash(*paste_spike*)" in deny
