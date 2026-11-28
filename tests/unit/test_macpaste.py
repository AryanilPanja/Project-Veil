"""macOS sanitize-then-paste (`veil clip paste` on darwin via CGEventPost + Accessibility)."""

import sys

import pytest

from tests.unit.test_clip_commands import FAKE, REAL, assert_no_reals, run
from tests.unit.test_clip_commands import board as board
from tests.unit.test_textcmd import imported  # noqa: F401 - pytest fixture
from veil import paths
from veil.clip import macpaste, messages, paste
from veil.clip.commands import Action, Outcome, Pasted
from veil.clip.io import Selection
from veil.exitcodes import ExitCode

CMD_V = macpaste.CHORDS["cmd+v"]
RealMacKeyboard = macpaste.MacKeyboard  # bound before conftest replaces MacKeyboard


@pytest.fixture(autouse=True)
def _darwin(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")


class Clock:
    def __init__(self, now: float) -> None:
        self.now, self.slept = now, []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(round(seconds, 4))
        self.now += seconds


class TestMacPasteUnit:
    def test_chord_is_cmd_v_even_in_terminal(self):
        assert paste.chord(terminal=False) == "cmd+v"
        assert paste.chord(terminal=True) == "cmd+v"

    def test_wait_for_modifiers_returns_immediately_when_clear(self):
        clock = Clock(10.0)
        macpaste.wait_for_modifiers(10.35, flags=lambda: 0, clock=clock, sleep=clock.sleep)
        assert clock.slept == []

    def test_wait_for_modifiers_stops_once_released(self):
        clock = Clock(10.0)
        states = iter([macpaste._FLAG_CONTROL | macpaste._FLAG_OPTION, macpaste._FLAG_OPTION, 0])
        macpaste.wait_for_modifiers(
            10.35, flags=lambda: next(states, 0), clock=clock, sleep=clock.sleep
        )
        assert len(clock.slept) == 2

    def test_wait_for_modifiers_stops_at_deadline(self):
        clock = Clock(10.33)
        macpaste.wait_for_modifiers(
            10.35, flags=lambda: macpaste._FLAG_OPTION, clock=clock, sleep=clock.sleep
        )
        assert sum(clock.slept) == pytest.approx(0.02, abs=1e-6)

    def test_mac_keyboard_refuses_when_not_trusted(self, monkeypatch):
        monkeypatch.setattr(macpaste, "is_trusted", lambda: False)
        with pytest.raises(macpaste.Refused):
            RealMacKeyboard().open()

    def test_mac_keyboard_posts_keydown_and_keyup_with_command_flag(self, monkeypatch):
        monkeypatch.setattr(macpaste, "is_trusted", lambda: True)
        posted: list[tuple[int, int, bool, int]] = []
        released: list[int] = []
        tokens = iter([101, 102])

        class FakeCF:
            @staticmethod
            def CFRelease(obj):
                released.append(obj)

        class FakeCG:
            @staticmethod
            def CGEventCreateKeyboardEvent(_src, keycode, down):
                ev = next(tokens)
                posted.append((ev, keycode, down, -1))
                return ev

            @staticmethod
            def CGEventSetFlags(ev, flags):
                for i, item in enumerate(posted):
                    if item[0] == ev:
                        posted[i] = (item[0], item[1], item[2], flags)

            @staticmethod
            def CGEventPost(tap, ev):
                assert tap == macpaste._HID_EVENT_TAP
                assert any(item[0] == ev for item in posted)

        monkeypatch.setattr(macpaste, "_frameworks", lambda: (object(), FakeCF, FakeCG))
        kb = RealMacKeyboard()
        assert kb.open() is None
        kb.press(CMD_V)
        kb.close()
        assert posted == [
            (101, macpaste._VK_ANSI_V, True, macpaste._FLAG_COMMAND),
            (102, macpaste._VK_ANSI_V, False, macpaste._FLAG_COMMAND),
        ]
        assert released == [101, 102]


class TestMacMessages:
    def test_not_pasted_uses_cmd_v(self):
        outcome = Outcome(Action.SANITIZE, replaced={"name": 1}, pasted=Pasted.REFUSED)
        assert "Not pasted: press Cmd+V yourself." in messages.notification(outcome).body
        line = messages.stderr_lines(outcome)[-1]
        assert "Accessibility permission required" in line
        assert "press Cmd+V yourself" in line


@pytest.mark.usefixtures("imported")
class TestMacPasteCli:
    def test_sanitize_then_paste_uses_cmd_v(self, board, capsys, portal_keyboard, notifications):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        code, out, err = run(capsys, "paste")
        assert code == ExitCode.OK
        assert board.text() == FAKE
        assert portal_keyboard.pressed == [CMD_V]
        assert err.splitlines()[-1] == "veil: pasted"
        assert notifications[-1].body.endswith("Pasted.")
        assert_no_reals(out, err, notifications[-1].body)

    def test_refused_without_accessibility(self, board, capsys, portal_keyboard, notifications):
        portal_keyboard.refuse = True
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        code, _, err = run(capsys, "paste")
        assert code == ExitCode.OK
        assert board.text() == FAKE
        assert "Accessibility permission" in err
        assert "press Cmd+V yourself" in err
        assert "press Cmd+V yourself" in notifications[-1].body
        assert paste.inject("cmd+v", config=paths.config_dir(), started=0) is Pasted.REFUSED
