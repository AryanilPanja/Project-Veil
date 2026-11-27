"""`veil clip paste` (M3.5, ADR-0030): sanitize, then press Ctrl+V / Ctrl+Shift+V via the portal.

conftest's `portal_keyboard` records every chord instead of typing (and zeroes the release
wait). Synthetic persona, in-memory clipboard.
"""

import pytest

from tests.unit.test_clip_commands import FAKE, FAKES, REAL, assert_no_reals, run
from tests.unit.test_clip_commands import board as board
from tests.unit.test_textcmd import imported  # noqa: F401 - pytest fixture
from veil import paths
from veil.clip import messages, paste, portal
from veil.clip.commands import Action, Outcome, Pasted, Skip
from veil.clip.io import Selection
from veil.clip.notify import Urgency
from veil.exitcodes import ExitCode

CTRL_V = portal.CHORDS["ctrl+v"]
CTRL_SHIFT_V = portal.CHORDS["ctrl+shift+v"]
SENSITIVE = "Jane Doe has asthma.\n"


def no_values(*texts: str) -> None:
    assert_no_reals(*texts)
    for text in texts:
        for fake in FAKES:
            assert fake not in text


class TestShouldPaste:
    def test_after_a_sanitize(self):
        assert paste.should_paste(Outcome(Action.SANITIZE))

    @pytest.mark.parametrize("skip", list(Skip))
    def test_never_after_a_skip(self, skip):
        assert not paste.should_paste(Outcome(Action.SANITIZE, skip))


class Clock:
    def __init__(self, now: float) -> None:
        self.now, self.slept = now, []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(round(seconds, 3))
        self.now += seconds


class TestInject:
    def test_presses_the_chord(self, portal_keyboard):
        assert paste.inject("ctrl+v", config=paths.config_dir(), started=0) is Pasted.PASTED
        assert portal_keyboard.pressed == [CTRL_V]
        assert portal_keyboard.keyboards[0].closed

    def test_terminal_chord(self, portal_keyboard):
        paste.inject(paste.chord(terminal=True), config=paths.config_dir(), started=0)
        assert portal_keyboard.pressed == [CTRL_SHIFT_V]

    def test_token_is_reused_and_renewed(self, portal_keyboard):
        config = paths.config_dir()
        portal.save_token(config, "token-1")
        paste.inject("ctrl+v", config=config, started=0)
        assert portal_keyboard.keyboards[0].opened_with == ["token-1"]
        assert portal.load_token(config) == "restored-token"

    def test_refused(self, portal_keyboard):
        portal_keyboard.refuse = True
        assert paste.inject("ctrl+v", config=paths.config_dir(), started=0) is Pasted.REFUSED
        assert portal_keyboard.pressed == []
        assert portal_keyboard.keyboards[0].closed

    def test_failed(self, portal_keyboard):
        portal_keyboard.fail = True
        assert paste.inject("ctrl+v", config=paths.config_dir(), started=0) is Pasted.FAILED

    def test_waits_for_the_keys_to_be_released(self, monkeypatch):
        monkeypatch.setattr(paste, "RELEASE_WAIT", 0.35)
        clock = Clock(10.1)
        paste.inject(
            "ctrl+v", config=paths.config_dir(), started=10.0, clock=clock, sleep=clock.sleep
        )
        assert clock.slept == [0.25]

    def test_no_wait_when_already_late(self, monkeypatch):
        monkeypatch.setattr(paste, "RELEASE_WAIT", 0.35)
        clock = Clock(11.0)
        paste.inject(
            "ctrl+v", config=paths.config_dir(), started=10.0, clock=clock, sleep=clock.sleep
        )
        assert clock.slept == []


class TestMessages:
    def test_pasted(self):
        outcome = Outcome(Action.SANITIZE, replaced={"name": 1}, pasted=Pasted.PASTED)
        assert messages.notification(outcome).body.endswith("Plain text only. Pasted.")
        assert messages.stderr_lines(outcome)[-1] == "veil: pasted"

    @pytest.mark.parametrize("result", [Pasted.REFUSED, Pasted.FAILED])
    def test_not_pasted(self, result):
        outcome = Outcome(Action.SANITIZE, replaced={"name": 1}, pasted=result)
        assert "Not pasted: press Ctrl+V yourself." in messages.notification(outcome).body
        assert messages.stderr_lines(outcome)[-1].endswith("press Ctrl+V yourself")


@pytest.mark.usefixtures("imported")
class TestCli:
    def test_sanitize_then_paste(self, board, capsys, portal_keyboard, notifications):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        code, out, err = run(capsys, "paste")
        assert code == ExitCode.OK
        assert board.text() == FAKE
        assert portal_keyboard.pressed == [CTRL_V]
        assert err.splitlines()[-1] == "veil: pasted"
        assert notifications[-1].body.endswith("Pasted.")
        no_values(out, err, notifications[-1].body)

    def test_terminal(self, board, capsys, portal_keyboard):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        run(capsys, "paste", "--terminal")
        assert portal_keyboard.pressed == [CTRL_SHIFT_V]

    @pytest.mark.parametrize("offer", [{"text/html": b"<b>x</b>"}, {"image/png": b"x"}, None])
    def test_skips_are_not_pasted(self, board, capsys, portal_keyboard, offer):
        board.offers[Selection.CLIPBOARD] = offer
        assert run(capsys, "paste")[0] == ExitCode.OK
        assert portal_keyboard.pressed == []

    def test_rich_only_warns(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {"text/html": b"<b>x</b>"}
        run(capsys, "paste")
        assert notifications[-1].urgency is Urgency.CRITICAL

    def test_deny_is_not_pasted(self, board, capsys, portal_keyboard):
        board.offers[Selection.CLIPBOARD] = {"text/plain": SENSITIVE.encode()}
        run(capsys, "paste")  # the scripted asker answers Deny
        assert portal_keyboard.pressed == []
        assert board.text() is None

    def test_error_is_not_pasted(self, board, capsys, portal_keyboard):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        board.fail_write = True
        code, _, _ = run(capsys, "paste")
        assert code == ExitCode.CLIPBOARD
        assert portal_keyboard.pressed == []
        assert board.text() is None  # fail closed

    def test_refused_leaves_sanitized_text(self, board, capsys, portal_keyboard, notifications):
        portal_keyboard.refuse = True
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        code, _, err = run(capsys, "paste")
        assert code == ExitCode.OK
        assert board.text() == FAKE
        assert "press Ctrl+V yourself" in err
        assert "Not pasted" in notifications[-1].body

    def test_works_while_veil_is_off(self, board, capsys, portal_keyboard, copy_watcher):
        # ADR-0031: OFF only stops the copy watcher; a hotkey you press still does its job.
        assert not copy_watcher.running
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        run(capsys, "paste")
        assert board.text() == FAKE
        assert portal_keyboard.pressed == [CTRL_V]


def test_only_two_chords_exist():
    assert set(portal.CHORDS) == {"ctrl+v", "ctrl+shift+v"}
    for chord in portal.CHORDS.values():
        assert all(isinstance(k, int) for k in chord)
