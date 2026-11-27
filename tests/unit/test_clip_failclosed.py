"""Fail closed (M2.5, spec §4.4): any error in sanitize / from-selection leaves nothing real on
the clipboard: placeholder, then clear, then a critical notification. Fault injection at every
step, in-memory clipboard, synthetic persona. Restore errors leave the clipboard alone.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.helpers.fakeclip import FakeBoard
from tests.unit.test_clip_commands import FAKES, REAL, REALS, Loader, assert_no_reals, run
from tests.unit.test_clip_commands import board as board
from tests.unit.test_clip_commands import engine as engine
from tests.unit.test_textcmd import imported  # noqa: F401 - pytest fixture
from veil.clip import commands, messages
from veil.clip import io as clipio
from veil.clip.commands import ERROR_PLACEHOLDER, WAITING_PLACEHOLDER, Scrub
from veil.clip.io import Selection
from veil.clip.io import detect as REAL_DETECT  # bound before conftest guards it
from veil.clip.notify import Urgency
from veil.engine import load as engine_load
from veil.engine.matcher import Engine
from veil.errors import Aborted, ClipboardError, DecryptFailed, KeyUnavailable, VeilError
from veil.exitcodes import ExitCode

FORWARD = ("sanitize", "from-selection")
SENSITIVE = "Jane Doe has asthma.\n"


def put(board: FakeBoard, command: str, text: str = REAL) -> None:
    """The text where `command` reads it; CLIPBOARD always starts with real text."""
    board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
    if command == "from-selection":
        board.offers[Selection.PRIMARY] = {"text/plain": text.encode()}
    else:
        board.offers[Selection.CLIPBOARD] = {"text/plain": text.encode()}


def no_values(*texts: str) -> None:
    assert_no_reals(*texts)
    for text in texts:
        for fake in FAKES:
            assert fake not in text, fake


class Flaky:
    """A board method that raises `error` (any exception type) instead of working."""

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def __call__(self, *args, **kwargs):
        raise self.error


# ── fail_closed itself ────────────────────────────────────────────────────────


class TestFailClosed:
    def test_placeholder_then_clear(self):
        board = FakeBoard.with_text(REAL)
        assert commands.fail_closed(board) is Scrub.CLEARED
        assert board.writes == [ERROR_PLACEHOLDER]
        assert board.clears == [Selection.CLIPBOARD]
        assert board.text() is None

    def test_clear_fails_placeholder_remains(self):
        board = FakeBoard.with_text(REAL)
        board.fail_clear = True
        assert commands.fail_closed(board) is Scrub.REPLACED
        assert board.text() == ERROR_PLACEHOLDER

    def test_write_fails_clear_still_tried(self):
        board = FakeBoard.with_text(REAL)
        board.fail_write = True
        # Cleared, but with no placeholder in front Klipper may restore the original: the
        # honest report is FAILED ("do not paste"; sweep 2026-10-26).
        assert commands.fail_closed(board) is Scrub.FAILED
        assert board.text() is None

    def test_both_fail(self):
        board = FakeBoard.with_text(REAL)
        board.fail_write = board.fail_clear = True
        assert commands.fail_closed(board) is Scrub.FAILED
        assert board.text() == REAL  # reported as NOT cleared

    def test_no_board(self):
        assert commands.fail_closed(None) is Scrub.FAILED

    @pytest.mark.parametrize("error", [RuntimeError("x"), OSError(5, "io"), ValueError()])
    def test_never_raises(self, error):
        board = FakeBoard.with_text(REAL)
        board.write_text = Flaky(error)
        board.clear = Flaky(error)
        assert commands.fail_closed(board) is Scrub.FAILED

    def test_primary_is_left_alone(self):
        board = FakeBoard.with_text(REAL, primary={"text/plain": b"selected"})
        commands.fail_closed(board)
        assert board.offers[Selection.PRIMARY] == {"text/plain": b"selected"}

    def test_placeholder_is_harmless(self):
        no_values(ERROR_PLACEHOLDER)
        assert ERROR_PLACEHOLDER != WAITING_PLACEHOLDER
        assert ERROR_PLACEHOLDER.startswith("[veil: ")


# ── the invariant, over every combination of faults ───────────────────────────

FAULTS = st.fixed_dictionaries(
    {
        "read": st.booleans(),
        "write": st.booleans(),
        "clear": st.booleans(),
        "load": st.sampled_from([None, KeyUnavailable("k"), DecryptFailed("d"), Aborted("a")]),
        "crash": st.booleans(),
        "selection": st.booleans(),
    }
)


@given(faults=FAULTS)
def test_property_original_never_left_unless_reported(engine, faults):
    board = FakeBoard.with_text(REAL, primary={"text/plain": REAL.encode()})
    board.fail_read, board.fail_write, board.fail_clear = (
        faults["read"],
        faults["write"],
        faults["clear"],
    )
    loaded = engine
    if faults["crash"]:
        loaded = Engine(engine.lexicon)
        loaded.forward_counted = Flaky(RuntimeError(REAL))
    command = commands.from_selection if faults["selection"] else commands.sanitize
    try:
        outcome = command(board, Loader(loaded, faults["load"]))
    except Exception:  # noqa: BLE001 - every error must end in fail_closed
        scrub = commands.fail_closed(board)
        if scrub is Scrub.FAILED:
            assert faults["write"]  # the placeholder couldn't be written
        else:
            assert board.text() in (None, ERROR_PLACEHOLDER)
    else:
        assert outcome.changed
        assert_no_reals(board.text() or "")


# ── CLI end to end ────────────────────────────────────────────────────────────


@pytest.fixture
def failing_load(monkeypatch):
    def install(error: BaseException) -> None:
        def load_engine(*args, **kwargs):
            raise error

        monkeypatch.setattr(engine_load, "load_engine", load_engine)

    return install


@pytest.mark.parametrize("command", FORWARD)
class TestCliFailClosed:
    @pytest.mark.parametrize(
        ("error", "code"),
        [
            (KeyUnavailable("the keyring is locked"), ExitCode.KEY_UNAVAILABLE),
            (DecryptFailed("the persona store could not be decrypted"), ExitCode.DECRYPT_FAILED),
            (Aborted("cancelled"), ExitCode.ABORTED),
            (RuntimeError(REAL), ExitCode.INTERNAL),
            (KeyboardInterrupt(), ExitCode.INTERRUPTED),
        ],
    )
    def test_load_errors_clear(
        self, board, capsys, notifications, failing_load, command, error, code
    ):
        put(board, command)
        failing_load(error)
        got, out, err = run(capsys, command)
        assert got == code
        assert board.text() is None
        assert board.writes == [ERROR_PLACEHOLDER]
        assert "clipboard cleared (fail closed)" in err
        assert len(notifications) == 1
        shown = notifications[0]
        assert shown.summary == "veil error: clipboard cleared"
        assert shown.urgency is Urgency.CRITICAL
        no_values(out, err, shown.summary, shown.body)

    def test_error_detail_is_value_free(self, board, capsys, notifications, failing_load, command):
        put(board, command)
        failing_load(RuntimeError(f"bad {REAL}"))
        _, _, err = run(capsys, command)
        assert notifications[0].body.endswith("(internal error (RuntimeError))")
        no_values(err, notifications[0].body)

    def test_interrupt_detail(self, board, capsys, notifications, failing_load, command):
        put(board, command)
        failing_load(KeyboardInterrupt())
        run(capsys, command)
        assert notifications[0].body.endswith("(interrupted)")

    def test_veil_error_detail(self, board, capsys, notifications, failing_load, command):
        put(board, command)
        failing_load(KeyUnavailable("the keyring is locked"))
        run(capsys, command)
        assert notifications[0].body.endswith("(the keyring is locked)")

    def test_read_failure_clears(self, board, capsys, notifications, command):
        put(board, command)
        board.fail_read = True
        got, _, _ = run(capsys, command)
        assert got == ExitCode.CLIPBOARD
        assert board.text() is None
        assert notifications[0].summary == "veil error: clipboard cleared"

    @pytest.mark.usefixtures("imported")
    def test_translation_crash_clears(self, board, capsys, notifications, monkeypatch, command):
        put(board, command)
        monkeypatch.setattr(Engine, "forward_counted", Flaky(RuntimeError(REAL)))
        got, out, err = run(capsys, command)
        assert got == ExitCode.INTERNAL
        assert board.text() is None
        no_values(out, err, notifications[0].body)

    @pytest.mark.usefixtures("imported")
    def test_write_failure_still_clears(self, board, capsys, notifications, command):
        put(board, command)
        board.fail_write = True
        got, _, _ = run(capsys, command)
        assert got == ExitCode.CLIPBOARD
        assert board.text() is None
        assert notifications[0].summary == "veil error: clipboard NOT cleared"

    @pytest.mark.usefixtures("imported")
    def test_clear_failure_leaves_placeholder(
        self, board, capsys, notifications, monkeypatch, command
    ):
        put(board, command)
        board.fail_clear = True
        monkeypatch.setattr(Engine, "forward_counted", Flaky(RuntimeError()))
        got, _, err = run(capsys, command)
        assert got == ExitCode.INTERNAL
        assert board.text() == ERROR_PLACEHOLDER
        assert "replaced by a placeholder" in err
        assert notifications[0].summary == "veil error: clipboard replaced"

    @pytest.mark.usefixtures("imported")
    def test_nothing_works_says_not_cleared(self, board, capsys, notifications, command):
        put(board, command)
        board.fail_write = board.fail_clear = True
        got, _, err = run(capsys, command)
        assert got == ExitCode.CLIPBOARD
        assert "clipboard NOT cleared: do not paste" in err
        assert notifications[0].summary == "veil error: clipboard NOT cleared"
        assert notifications[0].urgency is Urgency.CRITICAL

    @pytest.mark.usefixtures("imported")
    def test_asker_crash_clears(self, board, capsys, notifications, asker, command):
        put(board, command, SENSITIVE)
        asker.answer = "not-a-decision"  # the scripted asker raises ValueError
        got, _, _ = run(capsys, command)
        assert got == ExitCode.INTERNAL
        assert board.writes == [WAITING_PLACEHOLDER, ERROR_PLACEHOLDER]
        assert board.text() is None

    @pytest.mark.usefixtures("imported")
    def test_deny_clear_failure_is_fail_closed(self, board, capsys, notifications, asker, command):
        put(board, command, SENSITIVE)
        board.fail_clear = True
        got, _, _ = run(capsys, command)
        assert got == ExitCode.CLIPBOARD
        assert board.text() == ERROR_PLACEHOLDER
        assert notifications[-1].summary == "veil error: clipboard replaced"

    def test_no_notify_still_clears_and_reports(
        self, board, capsys, notifications, failing_load, command
    ):
        put(board, command)
        failing_load(KeyUnavailable("the keyring is locked"))
        got, _, err = run(capsys, command, "--no-notify")
        assert got == ExitCode.KEY_UNAVAILABLE
        assert board.text() is None
        assert notifications == []
        assert err == (
            "veil: clipboard cleared (fail closed); copy the text again and retry\n"
            "veil: the keyring is locked\n"
        )

    def test_failing_notifier_keeps_exit_code(
        self, board, capsys, monkeypatch, failing_load, command
    ):
        from veil.clip import notify

        monkeypatch.setattr(notify, "detect", lambda *a, **k: notify.NullNotifier())
        put(board, command)
        failing_load(DecryptFailed("bad"))
        got, _, _ = run(capsys, command)
        assert got == ExitCode.DECRYPT_FAILED
        assert board.text() is None

    def test_from_selection_leaves_primary(self, board, capsys, failing_load, command):
        put(board, command)
        failing_load(KeyUnavailable("k"))
        before = dict(board.offers[Selection.PRIMARY] or {})
        run(capsys, command)
        assert dict(board.offers[Selection.PRIMARY] or {}) == before

    def test_no_clipboard_tool(self, monkeypatch, capsys, notifications, command):
        monkeypatch.setattr(clipio, "detect", REAL_DETECT)  # no display set: finds no tool
        got, _, err = run(capsys, command)
        assert got == ExitCode.CLIPBOARD
        assert "clipboard NOT cleared" in err
        assert notifications[0].summary == "veil error: clipboard NOT cleared"


class TestRestoreErrors:
    """Restore reads fake text; on an error there is nothing to protect, so nothing is cleared."""

    @pytest.mark.parametrize(
        "error", [KeyUnavailable("the keyring is locked"), RuntimeError(REAL), KeyboardInterrupt()]
    )
    def test_clipboard_unchanged(self, board, capsys, notifications, failing_load, error):
        fake = "Alex Smith wrote this.\n"
        board.offers[Selection.CLIPBOARD] = {"text/plain": fake.encode()}
        failing_load(error)
        got, out, err = run(capsys, "restore")
        assert got != ExitCode.OK
        assert board.text() == fake
        assert board.writes == []
        assert board.clears == []
        assert "nothing restored; the clipboard is unchanged" in err
        assert notifications[-1].summary == "veil error: nothing restored"
        assert_no_reals(out, err, notifications[-1].body)

    def test_write_failure(self, board, capsys, notifications, failing_load):
        board.offers[Selection.CLIPBOARD] = {"text/plain": b"x"}
        board.fail_write = True
        failing_load(KeyUnavailable("k"))
        run(capsys, "restore")
        assert board.clears == []


def test_error_detail():
    assert messages.error_detail(VeilError("safe text")) == "safe text"
    assert messages.error_detail(KeyboardInterrupt()) == "interrupted"
    assert messages.error_detail(RuntimeError(REAL)) == "internal error (RuntimeError)"
    assert messages.error_detail(ClipboardError("wl-copy failed (exit 1)")) == (
        "wl-copy failed (exit 1)"
    )
    for real in REALS:
        assert real not in messages.error_detail(ValueError(real))
