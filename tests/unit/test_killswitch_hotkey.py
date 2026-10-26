"""Switching veil OFF from the hotkey (ADR-0018, ADR-0031): one click in a notification, never a
pipe. Switching ON needs nothing.

conftest's `switch_chooser` stands in for the notification (default: no answer), `copy_watcher`
for the watcher service and `switch_timers` for systemd; state lives in the XDG sandbox.
"""

import fnmatch
import io
import sys
import time

import pytest

from tests.unit.test_agent_deny_rules import deny as deny
from tests.unit.test_killswitch import cmd
from tests.unit.test_killswitch import config as config
from veil import killswitch, ui
from veil.clip import notify
from veil.clip.notify import Message, Urgency
from veil.exitcodes import ExitCode
from veil.killswitch import CONFIRM_BUTTONS, CONFIRM_SECONDS, confirm_by_notification
from veil.killswitch import detect_chooser as real_detect_chooser  # bound before conftest

# ── notify.choose: the generic "notification with buttons" ──────────────────

BUTTONS = [("a", "Apple"), ("b", "Banana")]
MESSAGE = Message("Pick?", "one of two", Urgency.CRITICAL, icon="dialog-question")


def fake_notify_send(tmp_path, body: str):
    script = tmp_path / "fake-notify-send"
    script.write_text(f"#!{sys.executable}\n{body}\n")
    script.chmod(0o700)
    return str(script)


class TestChoose:
    def test_argv(self):
        assert notify.choice_argv("/n", MESSAGE, BUTTONS, 7) == [
            "/n", "--app-name=veil", "--urgency=critical", "--icon=dialog-question",
            "--transient", "--wait", "--expire-time=7000", "--action=a=Apple",
            "--action=b=Banana", "--", "Pick?", "one of two",
        ]  # fmt: skip

    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            ("print('b')", "b"),
            ("print('a')", "a"),
            ("print('c')", None),  # not offered
            ("print('')", None),  # closed without a click
            ("import sys; sys.stdout.buffer.write(b'\\xff')", None),
            ("import sys; print('a'); sys.exit(1)", None),  # failed
            ("print('a' * 1000)", None),  # too much output
        ],
    )
    def test_replies(self, tmp_path, body, expected):
        assert notify.choose(fake_notify_send(tmp_path, body), MESSAGE, BUTTONS, 5) == expected

    def test_no_answer_times_out(self, tmp_path, monkeypatch):
        monkeypatch.setattr(notify, "GRACE_SECONDS", 0)
        path = fake_notify_send(tmp_path, "import time; time.sleep(30)")
        start = time.monotonic()
        assert notify.choose(path, MESSAGE, BUTTONS, 1) is None
        assert time.monotonic() - start < 10

    def test_missing_binary(self, tmp_path):
        assert notify.choose(str(tmp_path / "nope"), MESSAGE, BUTTONS, 1) is None


# ── the confirmation ──────────────────────────────────────────────────────────


class Chooser:
    def __init__(self, reply) -> None:
        self.reply, self.asked = reply, []

    def __call__(self, message, actions, timeout):
        self.asked.append((message, list(actions), timeout))
        return self.reply


class TestConfirm:
    @pytest.mark.parametrize(
        ("reply", "expected"),
        [("off", True), ("keep", False), (None, False), ("OFF", False), ("", False)],
    )
    def test_replies(self, reply, expected):
        assert confirm_by_notification(Chooser(reply)) is expected

    def test_no_way_to_ask_keeps_on(self):
        assert confirm_by_notification(None) is False

    def test_question(self):
        chooser = Chooser(None)
        confirm_by_notification(chooser)
        message, actions, timeout = chooser.asked[0]
        assert message.summary == "Switch veil OFF?"
        assert message.urgency is Urgency.CRITICAL
        assert "Copies won't be sanitized any more." in message.body
        assert f"No answer in {CONFIRM_SECONDS} s = veil stays ON." in message.body
        assert timeout == CONFIRM_SECONDS
        assert actions == [("off", "Switch OFF"), ("keep", "Keep ON")]

    def test_detect(self):
        assert real_detect_chooser(lambda name: None) is None
        assert callable(real_detect_chooser(lambda name: "/usr/bin/" + name))


# ── CLI ───────────────────────────────────────────────────────────────────────


@pytest.fixture
def on(capsys, copy_watcher):
    assert cmd(capsys, "on")[0] == ExitCode.OK
    return copy_watcher


@pytest.mark.parametrize("command", ["off", "toggle"])
class TestFromHotkey:
    def test_click(self, capsys, on, switch_chooser, notifications, command):
        switch_chooser.reply = "off"
        code, out, _ = cmd(capsys, command, "--from-hotkey")
        assert code == ExitCode.OK
        assert out == "veil: OFF, copy and paste are normal\n"
        assert not on.running
        assert notifications[-1].summary == "veil OFF"

    @pytest.mark.parametrize("reply", [None, "keep", "nonsense"])
    def test_no_click_keeps_on(self, capsys, on, switch_chooser, command, reply):
        switch_chooser.reply = reply
        code, _, err = cmd(capsys, command, "--from-hotkey")
        assert code == ExitCode.ABORTED
        assert "Switch OFF wasn't clicked); veil stays ON" in err
        assert on.running

    def test_no_notify_send_keeps_on(self, capsys, on, monkeypatch, command):
        monkeypatch.setattr(killswitch, "detect_chooser", lambda *a, **k: None)
        code, _, err = cmd(capsys, command, "--from-hotkey")
        assert code == ExitCode.ABORTED
        assert "notify-send is missing" in err
        assert on.running

    def test_needs_no_terminal_and_ignores_stdin(self, capsys, on, monkeypatch, command):
        # The hotkey has no terminal. Typing "off" into stdin must not count as a click.
        monkeypatch.setattr(sys, "stdin", io.StringIO("off\n"))
        monkeypatch.setattr(ui, "_isatty", lambda _stream: True)
        code, _, _ = cmd(capsys, command, "--from-hotkey")
        assert code == ExitCode.ABORTED
        assert on.running
        assert sys.stdin.read() == "off\n"  # never read


def test_toggle_from_hotkey_switches_on_without_asking(capsys, copy_watcher, switch_chooser):
    code, out, _ = cmd(capsys, "toggle", "--from-hotkey")
    assert code == ExitCode.OK
    assert out == "veil: ON, every copy is sanitized\n"
    assert copy_watcher.running
    assert switch_chooser.asked == []


def test_without_flag_still_needs_the_terminal(capsys, on, switch_chooser):
    switch_chooser.reply = "off"  # a click is ignored without --from-hotkey
    assert cmd(capsys, "off")[0] == ExitCode.UNSAFE_ENVIRONMENT
    assert switch_chooser.asked == []
    assert on.running


def test_on_has_no_hotkey_flag(capsys):
    with pytest.raises(SystemExit) as caught:
        cmd(capsys, "on", "--from-hotkey")
    assert caught.value.code == ExitCode.USAGE  # `on` never asks


@pytest.mark.parametrize(
    "command",
    [
        "uv run veil off --from-hotkey",
        "uv run veil toggle --from-hotkey",
        "python -m veil off --from-hotkey",
        "uv run veil on",
        "veil disable",
    ],
)
def test_agent_deny_rules_cover_the_switch(deny, command):
    patterns = [rule[len("Bash(") : -1] for rule in deny if rule.startswith("Bash(")]
    assert any(fnmatch.fnmatchcase(command, p) for p in patterns), command


# ── buttons fit (owner's screenshot: Plasma cut "Off for 30 m…") ──────────────


def test_kill_switch_buttons_fit():
    assert all(len(label) <= killswitch.MAX_BUTTON_LABEL for _, label in CONFIRM_BUTTONS)


def test_ask_before_send_buttons_fit():
    from veil.clip.ask import ACTIONS

    assert all(len(label) <= killswitch.MAX_BUTTON_LABEL for _, label in ACTIONS)
