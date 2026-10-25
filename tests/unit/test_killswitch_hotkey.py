"""Switching off from the hotkey (M3.2, ADR-0018): a click in a notification, never a pipe.

conftest's `switch_chooser` stands in for the notification (default: no answer), and
`switch_timers` for systemd; the state file lives in the per-test XDG sandbox.
"""

import fnmatch
import io
import sys
import time
from datetime import timedelta

import pytest

from tests.unit.test_agent_deny_rules import deny as deny
from tests.unit.test_killswitch import cmd, state_file
from tests.unit.test_killswitch import config as config
from veil import killswitch, ui
from veil.clip import notify
from veil.clip.notify import Message, Urgency
from veil.exitcodes import ExitCode
from veil.killswitch import (
    CONFIRM_SECONDS,
    HOTKEY_DEFAULT_FOR,
    ON,
    Switch,
    confirm_buttons,
    confirm_by_notification,
    read,
    write,
)
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
        ("reply", "duration", "expected"),
        [
            ("off-default", None, (True, HOTKEY_DEFAULT_FOR)),
            ("off", None, (True, None)),
            ("keep", None, (False, None)),
            (None, None, (False, None)),
            ("OFF", None, (False, None)),
            ("off-default", timedelta(hours=2), (False, None)),  # not offered with --for
            ("off", timedelta(hours=2), (True, timedelta(hours=2))),
            ("keep", timedelta(hours=2), (False, None)),
        ],
    )
    def test_replies(self, reply, duration, expected):
        assert confirm_by_notification(Chooser(reply), duration) == expected

    def test_no_way_to_ask_keeps_on(self):
        assert confirm_by_notification(None, None) == (False, None)

    def test_question(self):
        chooser = Chooser(None)
        confirm_by_notification(chooser, None)
        message, actions, timeout = chooser.asked[0]
        assert message.summary == "Switch veil OFF?"
        assert message.urgency is Urgency.CRITICAL
        assert f"No answer in {CONFIRM_SECONDS} s = veil stays ON." in message.body
        assert timeout == CONFIRM_SECONDS
        assert actions == [
            ("off-default", "Off for 30 min"),
            ("off", "Off until `veil on`"),
            ("keep", "Keep ON"),
        ]

    def test_buttons_with_duration(self):
        assert confirm_buttons(timedelta(minutes=90)) == [
            ("off", "Off for 1 h 30 min"),
            ("keep", "Keep ON"),
        ]

    def test_detect(self):
        assert real_detect_chooser(lambda name: None) is None
        assert callable(real_detect_chooser(lambda name: "/usr/bin/" + name))


# ── CLI ───────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("command", ["off", "toggle"])
class TestFromHotkey:
    def test_click_off(self, capsys, config, switch_chooser, switch_timers, notifications, command):
        switch_chooser.reply = "off"
        code, out, _ = cmd(capsys, command, "--from-hotkey")
        assert code == ExitCode.OK
        assert out.startswith("veil: OFF since ")
        assert read(config).switch.until is None
        assert len(switch_timers.scheduled) == 1
        assert notifications[-1].summary == "veil is OFF"

    def test_click_default(self, capsys, config, switch_chooser, command):
        switch_chooser.reply = "off-default"
        cmd(capsys, command, "--from-hotkey")
        switch = read(config).switch
        assert switch.until - switch.since == HOTKEY_DEFAULT_FOR

    def test_with_for(self, capsys, config, switch_chooser, command):
        switch_chooser.reply = "off"
        cmd(capsys, command, "--from-hotkey", "--for", "2h")
        switch = read(config).switch
        assert switch.until - switch.since == timedelta(hours=2)
        assert [name for name, _ in switch_chooser.asked[0][1]] == ["off", "keep"]

    @pytest.mark.parametrize("reply", [None, "keep", "nonsense"])
    def test_no_click_keeps_on(self, capsys, config, switch_chooser, switch_timers, command, reply):
        switch_chooser.reply = reply
        code, _, err = cmd(capsys, command, "--from-hotkey")
        assert code == ExitCode.ABORTED
        assert "no Off button clicked); veil stays ON" in err
        assert read(config).switch == ON
        assert switch_timers.scheduled == []

    def test_no_notify_send_keeps_on(self, capsys, config, monkeypatch, command):
        monkeypatch.setattr(killswitch, "detect_chooser", lambda *a, **k: None)
        code, _, err = cmd(capsys, command, "--from-hotkey")
        assert code == ExitCode.ABORTED
        assert "notify-send is missing" in err
        assert read(config).switch == ON

    def test_needs_no_terminal_and_ignores_stdin(self, capsys, config, monkeypatch, command):
        # The hotkey has no terminal. Typing "off" into stdin must not count as a click.
        monkeypatch.setattr(sys, "stdin", io.StringIO("off\n"))
        monkeypatch.setattr(ui, "_isatty", lambda _stream: True)
        code, _, _ = cmd(capsys, command, "--from-hotkey")
        assert code == ExitCode.ABORTED
        assert read(config).switch == ON
        assert sys.stdin.read() == "off\n"  # never read

    def test_since_is_the_click_time(self, capsys, config, switch_chooser, monkeypatch, command):
        later = killswitch.utc_now() + timedelta(seconds=25)

        def click(message, actions, timeout):
            monkeypatch.setattr(killswitch, "utc_now", lambda: later)
            return "off-default"

        monkeypatch.setattr(killswitch, "detect_chooser", lambda *a, **k: click)
        cmd(capsys, command, "--from-hotkey")
        switch = read(config).switch
        assert switch.since == later.replace(microsecond=0)
        assert switch.until - switch.since == HOTKEY_DEFAULT_FOR


def test_toggle_from_hotkey_switches_on_without_asking(capsys, config, switch_chooser):
    write(config, Switch(True, killswitch.utc_now()))
    code, out, _ = cmd(capsys, "toggle", "--from-hotkey")
    assert code == ExitCode.OK
    assert out == "veil: ON\n"
    assert switch_chooser.asked == []


def test_without_flag_still_needs_the_terminal(capsys, config, switch_chooser):
    switch_chooser.reply = "off"  # a click is ignored without --from-hotkey
    assert cmd(capsys, "off")[0] == ExitCode.UNSAFE_ENVIRONMENT
    assert switch_chooser.asked == []
    assert read(config).switch == ON


def test_on_has_no_hotkey_flag(capsys):
    with pytest.raises(SystemExit) as caught:
        cmd(capsys, "on", "--from-hotkey")
    assert caught.value.code == ExitCode.USAGE  # `on` has no such flag: it never asks


@pytest.mark.parametrize(
    "command",
    [
        "uv run veil off --from-hotkey",
        "uv run veil toggle --from-hotkey --for 2h",
        "python -m veil off --from-hotkey",
        "veil disable",
    ],
)
def test_agent_deny_rules_cover_the_hotkey_forms(deny, command):
    patterns = [rule[len("Bash(") : -1] for rule in deny if rule.startswith("Bash(")]
    assert any(fnmatch.fnmatchcase(command, p) for p in patterns), command


def test_state_untouched_by_a_failed_hotkey(capsys, config):
    cmd(capsys, "off", "--from-hotkey")
    assert not state_file(config).exists()
