"""The kill switch (M3.1, ADR-0018): state file, transitions, expiry, timers, CLI, clip no-op.

Every test runs in the per-test XDG sandbox (conftest), so the owner's real state file is never
read or written, and conftest's `switch_timers` fixture keeps systemd-run from ever running.
"""

import io
import json
import sys
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.unit.test_clip_commands import REAL, run
from tests.unit.test_clip_commands import board as board
from veil import cli, killswitch, paths, ui
from veil.clip import messages
from veil.clip.commands import Action, Outcome, Skip
from veil.clip.io import Selection
from veil.clip.notify import Urgency
from veil.exitcodes import ExitCode
from veil.killswitch import (
    ON,
    Reading,
    Switch,
    SystemdTimers,
    describe_duration,
    parse_duration,
    read,
    status_line,
    switch_off,
    switch_on,
    write,
)

T0 = datetime(2026, 10, 25, 12, 0, tzinfo=UTC)
M30 = timedelta(minutes=30)


@pytest.fixture
def config():
    return paths.config_dir()


def state_file(config):
    return killswitch.state_path(config)


# ── state file ────────────────────────────────────────────────────────────────


class TestState:
    def test_missing_is_on(self, config):
        assert read(config) == Reading(ON)

    @pytest.mark.parametrize("switch", [ON, Switch(True, T0, None), Switch(True, T0, T0 + M30)])
    def test_round_trip(self, config, switch):
        write(config, switch)
        assert read(config) == Reading(switch)

    def test_private_modes(self, config):
        write(config, Switch(True, T0))
        assert state_file(config).stat().st_mode & 0o777 == 0o600
        assert config.stat().st_mode & 0o777 == 0o700

    def test_format_is_small_ascii_json(self, config):
        write(config, Switch(True, T0, T0 + M30))
        data = json.loads(state_file(config).read_text(encoding="ascii"))
        assert data == {
            "format": 1,
            "state": "off",
            "since": "2026-10-25T12:00:00+00:00",
            "until": "2026-10-25T12:30:00+00:00",
        }

    @pytest.mark.parametrize(
        "content",
        [
            b"",
            b"not json",
            b"[]",
            b'{"format": 2, "state": "off", "since": "2026-10-25T12:00:00+00:00"}',
            b'{"format": 1, "state": "maybe"}',
            b'{"format": 1, "state": "off"}',  # no since
            b'{"format": 1, "state": "off", "since": "yesterday"}',
            b'{"format": 1, "state": "off", "since": "2026-10-25T12:00:00"}',  # no zone
            b'{"format": 1, "state": "off", "since": 5}',
            b'{"format": 1, "state": "off", "since": "2026-10-25T12:00:00+00:00", '
            b'"until": "2026-10-25T11:00:00+00:00"}',  # until before since
            '{"format": 1, "state": "off", "since": "2026-10-25T12:00:00+00:00", "x": "ü"}'.encode(),
            b"{" + b" " * 5000 + b"}",  # over the size limit
        ],
    )
    def test_anything_odd_means_on(self, config, content):
        config.mkdir(parents=True, exist_ok=True, mode=0o700)
        state_file(config).write_bytes(content)
        state_file(config).chmod(0o600)
        reading = read(config)
        assert reading.switch == ON
        assert reading.problem
        assert str(config) not in reading.problem  # no paths (they name the user)

    def test_symlink_means_on(self, config, tmp_path):
        target = tmp_path / "elsewhere"
        target.write_text('{"format": 1, "state": "off", "since": "2026-10-25T12:00:00+00:00"}')
        config.mkdir(parents=True, exist_ok=True, mode=0o700)
        state_file(config).symlink_to(target)
        assert read(config).switch == ON

    @pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
    def test_writable_by_others_means_on(self, config, mode):
        write(config, Switch(True, T0))
        state_file(config).chmod(mode)
        reading = read(config)
        assert reading.switch == ON
        assert reading.problem

    def test_readable_by_others_is_still_trusted(self, config):
        write(config, Switch(True, T0))
        state_file(config).chmod(0o644)
        assert read(config).switch.off

    def test_directory_instead_of_file_means_on(self, config):
        state_file(config).mkdir(parents=True)
        assert read(config).switch == ON

    def test_write_failure_raises(self, config, monkeypatch):
        from veil import fsutil
        from veil.errors import StorageError

        def full(*args, **kwargs):
            raise StorageError("disk full")

        monkeypatch.setattr(fsutil, "atomic_write", full)
        with pytest.raises(StorageError):
            write(config, Switch(True, T0))


class TestSemantics:
    def test_off_without_timer_stays_off(self):
        assert Switch(True, T0).is_off(T0 + timedelta(days=400))

    def test_timer(self):
        switch = Switch(True, T0, T0 + M30)
        assert switch.is_off(T0 + M30 - timedelta(seconds=1))
        assert not switch.is_off(T0 + M30)
        assert switch.expired(T0 + M30)
        assert not switch.expired(T0)

    def test_on_is_never_off(self):
        assert not ON.is_off(T0)
        assert not ON.expired(T0)


# ── durations ─────────────────────────────────────────────────────────────────


class TestDurations:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("30m", M30),
            ("2h", timedelta(hours=2)),
            ("1h30m", timedelta(minutes=90)),
            ("90s", timedelta(seconds=90)),
            ("1m", timedelta(minutes=1)),
            ("24h", timedelta(hours=24)),
            (" 45M ", timedelta(minutes=45)),
            ("0h60m", timedelta(hours=1)),
        ],
    )
    def test_valid(self, text, expected):
        assert parse_duration(text) == expected

    @pytest.mark.parametrize(
        "text",
        ["", "30", "m", "0m", "59s", "25h", "24h1s", "-5m", "1.5h", "30 m", "1d", "١٠m", "30m30h"],
    )
    def test_invalid(self, text):
        with pytest.raises(ValueError):  # noqa: PT011
            parse_duration(text)

    @pytest.mark.parametrize(
        ("duration", "text"),
        [
            (M30, "30 min"),
            (timedelta(hours=2), "2 h"),
            (timedelta(minutes=90), "1 h 30 min"),
            (timedelta(seconds=10), "1 min"),
        ],
    )
    def test_describe(self, duration, text):
        assert describe_duration(duration) == text


# ── transitions and timers ────────────────────────────────────────────────────


class TestTransitions:
    def test_off_then_on(self, config, switch_timers):
        switch, scheduled = switch_off(config, switch_timers, T0, M30)
        assert switch == Switch(True, T0, T0 + M30)
        assert scheduled
        assert switch_timers.scheduled == [(switch, T0)]
        assert read(config).switch.is_off(T0)
        switch_on(config, switch_timers)
        assert read(config).switch == ON
        assert switch_timers.cancelled == 1

    def test_scheduling_failure_is_reported_but_off_holds(self, config, switch_timers):
        switch_timers.ok = False
        switch, scheduled = switch_off(config, switch_timers, T0, M30)
        assert not scheduled
        assert read(config).switch == switch


class Runs:
    def __init__(self, code=0) -> None:
        self.argvs: list[list[str]] = []
        self.code = code

    def __call__(self, argv):
        self.argvs.append(list(argv))
        return self.code


class TestSystemdTimers:
    def timers(self, runs, env=None):
        return SystemdTimers(
            "/usr/bin/systemd-run", "/usr/bin/systemctl", python="/py", env=env or {}, run=runs
        )

    def test_reminder_only_without_timer(self):
        runs = Runs()
        assert self.timers(runs).schedule(Switch(True, T0), T0)
        assert runs.argvs[0] == [
            "/usr/bin/systemctl",
            "--user",
            "stop",
            "veil-expire.timer",
            "veil-remind.timer",
        ]
        assert runs.argvs[1] == [
            "/usr/bin/systemd-run", "--user", "--collect", "--quiet", "--unit=veil-remind",
            "--on-active=3600s", "--timer-property=AccuracySec=1s", "--on-unit-active=3600s",
            "--", "/py", "-m", "veil", "kill-switch-timer", "remind",
        ]  # fmt: skip
        assert len(runs.argvs) == 2

    def test_expiry_timer(self):
        runs = Runs()
        self.timers(runs).schedule(Switch(True, T0, T0 + M30), T0 + timedelta(minutes=5))
        expire = runs.argvs[2]
        assert "--unit=veil-expire" in expire
        assert "--on-active=1500s" in expire
        assert expire[-1] == "expire"
        assert not any(a.startswith("--on-unit-active") for a in expire)

    def test_passes_config_and_bus(self):
        runs = Runs()
        env = {"XDG_CONFIG_HOME": "/x/config", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/b", "Z": "1"}
        self.timers(runs, env).schedule(Switch(True, T0), T0)
        assert "--setenv=XDG_CONFIG_HOME=/x/config" in runs.argvs[1]
        assert "--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/b" in runs.argvs[1]
        assert not any("Z=1" in a for a in runs.argvs[1])

    def test_failure(self):
        assert not self.timers(Runs(code=1)).schedule(Switch(True, T0, T0 + M30), T0)

    def test_argv_is_value_free(self):
        runs = Runs()
        self.timers(runs).schedule(Switch(True, T0, T0 + M30), T0)
        for argv in runs.argvs:
            assert all("Jane" not in a and "Alex" not in a for a in argv)

    def test_run_never_raises(self, tmp_path):
        assert killswitch._run([str(tmp_path / "missing")]) == -1

    def test_detect(self):
        assert isinstance(killswitch.__dict__["SystemdTimers"]("a", "b", env={}), SystemdTimers)
        from veil.killswitch import NoTimers

        assert NoTimers().schedule(Switch(True, T0), T0) is False
        assert NoTimers().cancel() is None


class TestOnTimer:
    def test_expire_switches_back_on(self, config, switch_timers):
        write(config, Switch(True, T0, T0 + M30))
        message = killswitch.on_timer("expire", config, switch_timers, T0 + M30)
        assert message.summary == "veil is ON"
        assert "ran out" in message.body
        assert read(config).switch == ON
        assert switch_timers.cancelled == 1

    def test_early_or_stale_expire_does_nothing(self, config, switch_timers):
        write(config, Switch(True, T0, T0 + M30))
        assert killswitch.on_timer("expire", config, switch_timers, T0 + M30 / 2) is None
        assert read(config).switch.off

    def test_remind_while_off(self, config, switch_timers):
        write(config, Switch(True, T0))
        message = killswitch.on_timer("remind", config, switch_timers, T0 + timedelta(hours=2))
        assert message.summary == "veil is still OFF"
        assert "Off for 2 h" in message.body
        assert message.urgency is Urgency.CRITICAL

    def test_remind_when_on_stops_the_timer(self, config, switch_timers):
        assert killswitch.on_timer("remind", config, switch_timers, T0) is None
        assert switch_timers.cancelled == 1

    def test_remind_after_expiry_switches_on(self, config, switch_timers):
        write(config, Switch(True, T0, T0 + M30))
        message = killswitch.on_timer("remind", config, switch_timers, T0 + timedelta(hours=1))
        assert message.summary == "veil is ON"
        assert read(config).switch == ON

    def test_corrupt_state_is_left_on(self, config, switch_timers):
        config.mkdir(parents=True, mode=0o700)
        state_file(config).write_bytes(b"garbage")
        assert killswitch.on_timer("remind", config, switch_timers, T0) is None


EVENTS = st.lists(
    st.one_of(
        st.tuples(st.just("off"), st.one_of(st.none(), st.integers(1, 24 * 60))),
        st.tuples(st.just("on"), st.none()),
        st.tuples(st.just("wait"), st.integers(0, 3 * 60)),
        st.tuples(st.sampled_from(["expire", "remind"]), st.none()),
    ),
    max_size=20,
)


@given(EVENTS)
def test_property_state_machine(tmp_path_factory, events):
    """Against a model: OFF only after an explicit off; timers never switch off."""
    config = tmp_path_factory.mktemp("cfg") / "veil"
    timers = killswitch.NoTimers()
    now, model_until, model_off = T0, None, False
    for event, value in events:
        if event == "off":
            duration = None if value is None else timedelta(minutes=value)
            switch_off(config, timers, now, duration)
            model_off, model_until = True, None if duration is None else now + duration
        elif event == "on":
            switch_on(config, timers)
            model_off = False
        elif event == "wait":
            now += timedelta(minutes=value)
        else:
            before = read(config).switch.is_off(now)
            killswitch.on_timer(event, config, timers, now)
            assert read(config).switch.is_off(now) <= before  # never switches off
        expected = model_off and (model_until is None or now < model_until)
        assert read(config).switch.is_off(now) is expected


# ── what the user sees ────────────────────────────────────────────────────────


class TestStatusLine:
    def test_on(self):
        assert status_line(Reading(ON), T0) == "veil: ON"

    def test_off_with_timer(self):
        line = status_line(Reading(Switch(True, T0, T0 + M30)), T0 + timedelta(minutes=10))
        assert line.startswith("veil: OFF until ")
        assert line.endswith("(20 min left)")

    def test_off_without_timer(self):
        line = status_line(Reading(Switch(True, T0)), T0)
        assert line.startswith("veil: OFF since 2026-10-2")
        assert line.endswith("(no timer: `veil on` to switch back)")

    def test_expired(self):
        line = status_line(Reading(Switch(True, T0, T0 + M30)), T0 + timedelta(hours=1))
        assert line.startswith("veil: ON (the OFF timer ran out at ")

    def test_messages(self):
        off = killswitch.off_message(Switch(True, T0, T0 + M30), T0)
        assert off.summary == "veil is OFF"
        assert off.urgency is Urgency.CRITICAL
        assert "(30 min)" in off.body
        assert "Reminder every 1 h" in killswitch.off_message(Switch(True, T0), T0).body


# ── CLI ───────────────────────────────────────────────────────────────────────


@pytest.fixture
def terminal(monkeypatch):
    """A terminal where the user types `typed`."""

    def type_(typed: str) -> None:
        monkeypatch.setattr(ui, "_isatty", lambda _stream: True)
        monkeypatch.setattr(sys, "stdin", io.StringIO(typed))

    return type_


def cmd(capsys, *args):
    code = cli.main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


class TestStatusCommand:
    def test_on(self, capsys):
        assert cmd(capsys, "status") == (ExitCode.OK, "veil: ON\n", "")

    def test_off(self, capsys, config):
        write(config, Switch(True, killswitch.utc_now()))
        code, out, _ = cmd(capsys, "status")
        assert code == ExitCode.OFF
        assert out.startswith("veil: OFF since ")

    def test_corrupt_is_on_with_warning(self, capsys, config):
        config.mkdir(parents=True, mode=0o700)
        state_file(config).write_bytes(b"{")
        code, out, err = cmd(capsys, "status")
        assert code == ExitCode.OK
        assert out == "veil: ON\n"
        assert "can't be read or trusted; veil stays ON" in err

    def test_status_never_writes(self, capsys, config):
        cmd(capsys, "status")
        assert not state_file(config).exists()


class TestOffCommand:
    def test_refused_without_a_terminal(self, capsys, config, switch_timers, notifications):
        code, _, err = cmd(capsys, "off")
        assert code == ExitCode.UNSAFE_ENVIRONMENT
        assert "needs an interactive terminal" in err
        assert not state_file(config).exists()
        assert switch_timers.scheduled == []
        assert notifications == []

    @pytest.mark.parametrize("typed", ["", "\n", "of\n", "OFF\n", "yes\n", "off off\n"])
    def test_wrong_confirmation(self, capsys, config, terminal, typed):
        terminal(typed)
        code, _, err = cmd(capsys, "off")
        assert code == ExitCode.ABORTED
        assert "veil stays ON" in err
        assert read(config).switch == ON

    def test_off(self, capsys, config, terminal, switch_timers, notifications):
        terminal("off\n")
        code, out, _ = cmd(capsys, "off")
        assert code == ExitCode.OK
        assert out.startswith("veil: OFF since ")
        assert read(config).switch.off
        assert len(switch_timers.scheduled) == 1
        assert notifications[-1].summary == "veil is OFF"

    def test_off_for(self, capsys, config, terminal):
        terminal("off\n")
        code, out, _ = cmd(capsys, "off", "--for", "30m")
        assert code == ExitCode.OK
        assert out.endswith("(30 min left)\n")
        switch = read(config).switch
        assert switch.until - switch.since == M30

    @pytest.mark.parametrize("value", ["0m", "25h", "soon", ""])
    def test_bad_duration_is_usage(self, capsys, config, value):
        with pytest.raises(SystemExit) as caught:
            cli.main(["off", "--for", value])
        assert caught.value.code == ExitCode.USAGE
        assert not state_file(config).exists()

    def test_timer_failure_warns(self, capsys, terminal, switch_timers):
        switch_timers.ok = False
        terminal("off\n")
        code, _, err = cmd(capsys, "off", "--for", "1h")
        assert code == ExitCode.OK
        assert "couldn't schedule the reminder/expiry notifications" in err

    def test_off_again_resets_the_timer(self, capsys, config, terminal):
        terminal("off\n")
        cmd(capsys, "off", "--for", "1h")
        terminal("off\n")
        cmd(capsys, "off")
        assert read(config).switch.until is None


class TestOnCommand:
    def test_on_from_off(self, capsys, config, switch_timers, notifications):
        write(config, Switch(True, killswitch.utc_now()))
        assert cmd(capsys, "on")[:2] == (ExitCode.OK, "veil: ON\n")
        assert read(config).switch == ON
        assert switch_timers.cancelled == 1
        assert notifications[-1].summary == "veil is ON"

    def test_on_needs_no_terminal(self, capsys):
        # Switching ON is always allowed: it only ever adds protection.
        assert cmd(capsys, "on")[0] == ExitCode.OK

    def test_already_on(self, capsys, notifications):
        assert cmd(capsys, "on")[1] == "veil: ON (it already was)\n"
        assert notifications == []

    def test_on_repairs_a_corrupt_file(self, capsys, config):
        config.mkdir(parents=True, mode=0o700)
        state_file(config).write_bytes(b"{")
        cmd(capsys, "on")
        assert read(config) == Reading(ON)


class TestToggleCommand:
    def test_on_to_off_is_guarded(self, capsys, config):
        assert cmd(capsys, "toggle")[0] == ExitCode.UNSAFE_ENVIRONMENT
        assert read(config).switch == ON

    def test_on_to_off(self, capsys, config, terminal):
        terminal("off\n")
        assert cmd(capsys, "toggle", "--for", "2h")[0] == ExitCode.OK
        assert read(config).switch.is_off(killswitch.utc_now())

    def test_off_to_on_without_terminal(self, capsys, config):
        write(config, Switch(True, killswitch.utc_now()))
        assert cmd(capsys, "toggle")[:2] == (ExitCode.OK, "veil: ON\n")
        assert read(config).switch == ON

    def test_expired_off_toggles_to_off(self, capsys, config):
        # An expired timer is ON, so toggle means OFF (guarded).
        now = killswitch.utc_now()
        write(config, Switch(True, now - timedelta(hours=2), now - timedelta(hours=1)))
        assert cmd(capsys, "toggle")[0] == ExitCode.UNSAFE_ENVIRONMENT


class TestTimerCommand:
    def test_expire(self, capsys, config, notifications):
        now = killswitch.utc_now()
        write(config, Switch(True, now - timedelta(hours=1), now - timedelta(seconds=1)))
        assert cmd(capsys, "kill-switch-timer", "expire")[0] == ExitCode.OK
        assert read(config).switch == ON
        assert notifications[-1].summary == "veil is ON"

    def test_remind(self, capsys, config, notifications):
        write(config, Switch(True, killswitch.utc_now()))
        cmd(capsys, "kill-switch-timer", "remind")
        assert notifications[-1].summary == "veil is still OFF"

    def test_cannot_switch_off(self, capsys, config):
        for event in ("expire", "remind"):
            cmd(capsys, "kill-switch-timer", event)
        assert not read(config).switch.off

    def test_not_listed_in_help(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["--help"])
        out = capsys.readouterr().out
        assert "kill-switch-timer" not in out
        for listed in ("on", "off", "toggle", "status"):
            assert listed in out


# ── clip commands while OFF ───────────────────────────────────────────────────


class TestClipWhileOff:
    @pytest.fixture(autouse=True)
    def switched_off(self, config):
        write(config, Switch(True, killswitch.utc_now()))

    @pytest.mark.parametrize("command", ["sanitize", "from-selection"])
    def test_forward_is_a_noop(self, board, capsys, notifications, clip_history, command):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        board.offers[Selection.PRIMARY] = {"text/plain": REAL.encode()}
        code, _, err = run(capsys, command)
        assert code == ExitCode.OK
        assert board.reads == []  # the clipboard isn't even read
        assert board.writes == []
        assert board.clears == []
        assert clip_history.calls == 0
        assert "NOT sanitized: veil is OFF (kill switch)" in err
        shown = notifications[-1]
        assert shown.summary == "veil is OFF: clipboard NOT sanitized"
        assert shown.urgency is Urgency.CRITICAL

    def test_restore_is_a_noop(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {"text/plain": b"Alex Smith"}
        code, _, _ = run(capsys, "restore")
        assert code == ExitCode.OK
        assert board.reads == []
        assert notifications[-1].summary == "veil is OFF: nothing restored"
        assert notifications[-1].urgency is Urgency.NORMAL

    def test_no_store_needed(self, board, capsys):
        # OFF never touches the key or the persona (no store exists in this test).
        assert run(capsys, "sanitize")[0] == ExitCode.OK

    def test_no_notify(self, board, capsys, notifications):
        run(capsys, "sanitize", "--no-notify")
        assert notifications == []

    def test_back_on_works_again(self, board, capsys, config):
        switch_on(config, killswitch.NoTimers())
        board.offers[Selection.CLIPBOARD] = {"image/png": b"x"}
        _, _, err = run(capsys, "sanitize")
        assert "veil is OFF" not in err


def test_expired_timer_sanitizes_again(board, capsys, config):
    now = killswitch.utc_now()
    write(config, Switch(True, now - timedelta(hours=1), now - timedelta(seconds=1)))
    board.offers[Selection.CLIPBOARD] = {"image/png": b"x"}
    _, _, err = run(capsys, "sanitize")
    assert "veil is OFF" not in err
    assert board.reads == [Selection.CLIPBOARD]


def test_corrupt_state_sanitizes(board, capsys, config):
    config.mkdir(parents=True, mode=0o700)
    state_file(config).write_bytes(b"\x00")
    board.offers[Selection.CLIPBOARD] = {"image/png": b"x"}
    _, _, err = run(capsys, "sanitize")
    assert "veil stays ON" in err
    assert board.reads == [Selection.CLIPBOARD]


@pytest.mark.parametrize("action", list(Action))
def test_off_messages(action):
    message = messages.notification(Outcome(action, Skip.OFF))
    assert "veil is OFF" in message.summary
    assert message.body.endswith("Run `veil on` to switch back.")
    assert "Meta+Alt" not in message.body  # no hotkey until M3.3 installs one


def test_state_file_is_in_the_agent_denied_directory(config):
    # The deny rules cover ~/.config/veil/**; the state must live there (ADR-0018).
    assert state_file(config).parent == paths.config_dir()
    assert state_file(config).name == "state"
