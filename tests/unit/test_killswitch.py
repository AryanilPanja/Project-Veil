"""veil ON / OFF (ADR-0031): ON = the copy watcher service sanitizes every copy; OFF = normal.

Every test runs in the per-test XDG sandbox (conftest); `copy_watcher` stands in for the
veil-watch systemd service and `switch_timers` for the end-time timer, so nothing real is ever
started, stopped or scheduled.
"""

import io
import json
import sys
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil import cli, killswitch, paths, ui
from veil.clip.notify import Urgency
from veil.errors import VeilError
from veil.exitcodes import ExitCode
from veil.killswitch import (
    OFF,
    Reading,
    Switch,
    SystemdTimers,
    SystemdWatcher,
    describe_duration,
    parse_duration,
    read_switch,
    status_line,
    switch_off,
    switch_on,
    write,
)

T0 = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
M30 = timedelta(minutes=30)


@pytest.fixture
def config():
    return paths.config_dir()


def state_file(config):
    return killswitch.state_path(config)


def cmd(capsys, *args):
    code = cli.main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


# ── state file ────────────────────────────────────────────────────────────────


class TestState:
    def test_missing_is_off(self, config):
        assert read_switch(config) == (OFF, None)

    @pytest.mark.parametrize("switch", [OFF, Switch(True, T0, None), Switch(True, T0, T0 + M30)])
    def test_round_trip(self, config, switch):
        write(config, switch)
        assert read_switch(config) == (switch, None)
        assert state_file(config).stat().st_mode & 0o777 == 0o600

    def test_format(self, config):
        write(config, Switch(True, T0, T0 + M30))
        assert json.loads(state_file(config).read_text()) == {
            "format": 2,
            "on": True,
            "since": "2026-10-26T12:00:00+00:00",
            "until": "2026-10-26T12:30:00+00:00",
        }

    def test_older_format_is_ignored(self, config):
        # Before ADR-0031 "off" meant "hotkeys disabled": it says nothing about the watcher.
        config.mkdir(parents=True, mode=0o700)
        state_file(config).write_text(
            '{"format": 1, "state": "off", "since": "2026-10-25T12:00:00+00:00"}'
        )
        state_file(config).chmod(0o600)
        assert read_switch(config) == (OFF, None)

    @pytest.mark.parametrize(
        "content",
        [
            b"not json",
            b"[]",
            b'{"format": 2, "on": true}',
            b'{"format": 2, "on": true, "since": "x"}',
            b'{"format": 2, "on": true, "since": "2026-10-26T12:00:00"}',
            b'{"format": 2, "on": true, "since": "2026-10-26T12:00:00+00:00", "until": "2026-10-26T11:00:00+00:00"}',
            b"{" + b" " * 5000 + b"}",
        ],
    )
    def test_odd_file_is_a_problem(self, config, content):
        config.mkdir(parents=True, exist_ok=True, mode=0o700)
        state_file(config).write_bytes(content)
        state_file(config).chmod(0o600)
        switch, problem = read_switch(config)
        assert switch == OFF
        assert problem
        assert str(config) not in problem

    def test_writable_by_others(self, config):
        write(config, Switch(True, T0))
        state_file(config).chmod(0o666)
        assert read_switch(config)[1]


class TestReading:
    def test_on_needs_the_watcher(self):
        assert Reading(Switch(True, T0), watching=True).is_on(T0)
        assert not Reading(Switch(True, T0), watching=False).is_on(T0)

    def test_watcher_alone_is_on(self):
        # The service is the truth: a missing or doubtful state file can't switch it off.
        assert Reading(OFF, watching=True, problem="x").is_on(T0)

    def test_time_up(self):
        reading = Reading(Switch(True, T0, T0 + M30), watching=True)
        assert reading.is_on(T0 + M30 - timedelta(seconds=1))
        assert not reading.is_on(T0 + M30)


# ── durations ─────────────────────────────────────────────────────────────────


class TestDurations:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("30m", M30),
            ("2h", timedelta(hours=2)),
            ("1h30m", timedelta(minutes=90)),
            (" 45M ", timedelta(minutes=45)),
        ],
    )
    def test_valid(self, text, expected):
        assert parse_duration(text) == expected

    @pytest.mark.parametrize(
        "text", ["", "30", "0m", "59s", "25h", "-5m", "1.5h", "1d", chr(0x661) + chr(0x660) + "m"]
    )
    def test_invalid(self, text):
        with pytest.raises(ValueError):  # noqa: PT011
            parse_duration(text)

    @pytest.mark.parametrize(
        ("duration", "text"),
        [(M30, "30 min"), (timedelta(hours=2), "2 h"), (timedelta(minutes=90), "1 h 30 min")],
    )
    def test_describe(self, duration, text):
        assert describe_duration(duration) == text


# ── the watcher service ───────────────────────────────────────────────────────


class Runs:
    """Records systemctl calls; `codes` maps a systemctl verb to its exit code."""

    def __init__(self, codes=None) -> None:
        self.argvs: list[list[str]] = []
        self.codes = codes or {}

    def __call__(self, argv):
        self.argvs.append(list(argv))
        return self.codes.get(argv[2] if len(argv) > 2 else "", 0)


class TestSystemdWatcher:
    def watcher(self, tmp_path, runs, env=None):
        return SystemdWatcher(
            "/bin/systemctl", tmp_path / "units", python="/py", env=env or {}, run=runs
        )

    def test_unit(self, tmp_path):
        env = {
            "WAYLAND_DISPLAY": "wayland-0",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/b",
            "HOME": "/h",
        }
        text = self.watcher(tmp_path, Runs(), env).unit_text()
        assert "ExecStart=/py -m veil clip watch\n" in text
        assert "Environment=WAYLAND_DISPLAY=wayland-0\n" in text
        assert "Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/b\n" in text
        assert "HOME" not in text
        assert "Restart=on-failure\n" in text
        assert "WantedBy=graphical-session.target\n" in text

    def test_start(self, tmp_path):
        runs = Runs()
        assert self.watcher(tmp_path, runs).start()
        unit = tmp_path / "units" / "veil-watch.service"
        assert unit.stat().st_mode & 0o777 == 0o644
        assert runs.argvs == [
            ["/bin/systemctl", "--user", "daemon-reload"],
            ["/bin/systemctl", "--user", "enable", "--now", "veil-watch.service"],
            ["/bin/systemctl", "--user", "is-active", "--quiet", "veil-watch.service"],
        ]

    @pytest.mark.parametrize("failing", ["enable", "is-active"])
    def test_start_failure(self, tmp_path, failing):
        assert not self.watcher(tmp_path, Runs({failing: 3})).start()

    def test_stop_and_active(self, tmp_path):
        runs = Runs({"is-active": 3})
        watcher = self.watcher(tmp_path, runs)
        watcher.stop()
        assert runs.argvs[-1] == [
            "/bin/systemctl",
            "--user",
            "disable",
            "--now",
            "veil-watch.service",
        ]
        assert watcher.active() is False

    def test_no_watcher(self):
        none = killswitch.NoWatcher()
        assert none.start() is False
        assert none.active() is False
        assert none.stop() is None


class TestTimers:
    def timers(self, runs):
        return SystemdTimers("/sr", "/sc", python="/py", env={}, run=runs)

    def test_end_time(self):
        runs = Runs()
        assert self.timers(runs).schedule(Switch(True, T0, T0 + M30), T0)
        assert runs.argvs[0] == ["/sc", "--user", "stop", "veil-expire.timer", "veil-remind.timer"]
        assert "--on-active=1800s" in runs.argvs[1]
        assert runs.argvs[1][-2:] == ["kill-switch-timer", "expire"]

    def test_no_end_time(self):
        runs = Runs()
        assert self.timers(runs).schedule(Switch(True, T0), T0)
        assert len(runs.argvs) == 1  # only the cancel

    def test_failure(self):
        assert not self.timers(lambda argv: 1).schedule(Switch(True, T0, T0 + M30), T0)

    def test_no_timers(self):
        assert killswitch.NoTimers().schedule(Switch(True, T0), T0) is True
        assert killswitch.NoTimers().schedule(Switch(True, T0, T0 + M30), T0) is False

    def test_run_never_raises(self, tmp_path):
        assert killswitch._run([str(tmp_path / "missing")]) == -1


# ── transitions ───────────────────────────────────────────────────────────────


class TestTransitions:
    def test_on(self, config, copy_watcher, switch_timers):
        switch, scheduled = switch_on(config, copy_watcher, switch_timers, T0, M30)
        assert switch == Switch(True, T0, T0 + M30)
        assert scheduled
        assert copy_watcher.running
        assert read_switch(config) == (switch, None)

    def test_on_fails_closed(self, config, copy_watcher, switch_timers):
        copy_watcher.can_start = False
        with pytest.raises(VeilError, match="veil stays OFF"):
            switch_on(config, copy_watcher, switch_timers, T0)
        assert read_switch(config) == (OFF, None)
        assert copy_watcher.stops == 1
        assert switch_timers.scheduled == []

    def test_off(self, config, copy_watcher, switch_timers):
        switch_on(config, copy_watcher, switch_timers, T0)
        switch_off(config, copy_watcher, switch_timers)
        assert not copy_watcher.running
        assert read_switch(config) == (OFF, None)
        assert switch_timers.cancelled == 1


class TestOnTimer:
    def test_expire(self, config, copy_watcher, switch_timers):
        switch_on(config, copy_watcher, switch_timers, T0, M30)
        message = killswitch.on_timer("expire", config, copy_watcher, switch_timers, T0 + M30)
        assert message.summary == "veil OFF"
        assert message.urgency is Urgency.CRITICAL
        assert not copy_watcher.running

    def test_early_expire_does_nothing(self, config, copy_watcher, switch_timers):
        switch_on(config, copy_watcher, switch_timers, T0, M30)
        assert killswitch.on_timer("expire", config, copy_watcher, switch_timers, T0) is None
        assert copy_watcher.running

    def test_old_reminder_stops_itself(self, config, copy_watcher, switch_timers):
        assert killswitch.on_timer("remind", config, copy_watcher, switch_timers, T0) is None
        assert switch_timers.cancelled == 1


EVENTS = st.lists(
    st.one_of(
        st.tuples(st.just("on"), st.one_of(st.none(), st.integers(1, 600))),
        st.tuples(st.just("off"), st.none()),
        st.tuples(st.just("wait"), st.integers(0, 300)),
        st.tuples(st.just("expire"), st.none()),
    ),
    max_size=20,
)


@given(EVENTS)
def test_property_state_machine(tmp_path_factory, events):
    """Against a model: ON only after `on`, and only while the watcher runs and the chosen time
    isn't up; a timer never switches ON."""
    from tests.conftest import FakeWatcher

    config = tmp_path_factory.mktemp("cfg") / "veil"
    watcher, timers = FakeWatcher(), killswitch.NoTimers()
    now, model_on, model_until = T0, False, None
    for event, value in events:
        if event == "on":
            duration = None if value is None else timedelta(minutes=value)
            switch_on(config, watcher, timers, now, duration)
            model_on, model_until = True, None if duration is None else now + duration
        elif event == "off":
            switch_off(config, watcher, timers)
            model_on = False
        elif event == "wait":
            now += timedelta(minutes=value)
        else:
            before = killswitch.read(config, watcher).is_on(now)
            killswitch.on_timer("expire", config, watcher, timers, now)
            assert killswitch.read(config, watcher).is_on(now) <= before  # never switches ON
            if model_on and model_until is not None and now >= model_until:
                model_on = False
        expected = model_on and (model_until is None or now < model_until)
        assert killswitch.read(config, watcher).is_on(now) is expected


# ── what the user sees ────────────────────────────────────────────────────────


class TestMessages:
    def test_status_lines(self):
        assert status_line(Reading(OFF, False), T0) == "veil: OFF, copy and paste are normal"
        assert (
            status_line(Reading(Switch(True, T0), True), T0) == "veil: ON, every copy is sanitized"
        )
        timed = status_line(Reading(Switch(True, T0, T0 + M30), True), T0 + timedelta(minutes=10))
        assert timed.endswith("20 min left)")
        assert "time is up" in status_line(Reading(Switch(True, T0, T0 + M30), True), T0 + M30)

    def test_on(self):
        message = killswitch.on_message(Switch(True, T0, T0 + M30), T0)
        assert message.summary == "veil ON"
        assert "Every copy is sanitized" in message.body
        assert "(30 min)" in message.body
        assert "Until you switch it off." in killswitch.on_message(Switch(True, T0), T0).body

    def test_off(self):
        assert killswitch.off_message().urgency is Urgency.NORMAL
        assert killswitch.off_message(expired=True).body.startswith("Its time is up.")

    def test_toggle_hint_without_shortcut(self):
        assert killswitch.toggle_hint() == "`veil on` / `veil off` switch it."


# ── CLI ───────────────────────────────────────────────────────────────────────


@pytest.fixture
def terminal(monkeypatch):
    def type_(typed: str) -> None:
        monkeypatch.setattr(ui, "_isatty", lambda _stream: True)
        monkeypatch.setattr(sys, "stdin", io.StringIO(typed))

    return type_


class TestCli:
    def test_status_off_by_default(self, capsys):
        assert cmd(capsys, "status") == (
            ExitCode.OFF,
            "veil: OFF, copy and paste are normal\n",
            "",
        )

    def test_on(self, capsys, copy_watcher, notifications):
        code, out, _ = cmd(capsys, "on")
        assert code == ExitCode.OK
        assert out == "veil: ON, every copy is sanitized\n"
        assert copy_watcher.running
        assert notifications[-1].summary == "veil ON"
        assert cmd(capsys, "status")[0] == ExitCode.OK

    def test_on_needs_no_terminal_or_confirmation(self, capsys, copy_watcher, switch_chooser):
        assert cmd(capsys, "on")[0] == ExitCode.OK
        assert switch_chooser.asked == []

    def test_on_for(self, capsys, config, switch_timers):
        cmd(capsys, "on", "--for", "30m")
        switch, _ = read_switch(config)
        assert switch.until - switch.since == M30
        assert len(switch_timers.scheduled) == 1

    def test_on_fails_closed(self, capsys, copy_watcher):
        copy_watcher.can_start = False
        code, _, err = cmd(capsys, "on")
        assert code == ExitCode.UNSAFE_ENVIRONMENT
        assert "veil stays OFF" in err
        assert cmd(capsys, "status")[0] == ExitCode.OFF

    def test_off_refused_without_terminal(self, capsys, copy_watcher):
        cmd(capsys, "on")
        code, _, _ = cmd(capsys, "off")
        assert code == ExitCode.UNSAFE_ENVIRONMENT
        assert copy_watcher.running

    @pytest.mark.parametrize("typed", ["", "\n", "OFF\n", "of\n", "yes\n"])
    def test_off_wrong_confirmation(self, capsys, copy_watcher, terminal, typed):
        cmd(capsys, "on")
        terminal(typed)
        assert cmd(capsys, "off")[0] == ExitCode.ABORTED
        assert copy_watcher.running

    def test_off(self, capsys, copy_watcher, terminal, notifications):
        cmd(capsys, "on")
        terminal("off\n")
        code, out, _ = cmd(capsys, "off")
        assert code == ExitCode.OK
        assert out == "veil: OFF, copy and paste are normal\n"
        assert not copy_watcher.running
        assert notifications[-1].summary == "veil OFF"

    def test_off_when_already_off(self, capsys):
        assert cmd(capsys, "off")[:2] == (ExitCode.OK, "veil: OFF (it already was)\n")

    def test_toggle_on_without_terminal(self, capsys, copy_watcher):
        assert cmd(capsys, "toggle")[0] == ExitCode.OK
        assert copy_watcher.running

    def test_toggle_off_is_guarded(self, capsys, copy_watcher):
        cmd(capsys, "toggle")
        assert cmd(capsys, "toggle")[0] == ExitCode.UNSAFE_ENVIRONMENT
        assert copy_watcher.running

    def test_timer_expire(self, capsys, copy_watcher, config, notifications):
        cmd(capsys, "on")
        now = killswitch.utc_now()
        write(config, Switch(True, now - timedelta(hours=1), now - timedelta(seconds=1)))
        assert cmd(capsys, "kill-switch-timer", "expire")[0] == ExitCode.OK
        assert not copy_watcher.running
        assert notifications[-1].urgency is Urgency.CRITICAL

    def test_corrupt_state_warns(self, capsys, config):
        config.mkdir(parents=True, mode=0o700)
        state_file(config).write_bytes(b"{")
        state_file(config).chmod(0o600)
        _, _, err = cmd(capsys, "status")
        assert "can't be read or trusted" in err

    def test_timer_command_not_listed(self, capsys):
        with pytest.raises(SystemExit):
            cli.main(["--help"])
        out = capsys.readouterr().out
        assert "kill-switch-timer" not in out
        for listed in ("on", "off", "toggle", "status"):
            assert listed in out

    @pytest.mark.parametrize("value", ["0m", "25h", "soon"])
    def test_bad_duration(self, capsys, value):
        with pytest.raises(SystemExit) as caught:
            cli.main(["on", "--for", value])
        assert caught.value.code == ExitCode.USAGE

    def test_off_has_no_for(self, capsys):
        with pytest.raises(SystemExit) as caught:
            cli.main(["off", "--for", "30m"])
        assert caught.value.code == ExitCode.USAGE


def test_state_file_is_in_the_agent_denied_directory(config):
    assert state_file(config).parent == paths.config_dir()
    assert state_file(config).name == "state"
