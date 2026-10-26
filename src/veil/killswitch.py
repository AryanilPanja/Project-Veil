"""veil ON / OFF (ADR-0031, revising ADR-0018): `veil on [--for 2h] | off | status | toggle`.

**ON = every copy is sanitized.** A copy watcher (`veil clip watch`, a systemd user service)
sanitizes the clipboard right after each Ctrl+C, so Ctrl+V pastes the sanitized text.
**OFF = copy and paste are normal**; it is the resting state. The explicit hotkeys
(Meta+Alt+V/C/E, Alt+V…) work either way: pressing one is itself the decision.

- **The service is the truth.** veil is ON only while the watcher service runs: a state that
  claims protection nothing provides would be the worst failure. The state file
  (`<config>/state`, 0600) only adds when it started and when it ends.
- **Switching OFF is a human decision** (ADR-0018 stays): a terminal and a typed `off`, or the
  hotkey with one click in a notification ([Switch OFF] / [Keep ON]); agents can't click. Errors
  never switch veil OFF, and switching ON needs no confirmation.
- **`--for`** (1 minute to 24 hours) ends ON at a set time: a systemd timer runs
  `veil kill-switch-timer expire`, and the watcher checks the clock too (a copy after the end
  time is still sanitized, then veil switches OFF and says so).
"""

import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from veil import fsutil
from veil.clip.notify import Message, Urgency
from veil.errors import VeilError
from veil.exitcodes import ExitCode

STATE_FILE = "state"
MAX_STATE_BYTES = 4096
FORMAT = 2  # format 1 (before ADR-0031) meant something else: it is ignored
MIN_FOR = timedelta(minutes=1)
MAX_FOR = timedelta(hours=24)
EXPIRE_UNIT = "veil-expire"
LEGACY_UNITS = ("veil-remind",)  # the old OFF reminder (ADR-0018 amendment 1)
TIMER_COMMAND = "kill-switch-timer"
WATCH_UNIT = "veil-watch.service"

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


# ── state ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Switch:
    """What the state file says. `on` alone isn't the answer: see `Reading.is_on`."""

    on: bool = False
    since: datetime | None = None
    until: datetime | None = None  # ON ends by itself then (None: until switched off)

    def expired(self, now: datetime) -> bool:
        return self.on and self.until is not None and now >= self.until


OFF = Switch()


@dataclass(frozen=True)
class Reading:
    switch: Switch
    watching: bool  # the copy watcher service is running
    problem: str | None = None  # value-free; the state file couldn't be trusted

    def is_on(self, now: datetime) -> bool:
        """ON only while the watcher runs and the time (if any) isn't up."""
        return self.watching and not self.switch.expired(now)


def state_path(config: Path) -> Path:
    return config / STATE_FILE


def read_switch(config: Path) -> tuple[Switch, str | None]:
    """The state file. Never raises: anything wrong means "no time limit known" plus a problem."""
    path = state_path(config)
    try:
        if not path.exists() and not path.is_symlink():
            return OFF, None
        if not path.is_symlink() and path.lstat().st_mode & 0o022:
            raise ValueError("writable by others")
        raw = fsutil.read_private(path, MAX_STATE_BYTES, "the veil state file")
        return _decode(raw), None
    except (VeilError, OSError, ValueError, TypeError, KeyError):
        return (
            OFF,
            "the veil state file can't be read or trusted; `veil on` or `veil off` resets it",
        )


def read(config: Path, watcher: "Watcher") -> Reading:
    switch, problem = read_switch(config)
    return Reading(switch, watcher.active(), problem)


def write(config: Path, switch: Switch) -> None:
    fsutil.ensure_private_dir(config, "the veil config directory")
    fsutil.atomic_write(state_path(config), _encode(switch), what="the veil state file")


def _encode(switch: Switch) -> bytes:
    data = {
        "format": FORMAT,
        "on": switch.on,
        "since": _stamp(switch.since),
        "until": _stamp(switch.until),
    }
    return (json.dumps(data, sort_keys=True) + "\n").encode("ascii")


def _decode(raw: bytes) -> Switch:
    data = json.loads(raw.decode("ascii"))
    if not isinstance(data, dict):
        raise ValueError("not an object")
    if data.get("format") != FORMAT:
        return OFF  # an older veil's file (its "off" meant something else)
    if not data.get("on"):
        return OFF
    since, until = _parse(data.get("since")), _parse(data.get("until"))
    if since is None or (until is not None and until <= since):
        raise ValueError("bad times")
    return Switch(True, since, until)


def _stamp(moment: datetime | None) -> str | None:
    return None if moment is None else moment.astimezone(UTC).isoformat(timespec="seconds")


def _parse(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("not a timestamp")
    moment = datetime.fromisoformat(value)
    if moment.tzinfo is None:
        raise ValueError("timestamp without a time zone")
    return moment


# ── durations ─────────────────────────────────────────────────────────────────

# ASCII digits only: \d would also accept other scripts' digits (Arabic-Indic, Devanagari).
_DURATION = re.compile(r"(?:([0-9]{1,3})h)?(?:([0-9]{1,4})m)?(?:([0-9]{1,5})s)?", re.IGNORECASE)


def parse_duration(text: str) -> timedelta:
    """`30m`, `2h`, `1h30m`, `90s`: 1 minute to 24 hours. Raises ValueError otherwise."""
    match = _DURATION.fullmatch(text.strip())
    if not text.strip() or match is None or not any(match.groups()):
        raise ValueError("use a duration such as 30m, 2h or 1h30m")
    hours, minutes, seconds = (int(g or 0) for g in match.groups())
    duration = timedelta(hours=hours, minutes=minutes, seconds=seconds)
    if not MIN_FOR <= duration <= MAX_FOR:
        raise ValueError("the duration must be between 1 minute and 24 hours")
    return duration


def describe_duration(duration: timedelta) -> str:
    minutes = max(1, round(duration.total_seconds() / 60))
    hours, minutes = divmod(minutes, 60)
    if hours and minutes:
        return f"{hours} h {minutes} min"
    return f"{hours} h" if hours else f"{minutes} min"


# ── the copy watcher service ──────────────────────────────────────────────────


class Watcher(Protocol):
    def start(self) -> bool: ...

    def stop(self) -> None: ...

    def active(self) -> bool: ...


Run = Callable[[Sequence[str]], int]


class SystemdWatcher:
    """`veil-watch.service`, a systemd user service running `python -m veil clip watch`.
    Enabled while ON, so it comes back after a reboot and restarts if it crashes."""

    def __init__(
        self,
        systemctl: str,
        unit_dir: Path,
        *,
        python: str = sys.executable,
        env: dict[str, str] | None = None,
        run: Run | None = None,
    ) -> None:
        self._systemctl, self._unit_dir, self._python = systemctl, unit_dir, python
        self._env = dict(os.environ) if env is None else env
        self._run = run or _run

    def unit_text(self) -> str:
        environment = "".join(
            f"Environment={name}={self._env[name]}\n"
            # The user manager may not know the session's display or bus; the watcher needs both.
            for name in (
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "WAYLAND_DISPLAY",
                "DISPLAY",
                "DBUS_SESSION_BUS_ADDRESS",
            )
            if self._env.get(name)
        )
        return (
            "[Unit]\n"
            "Description=veil: sanitize every copy (veil ON)\n"
            "PartOf=graphical-session.target\n"
            "After=graphical-session.target\n\n"
            "[Service]\n"
            f"ExecStart={self._python} -m veil clip watch\n"
            f"{environment}"
            "Restart=on-failure\n"
            "RestartSec=2\n\n"
            "[Install]\n"
            "WantedBy=graphical-session.target\n"
        )

    def start(self) -> bool:
        self._unit_dir.mkdir(parents=True, exist_ok=True)
        unit = self._unit_dir / WATCH_UNIT
        fsutil.atomic_write(unit, self.unit_text().encode("utf-8"), what="the watcher unit")
        unit.chmod(0o644)
        self._systemctl_run("daemon-reload")
        return self._systemctl_run("enable", "--now", WATCH_UNIT) == 0 and self.active()

    def stop(self) -> None:
        self._systemctl_run("disable", "--now", WATCH_UNIT)

    def active(self) -> bool:
        return self._systemctl_run("is-active", "--quiet", WATCH_UNIT) == 0

    def _systemctl_run(self, *args: str) -> int:
        return self._run([self._systemctl, "--user", *args])


class NoWatcher:
    """No systemd: veil can't watch copies (the explicit hotkeys still work)."""

    def start(self) -> bool:
        return False

    def stop(self) -> None:
        return None

    def active(self) -> bool:
        return False


def unit_dir() -> Path:
    from veil import paths

    return paths.config_dir().parent / "systemd" / "user"  # $XDG_CONFIG_HOME/systemd/user


def detect_watcher(which: Callable[[str], str | None] = shutil.which) -> Watcher:
    systemctl = which("systemctl")
    return SystemdWatcher(systemctl, unit_dir()) if systemctl else NoWatcher()


# ── the end-time timer (best effort; the watcher's clock check is the guarantee) ──


class Timers(Protocol):
    def schedule(self, switch: Switch, now: datetime) -> bool: ...

    def cancel(self) -> None: ...


class SystemdTimers:
    """A transient `systemd-run --user` timer that runs `veil kill-switch-timer expire`."""

    def __init__(
        self,
        systemd_run: str,
        systemctl: str,
        *,
        python: str = sys.executable,
        env: dict[str, str] | None = None,
        run: Run | None = None,
    ) -> None:
        self._systemd_run, self._systemctl = systemd_run, systemctl
        self._python = python
        self._env = dict(os.environ) if env is None else env
        self._run = run or _run

    def schedule(self, switch: Switch, now: datetime) -> bool:
        self.cancel()
        if switch.until is None:
            return True
        delay = max(switch.until - now, timedelta(seconds=1))
        argv = timer_argv(
            self._systemd_run,
            EXPIRE_UNIT,
            delay,
            [TIMER_COMMAND, "expire"],
            repeat=False,
            env=self._env,
            python=self._python,
        )
        return self._run(argv) == 0

    def cancel(self) -> None:
        units = [f"{unit}.timer" for unit in (EXPIRE_UNIT, *LEGACY_UNITS)]
        self._run([self._systemctl, "--user", "stop", *units])


def timer_argv(
    systemd_run: str,
    unit: str,
    delay: timedelta,
    veil_args: Sequence[str],
    *,
    repeat: bool,
    env: dict[str, str],
    python: str = sys.executable,
) -> list[str]:
    """A transient `systemd-run --user` timer that runs `python -m veil <veil_args>` after
    `delay` (and every `delay` after that, with `repeat`)."""
    seconds = max(1, int(delay.total_seconds()))
    argv = [
        systemd_run,
        "--user",
        "--collect",
        "--quiet",
        f"--unit={unit}",
        f"--on-active={seconds}s",
        "--timer-property=AccuracySec=1s",
    ]
    if repeat:
        argv.append(f"--on-unit-active={seconds}s")
    for name in ("XDG_CONFIG_HOME", "DBUS_SESSION_BUS_ADDRESS"):
        if env.get(name):
            argv.append(f"--setenv={name}={env[name]}")
    return [*argv, "--", python, "-m", "veil", *veil_args]


class NoTimers:
    def schedule(self, switch: Switch, now: datetime) -> bool:
        return switch.until is None

    def cancel(self) -> None:
        return None


def detect_timers(which: Callable[[str], str | None] = shutil.which) -> Timers:
    systemd_run, systemctl = which("systemd-run"), which("systemctl")
    if systemd_run and systemctl:
        return SystemdTimers(systemd_run, systemctl)
    return NoTimers()


def _run(argv: Sequence[str]) -> int:
    try:
        return subprocess.run(  # noqa: S603 - fixed argv, no shell, no values
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        ).returncode
    except (OSError, subprocess.SubprocessError):
        return -1


# ── transitions ───────────────────────────────────────────────────────────────


def switch_on(
    config: Path, watcher: Watcher, timers: Timers, now: datetime, duration: timedelta | None = None
) -> tuple[Switch, bool]:
    """Start the watcher, then record ON. Raises VeilError if the watcher won't run (veil then
    stays OFF: never "ON" without protection). Returns (switch, end timer scheduled)."""
    if not watcher.start():
        watcher.stop()
        raise VeilError(
            "the copy watcher didn't start (systemd user service veil-watch); veil stays OFF",
            exit_code=ExitCode.UNSAFE_ENVIRONMENT,
        )
    switch = Switch(True, now, None if duration is None else now + duration)
    write(config, switch)
    return switch, timers.schedule(switch, now)


def switch_off(config: Path, watcher: Watcher, timers: Timers) -> None:
    """Stop the watcher first (that is what ends the sanitizing), then record OFF. The caller
    has confirmed it with a human, or the end time has passed."""
    watcher.stop()
    write(config, OFF)
    timers.cancel()


def status_line(reading: Reading, now: datetime) -> str:
    switch = reading.switch
    if reading.is_on(now):
        if switch.until is not None:
            left = describe_duration(switch.until - now)
            return f"veil: ON, every copy is sanitized (until {_local(switch.until)}, {left} left)"
        return "veil: ON, every copy is sanitized"
    if reading.watching:
        return "veil: ON but its time is up (the next copy is sanitized, then veil switches OFF)"
    return "veil: OFF, copy and paste are normal"


def _local(moment: datetime | None) -> str:
    return moment.astimezone().strftime("%H:%M") if moment else "?"


# ── what the user sees (value-free: states and times only) ────────────────────


def toggle_hint() -> str:
    """How to switch: the hotkey only once `veil install-shortcuts` set it up."""
    from veil import shortcuts

    keys = shortcuts.installed_keys(shortcuts.TOGGLE)
    return f"{keys} switches it." if keys else "`veil on` / `veil off` switch it."


def on_message(switch: Switch, now: datetime) -> Message:
    if switch.until is not None:
        until = f"Until {_local(switch.until)} ({describe_duration(switch.until - now)}). "
    else:
        until = "Until you switch it off. "
    return Message(
        "veil ON",
        f"Every copy is sanitized: Ctrl+V pastes the sanitized text.\n{until}{toggle_hint()}",
        icon="security-high",
    )


def off_message(*, expired: bool = False) -> Message:
    reason = "Its time is up. " if expired else ""
    return Message(
        "veil OFF",
        f"{reason}Copy and paste are normal again: sanitize before pasting into a chat.\n"
        f"{toggle_hint()}",
        Urgency.CRITICAL if expired else Urgency.NORMAL,
        icon="security-low",
    )


def on_timer(
    event: str, config: Path, watcher: Watcher, timers: Timers, now: datetime
) -> Message | None:
    """What a systemd timer does (`veil kill-switch-timer expire`). Switches OFF only when the
    ON time the user chose has run out. Old reminder timers (`remind`) just stop themselves."""
    switch, _ = read_switch(config)
    if event == "expire" and switch.expired(now):
        switch_off(config, watcher, timers)
        return off_message(expired=True)
    if event != "expire":
        timers.cancel()
    return None


# ── switching OFF from the hotkey: one click in a notification ───────────────

CONFIRM_SECONDS = 30

# (message, buttons, timeout in s) → the clicked button's name, or None (no answer)
Chooser = Callable[[Message, Sequence[tuple[str, str]], int], str | None]

# Plasma shares the notification's width among the buttons and cuts long labels (owner's
# screenshot 2026-10-26): labels stay short, the body explains them.
MAX_BUTTON_LABEL = 10
CONFIRM_BUTTONS = (("off", "Switch OFF"), ("keep", "Keep ON"))


def confirm_message() -> Message:
    return Message(
        "Switch veil OFF?",
        f"Copies won't be sanitized any more.\nNo answer in {CONFIRM_SECONDS} s = veil stays ON.",
        Urgency.CRITICAL,
        icon="dialog-question",
    )


def confirm_by_notification(choose: Chooser | None) -> bool:
    """Only a click on Switch OFF confirms. Every way of not answering (no notify-send,
    timeout, closed, odd reply) keeps veil ON."""
    if choose is None:
        return False
    return choose(confirm_message(), CONFIRM_BUTTONS, CONFIRM_SECONDS) == "off"


def detect_chooser(which: Callable[[str], str | None] = shutil.which) -> Chooser | None:
    path = which("notify-send")
    if path is None:
        return None
    from veil.clip import notify

    return lambda message, actions, timeout: notify.choose(path, message, actions, timeout)
