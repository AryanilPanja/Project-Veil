"""The kill switch (M3.1, ADR-0018, spec §5): `veil on | off [--for 30m] | status | toggle`.

State: `<config>/state`, a small JSON file (0600, written atomically). OFF is only ever a
deliberate human action:
- a missing file means ON; so does an unreadable, corrupt or untrusted one (with a warning):
  errors never imply OFF (ADR-0022);
- whether veil is off is decided from the timestamps on every check, so `--for` expires on time
  even if no timer ever fires;
- switching off needs a terminal and a typed `off` (cli.py); M3.2 adds the hotkey path.

Notifications while OFF (best effort, never needed for correctness): a reminder every 60 minutes,
and one at expiry. They come from transient systemd user timers that run `veil` again
(`python -m veil kill-switch-timer remind|expire`); if scheduling fails, a warning says so.
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

STATE_FILE = "state"
MAX_STATE_BYTES = 4096
FORMAT = 1
REMIND_EVERY = timedelta(minutes=60)
MIN_FOR = timedelta(minutes=1)
MAX_FOR = timedelta(hours=24)
EXPIRE_UNIT = "veil-expire"
REMIND_UNIT = "veil-remind"
TIMER_COMMAND = "kill-switch-timer"

Clock = Callable[[], datetime]


def utc_now() -> datetime:
    return datetime.now(UTC)


# ── state ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Switch:
    """The stored switch. `off` alone isn't the answer: an OFF with a past `until` is ON."""

    off: bool = False
    since: datetime | None = None  # when it was switched off
    until: datetime | None = None  # when it switches itself back on (None: stays off)

    def is_off(self, now: datetime) -> bool:
        return self.off and (self.until is None or now < self.until)

    def expired(self, now: datetime) -> bool:
        """Switched off with a timer that has run out (effectively ON, not yet written)."""
        return self.off and self.until is not None and now >= self.until


ON = Switch()


@dataclass(frozen=True)
class Reading:
    switch: Switch
    problem: str | None = None  # value-free; set when the file couldn't be trusted (→ ON)


def state_path(config: Path) -> Path:
    return config / STATE_FILE


def read(config: Path) -> Reading:
    """The stored switch. Never raises: anything wrong means ON plus a problem to report."""
    path = state_path(config)
    try:
        if not path.exists() and not path.is_symlink():
            return Reading(ON)
        if not path.is_symlink() and path.lstat().st_mode & 0o022:
            raise ValueError("writable by others: someone else may have switched it")
        raw = fsutil.read_private(path, MAX_STATE_BYTES, "the kill-switch state file")
        return Reading(_decode(raw))
    except (VeilError, OSError, ValueError, TypeError, KeyError):
        return Reading(
            ON,
            "the kill-switch state file can't be read or trusted; "
            "veil stays ON (`veil on` resets it)",
        )


def write(config: Path, switch: Switch) -> None:
    fsutil.ensure_private_dir(config, "the veil config directory")
    fsutil.atomic_write(state_path(config), _encode(switch), what="the kill-switch state file")


def _encode(switch: Switch) -> bytes:
    data = {
        "format": FORMAT,
        "state": "off" if switch.off else "on",
        "since": _stamp(switch.since),
        "until": _stamp(switch.until),
    }
    return (json.dumps(data, sort_keys=True) + "\n").encode("ascii")


def _decode(raw: bytes) -> Switch:
    data = json.loads(raw.decode("ascii"))
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ValueError("unknown format")
    state = data["state"]
    if state == "on":
        return ON
    if state != "off":
        raise ValueError("unknown state")
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


# ── timers (notifications only) ───────────────────────────────────────────────


class Timers(Protocol):
    def schedule(self, switch: Switch, now: datetime) -> bool: ...

    def cancel(self) -> None: ...


class SystemdTimers:
    """Transient `systemd-run --user` timers that run `veil kill-switch-timer …`."""

    def __init__(
        self,
        systemd_run: str,
        systemctl: str,
        *,
        python: str = sys.executable,
        env: dict[str, str] | None = None,
        run: Callable[..., int] | None = None,
    ) -> None:
        self._systemd_run, self._systemctl = systemd_run, systemctl
        self._python = python
        self._env = dict(os.environ) if env is None else env
        self._run = run or _run

    def schedule(self, switch: Switch, now: datetime) -> bool:
        self.cancel()
        ok = self._run(self._timer(REMIND_UNIT, "remind", REMIND_EVERY, repeat=True)) == 0
        if switch.until is not None:
            delay = max(switch.until - now, timedelta(seconds=1))
            ok = self._run(self._timer(EXPIRE_UNIT, "expire", delay, repeat=False)) == 0 and ok
        return ok

    def cancel(self) -> None:
        self._run(
            [self._systemctl, "--user", "stop", f"{EXPIRE_UNIT}.timer", f"{REMIND_UNIT}.timer"]
        )

    def _timer(self, unit: str, event: str, delay: timedelta, *, repeat: bool) -> list[str]:
        seconds = max(1, int(delay.total_seconds()))
        argv = [
            self._systemd_run,
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
            if self._env.get(name):
                argv.append(f"--setenv={name}={self._env[name]}")
        return [*argv, "--", self._python, "-m", "veil", TIMER_COMMAND, event]


class NoTimers:
    def schedule(self, switch: Switch, now: datetime) -> bool:
        return False

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
            timeout=5,
            check=False,
        ).returncode
    except (OSError, subprocess.SubprocessError):
        return -1


# ── transitions ───────────────────────────────────────────────────────────────


def switch_off(
    config: Path, timers: Timers, now: datetime, duration: timedelta | None = None
) -> tuple[Switch, bool]:
    """Write OFF (the caller has already confirmed it with a human); schedule notifications.
    Returns the switch and whether the notifications could be scheduled."""
    switch = Switch(True, now, None if duration is None else now + duration)
    write(config, switch)
    return switch, timers.schedule(switch, now)


def switch_on(config: Path, timers: Timers) -> None:
    write(config, ON)
    timers.cancel()


def status_line(reading: Reading, now: datetime) -> str:
    switch = reading.switch
    if switch.is_off(now):
        if switch.until is not None:
            left = describe_duration(switch.until - now)
            return f"veil: OFF until {_local(switch.until)} ({left} left)"
        since = switch.since.astimezone().strftime("%Y-%m-%d %H:%M") if switch.since else "?"
        return f"veil: OFF since {since} (no timer: `veil on` to switch back)"
    if switch.expired(now):
        return f"veil: ON (the OFF timer ran out at {_local(switch.until)})"
    return "veil: ON"


def _local(moment: datetime | None) -> str:
    return moment.astimezone().strftime("%H:%M") if moment else "?"


# ── what the user sees (value-free: states and times only) ────────────────────

# How to switch back. The Meta+Alt+K hotkey joins this once `veil install-shortcuts` (M3.3)
# has registered it: until then a notification must not promise a key that does nothing.
SWITCH_BACK = "Run `veil on` to switch back."


def switch_back() -> str:
    """How to switch back ON: with the hotkey only once `veil install-shortcuts` set it up."""
    from veil import shortcuts

    keys = shortcuts.installed_keys(shortcuts.TOGGLE)
    if keys:
        return f"Run `veil on` or press {keys} to switch back."
    return SWITCH_BACK


def off_message(switch: Switch, now: datetime) -> Message:
    when = (
        f"Back ON at {_local(switch.until)} ({describe_duration(switch.until - now)})."
        if switch.until is not None
        else f"Reminder every {describe_duration(REMIND_EVERY)} until you switch it back."
    )
    return Message(
        "veil is OFF",
        f"Clipboard hotkeys do nothing: copied text is NOT sanitized.\n{when}\n{switch_back()}",
        Urgency.CRITICAL,
        icon="security-low",
    )


def on_message(*, expired: bool = False) -> Message:
    body = "The OFF timer ran out. " if expired else ""
    return Message("veil is ON", f"{body}Clipboard hotkeys sanitize again.")


def reminder_message(switch: Switch, now: datetime) -> Message:
    since = describe_duration(now - switch.since) if switch.since else "a while"
    return Message(
        "veil is still OFF",
        f"Off for {since}: copied text is NOT sanitized.\n{switch_back()}",
        Urgency.CRITICAL,
        icon="security-low",
    )


def on_timer(event: str, config: Path, timers: Timers, now: datetime) -> Message | None:
    """What a systemd timer does (`veil kill-switch-timer expire|remind`). Never switches off;
    at most switches back on (when the timer has run out). Returns the notification to show."""
    switch = read(config).switch
    if switch.expired(now):
        switch_on(config, timers)
        return on_message(expired=True)
    if not switch.is_off(now):
        timers.cancel()  # a stale timer: nothing to remind about
        return None
    if event == "remind":
        return reminder_message(switch, now)
    return None  # an early or stale expiry timer: the switch decides, not the timer


# ── switching off from the hotkey (M3.2): a click in a notification, not a terminal ───

CONFIRM_SECONDS = 30
HOTKEY_DEFAULT_FOR = timedelta(minutes=30)

# (message, buttons, timeout in s) → the clicked button's name, or None (no answer)
Chooser = Callable[[Message, Sequence[tuple[str, str]], int], str | None]


def confirm_buttons(duration: timedelta | None) -> list[tuple[str, str]]:
    if duration is not None:
        return [("off", f"Off for {describe_duration(duration)}"), ("keep", "Keep ON")]
    return [
        ("off-default", f"Off for {describe_duration(HOTKEY_DEFAULT_FOR)}"),
        ("off", "Off until `veil on`"),
        ("keep", "Keep ON"),
    ]


def confirm_message() -> Message:
    return Message(
        "Switch veil OFF?",
        "Asked by the kill-switch hotkey. While OFF, clipboard hotkeys don't sanitize copied "
        f"text.\nNo answer in {CONFIRM_SECONDS} s = veil stays ON.",
        Urgency.CRITICAL,
        icon="dialog-question",
    )


def confirm_by_notification(
    choose: Chooser | None, duration: timedelta | None
) -> tuple[bool, timedelta | None]:
    """Ask with buttons; only a click on an Off button confirms. Returns (confirmed, duration).
    Every way of not answering (no notify-send, timeout, closed, odd reply) keeps veil ON."""
    if choose is None:
        return False, None
    reply = choose(confirm_message(), confirm_buttons(duration), CONFIRM_SECONDS)
    if reply == "off-default" and duration is None:
        return True, HOTKEY_DEFAULT_FOR
    if reply == "off":
        return True, duration
    return False, None


def detect_chooser(which: Callable[[str], str | None] = shutil.which) -> Chooser | None:
    path = which("notify-send")
    if path is None:
        return None
    from veil.clip import notify

    return lambda message, actions, timeout: notify.choose(path, message, actions, timeout)
