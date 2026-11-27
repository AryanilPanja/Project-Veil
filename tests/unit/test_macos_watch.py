"""macOS watcher: the polling loop, the launchd agent, osascript notifications and dialogs."""

import contextlib
import plistlib
import sys

import pytest

from veil import killswitch
from veil.clip import ask, macnotify, macwatch, watch
from veil.clip import notify as notifymod
from veil.clip.notify import Message
from veil.clip.proc import Captured

# Bound before conftest replaces the detectors with fakes.
REAL = {
    "watcher": killswitch.detect_watcher,
    "timers": killswitch.detect_timers,
    "chooser": killswitch.detect_chooser,
    "notify": notifymod.detect,
    "ask": ask.detect,
}


class Script:
    """A fake clock and pasteboard: `counts` are successive changeCount reads."""

    def __init__(self, counts, *, idle=0.0, clock_ok=10**9):
        self.counts, self.idle, self.clock_ok = list(counts), idle, clock_ok
        self.copies = self.clock_calls = 0
        self.slept: list[float] = []
        self.now = 0.0

    def change_count(self):
        if not self.counts:
            raise StopIteration  # ends the test loop
        return self.counts.pop(0)

    def on_copy(self):
        self.copies += 1

    def on_clock(self):
        self.clock_calls += 1
        return self.clock_calls <= self.clock_ok

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds

    def run(self):
        with contextlib.suppress(StopIteration):
            macwatch.run(
                self.change_count,
                self.on_copy,
                self.on_clock,
                idle=lambda: self.idle,
                sleep=self.sleep,
                monotonic=lambda: self.now,
            )


def test_copy_runs_once_and_own_write_is_skipped():
    # start 5; poll 5; poll 6 (copy) -> re-read 7 (veil's write); poll 7; poll 7
    script = Script([5, 5, 6, 7, 7, 7])
    script.run()
    assert script.copies == 1


def test_image_write_bumps_change_count_and_is_ignored():
    from tests.helpers.fakeclip import FakeBoard
    from tests.unit.test_imagemeta import build_png
    from veil.clip import commands

    png, _ = build_png((b"tEXt", b"Author\x00Jane Doe"))
    board = FakeBoard({"image/png": png})
    counter = [10]
    outcomes = []

    def on_copy():
        outcomes.append(commands.sanitize(board, lambda: pytest.fail("must not load"), auto=True))
        counter[0] = 12  # pasteboard.write_image bumps changeCount

    polls = iter([10, 11, 12, 12])  # initial 10; poll 11 (copy) -> re-read 12; poll 12; poll 12
    ticks = 0

    def next_count():
        nonlocal ticks
        ticks += 1
        if ticks == 3:
            return counter[0]
        return next(polls)

    with contextlib.suppress(StopIteration):
        macwatch.run(
            next_count,
            on_copy,
            lambda: True,
            idle=lambda: 0.0,
            sleep=lambda _s: None,
            monotonic=lambda: 0.0,
        )
    assert len(outcomes) == 1
    assert outcomes[0].image_removed == 1
    assert len(board.image_writes) == 1


def test_polls_fast_while_active_and_slow_when_idle():
    active = Script([1, 1, 1])
    active.run()
    assert set(active.slept) == {macwatch.ACTIVE_SECONDS}
    idle = Script([1, 1, 1], idle=macwatch.IDLE_AFTER_SECONDS + 1)
    idle.run()
    assert set(idle.slept) == {macwatch.IDLE_SECONDS}


def test_off_at_start_never_polls():
    script = Script([1], clock_ok=0)
    script.run()
    assert script.slept == []


def test_clock_check_ends_the_loop():
    polls = int(macwatch.CLOCK_CHECK_SECONDS / macwatch.ACTIVE_SECONDS) + 5
    script = Script([1] * (polls + 10), clock_ok=1)
    script.run()
    assert script.clock_calls == 2
    assert len(script.slept) <= polls


def test_watch_run_on_macos_does_not_need_wayland(monkeypatch):
    called = []
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(watch, "run_macos", lambda: called.append(True))
    watch.run(which=lambda _name: None, env={}, execv=lambda *_a: pytest.fail("execv"))
    assert called == [True]


@pytest.mark.skipif(sys.platform != "darwin", reason="CoreGraphics is macOS only")
def test_idle_seconds_reads_core_graphics():
    assert macwatch.idle_seconds() >= 0.0


# ── launchd ──────────────────────────────────────────────────────────────────


def agent(tmp_path, codes=None):
    calls = []

    def run(argv):
        calls.append(list(argv))
        return (codes or {}).get(argv[1], 0)

    watcher = killswitch.LaunchdWatcher(
        tmp_path / "LaunchAgents", python="/opt/py 3/python", env={"XDG_CONFIG_HOME": "/x y"},
        uid=501, run=run,
    )  # fmt: skip
    return watcher, calls


def test_plist_runs_the_watcher_and_survives_odd_paths(tmp_path):
    watcher, _ = agent(tmp_path)
    data = plistlib.loads(watcher.plist_bytes())
    assert data["Label"] == killswitch.LAUNCHD_LABEL
    assert data["ProgramArguments"] == ["/opt/py 3/python", "-m", "veil", "clip", "watch"]
    assert data["KeepAlive"] == {"SuccessfulExit": False}
    assert data["EnvironmentVariables"] == {"XDG_CONFIG_HOME": "/x y"}
    assert data["StandardErrorPath"] == "/dev/null"


def test_start_writes_plist_and_bootstraps(tmp_path):
    watcher, calls = agent(tmp_path)
    assert watcher.start() is True
    assert watcher.plist_path.exists()
    assert oct(watcher.plist_path.stat().st_mode & 0o777) == "0o644"
    verbs = [c[1] for c in calls]
    assert verbs == ["bootout", "bootstrap", "print"]
    assert calls[1][2:] == ["gui/501", str(watcher.plist_path)]


def test_failed_bootstrap_reports_false(tmp_path):
    watcher, _ = agent(tmp_path, codes={"bootstrap": 5})
    assert watcher.start() is False


def test_stop_removes_plist_before_bootout(tmp_path):
    watcher, _ = agent(tmp_path)
    watcher.start()
    seen = []
    watcher._run = lambda argv: seen.append(watcher.plist_path.exists()) or 0
    watcher.stop()
    assert seen == [False]


def test_detect_on_macos(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert isinstance(REAL["watcher"](), killswitch.LaunchdWatcher)
    assert isinstance(REAL["timers"](), killswitch.WatcherClock)
    assert REAL["chooser"]() is macnotify.choose


# ── osascript ────────────────────────────────────────────────────────────────

INJECT = 'x" & (do shell script "touch /tmp/pwned") & "'


def test_texts_are_arguments_never_script_source():
    argv = macnotify.notify_argv(Message(INJECT, INJECT))
    split = argv.index("--")
    assert all(INJECT not in part for part in argv[:split])
    assert argv[split + 1 :] == [INJECT, INJECT]


def test_dialog_argv_has_labels_and_timeout_as_arguments():
    argv = macnotify.choice_argv(Message("s", "b"), [("a", "Allow"), ("d", "Deny")], 30)
    assert argv[argv.index("--") + 1 :] == ["s", "b", "Allow", "Deny", "30"]
    with pytest.raises(ValueError, match="three buttons"):
        macnotify.choice_argv(Message("s", "b"), [("a", "1")] * 4, 30)


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (Captured(0, b"Generalize\n", b""), ask.Decision.GENERALIZE),
        (Captured(0, b"\n", b""), ask.Decision.DENY),  # gave up
        (Captured(1, b"", b"-128"), ask.Decision.DENY),  # closed / error
        (Captured(0, b"Something else\n", b""), ask.Decision.DENY),
    ],
)
def test_dialog_asker_maps_replies(result, expected):
    asker = ask.DialogAsker(capture=lambda *_a, **_k: result)
    assert asker({"health": 1}, 30) is expected


def test_notify_and_ask_detect_on_macos(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert isinstance(REAL["notify"](), macnotify.OsascriptNotifier)
    assert isinstance(REAL["ask"](), ask.DialogAsker)
