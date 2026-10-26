"""veil ON = every copy sanitized (ADR-0031): the copy watcher, auto-mode sanitizing, and the
recent-writes guard that keeps it from looping or undoing a restore.

In-memory clipboard (FakeBoard remembers its writes like the real backends), synthetic persona;
conftest keeps the recent-writes list, the watcher service and notifications in the sandbox.
"""

import io
import json
from datetime import timedelta

import pytest

from tests.helpers.fakeclip import FakeBoard
from tests.unit.test_clip_commands import FAKE, FAKES, REAL, Loader, assert_no_reals, run
from tests.unit.test_clip_commands import board as board
from tests.unit.test_clip_commands import engine as engine
from tests.unit.test_textcmd import imported  # noqa: F401 - pytest fixture
from veil import killswitch, paths
from veil.clip import commands, messages, recent, watch
from veil.clip.commands import Action, Outcome, Skip
from veil.clip.io import Selection, plain_only
from veil.clip.notify import Urgency
from veil.errors import ClipboardError
from veil.exitcodes import ExitCode

SENSITIVE = "Jane Doe has asthma.\n"


# ── the recent-writes guard ───────────────────────────────────────────────────


class TestRecent:
    def test_remember_and_seen(self):
        recent.remember("hello")
        assert recent.seen("hello")
        assert not recent.seen("hello!")

    def test_forgets_after_ten_seconds(self):
        assert recent.MAX_AGE == 10.0
        recent.remember("x", now=1000.0)
        assert recent.seen("x", now=1000.0 + recent.MAX_AGE - 1)
        assert not recent.seen("x", now=1000.0 + recent.MAX_AGE)

    def test_consume_uses_the_entry_up(self):
        recent.remember("x", now=1000.0)
        assert recent.consume("x", now=1001.0)
        assert not recent.consume("x", now=1002.0)
        assert not recent.seen("x", now=1002.0)

    def test_consume_one_of_two_identical_writes(self):
        recent.remember("x", now=1000.0)
        recent.remember("x", now=1000.5)
        assert recent.consume("x", now=1001.0)
        assert recent.consume("x", now=1001.0)
        assert not recent.consume("x", now=1001.0)

    def test_consume_never_raises(self, monkeypatch):
        def broken():
            raise OSError("gone")

        monkeypatch.setattr(recent, "location", broken)
        assert recent.consume("x") is False

    def test_concurrent_writers_keep_every_entry(self):
        import threading

        threads = [threading.Thread(target=recent.remember, args=(f"t{i}",)) for i in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(recent.seen(f"t{i}") for i in range(12))

    def test_keeps_the_last_sixteen(self):
        for i in range(recent.KEEP + 5):
            recent.remember(f"t{i}", now=1000.0 + i)
        assert not recent.seen("t0", now=1021.0)
        assert recent.seen(f"t{recent.KEEP + 4}", now=1021.0)

    def test_stores_no_text(self, recent_writes):
        recent.remember(REAL)
        stored = recent_writes.read_text()
        assert_no_reals(stored)
        assert recent_writes.stat().st_mode & 0o777 == 0o600

    def test_hashes_are_keyed(self, recent_writes):
        recent.remember("same")
        first = json.loads(recent_writes.read_text())["entries"][0][1]
        recent_writes.unlink()
        recent.remember("same")
        second = json.loads(recent_writes.read_text())["entries"][0][1]
        assert first != second  # a new key: hashes can't be compared across sessions

    @pytest.mark.parametrize("content", [b"garbage", b"{}", b'{"key": "short", "entries": []}'])
    def test_damaged_list(self, recent_writes, content):
        recent_writes.write_bytes(content)
        recent_writes.chmod(0o600)
        assert not recent.seen("x")
        recent.remember("x")  # replaced, not stuck
        assert recent.seen("x")

    def test_unwritable_location_never_raises(self, monkeypatch, tmp_path):
        def broken():
            raise OSError("no runtime dir")

        monkeypatch.setattr(recent, "location", broken)
        recent.remember("x")
        assert recent.seen("x") is False


# ── the watcher command ───────────────────────────────────────────────────────


class TestWatch:
    def test_argv(self):
        assert watch.argv("/usr/bin/wl-paste", "/py") == [
            "/usr/bin/wl-paste", "--watch", "/py", "-m", "veil", "clip", "sanitize", "--auto",
        ]  # fmt: skip

    def test_run_execs_wl_paste(self):
        calls = []
        watch.run(
            which=lambda name: f"/usr/bin/{name}",
            env={"WAYLAND_DISPLAY": "wayland-0"},
            execv=lambda path, argv: calls.append((path, argv)),
        )
        assert calls[0][0] == "/usr/bin/wl-paste"
        assert calls[0][1][1:3] == ["--watch", calls[0][1][2]]

    @pytest.mark.parametrize(
        ("which", "env"),
        [
            (lambda name: None, {"WAYLAND_DISPLAY": "wayland-0"}),
            (lambda name: f"/usr/bin/{name}", {}),
        ],
    )
    def test_needs_wayland_and_wl_paste(self, which, env):
        with pytest.raises(ClipboardError):
            watch.run(which=which, env=env, execv=lambda *a: None)

    def test_drain_reads_and_drops(self):
        stream = io.BytesIO(b"x" * 300_000)
        stream.isatty = lambda: False
        watch.drain_stdin(stream)
        assert stream.read() == b""

    def test_drain_stops_at_the_limit(self):
        stream = io.BytesIO(b"x" * 1000)
        stream.isatty = lambda: False
        watch.drain_stdin(stream, limit=10)
        assert stream.read()  # stopped early, rest left alone

    def test_drain_gives_up_on_a_pipe_that_never_closes(self):
        import os
        import time

        read_end, write_end = os.pipe()
        try:
            os.write(write_end, b"partial")
            stream = os.fdopen(read_end, "rb", buffering=0)
            start = time.monotonic()
            watch.drain_stdin(stream, deadline=0.3)
            assert time.monotonic() - start < 2
        finally:
            os.close(write_end)
            stream.close()

    def test_drain_handles_a_closed_stdin(self):
        stream = io.BytesIO(b"")
        stream.close()
        watch.drain_stdin(stream)  # no exception

    def test_drain_skips_a_terminal(self):
        stream = io.BytesIO(b"typed")
        stream.isatty = lambda: True
        watch.drain_stdin(stream)
        assert stream.read() == b"typed"


# ── auto-mode sanitizing ──────────────────────────────────────────────────────


class TestAuto:
    def test_sanitizes_a_copy(self, engine):
        board = FakeBoard.with_text(REAL)
        outcome = commands.sanitize(board, Loader(engine), auto=True)
        assert outcome.changed
        assert board.text() == FAKE

    def test_own_write_is_skipped_before_decrypting(self, engine):
        board = FakeBoard.with_text(REAL)
        commands.sanitize(board, Loader(engine), auto=True)  # writes FAKE, remembered
        loader = Loader(engine)
        outcome = commands.sanitize(board, loader, auto=True)  # the watcher sees it come back
        assert outcome.skipped is Skip.OWN
        assert loader.calls == 0
        assert board.writes == [FAKE]

    def test_loop_ends_even_without_the_guard(self, engine, monkeypatch):
        monkeypatch.setattr(recent, "seen", lambda text, **kw: False)
        board = FakeBoard.with_text(REAL)
        commands.sanitize(board, Loader(engine), auto=True)
        commands.sanitize(board, Loader(engine), auto=True)  # plain fake text: nothing to do
        assert board.writes == [FAKE]

    def test_rich_types_are_still_dropped(self, engine):
        board = FakeBoard.with_text("no details here", html="<b>no details here</b>")
        commands.sanitize(board, Loader(engine), auto=True)
        assert board.types() == ["text/plain"]

    def test_restore_is_not_undone(self, engine):
        board = FakeBoard.with_text(FAKE)
        commands.restore(board, Loader(engine))  # writes REAL, remembered
        outcome = commands.sanitize(board, Loader(engine), auto=True)
        assert outcome.skipped is Skip.OWN
        assert board.text() == REAL

    def test_restored_text_copied_again_is_sanitized(self, engine):
        # Sweep 2026-10-26 (was a leak): restore writes the real text; the watcher sees that
        # write once; copying the same real text again is a NEW copy and must be sanitized.
        board = FakeBoard.with_text(FAKE)
        commands.restore(board, Loader(engine))
        assert commands.sanitize(board, Loader(engine), auto=True).skipped is Skip.OWN
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}  # copied again
        outcome = commands.sanitize(board, Loader(engine), auto=True)
        assert outcome.skipped is None
        assert board.text() == FAKE

    def test_own_write_is_skipped_once(self, engine):
        board = FakeBoard.with_text(REAL)
        commands.sanitize(board, Loader(engine), auto=True)
        assert commands.sanitize(board, Loader(engine), auto=True).skipped is Skip.OWN
        # The same (fake) text again: nothing to replace and plain only, so nothing is written.
        assert commands.sanitize(board, Loader(engine), auto=True).skipped is None
        assert board.writes == [FAKE]

    def test_remembered_before_the_write(self, engine, monkeypatch):
        order = []
        monkeypatch.setattr(recent, "remember", lambda text, **kw: order.append("remember"))
        board = FakeBoard.with_text(REAL)
        real_write = board.write_text

        def write(text):
            real_write(text)
            order.append("write")

        board.write_text = write
        commands.sanitize(board, Loader(engine), auto=True)
        assert order[:2] == ["remember", "write"]

    def test_failed_write_leaves_only_a_harmless_entry(self, engine):
        board = FakeBoard.with_text(REAL)
        board.fail_write = True
        with pytest.raises(ClipboardError):
            commands.sanitize(board, Loader(engine), auto=True)
        # The entry is for the fake text, which isn't on the clipboard: the real copy is not
        # skipped on the next run.
        board.fail_write = False
        assert commands.sanitize(board, Loader(engine), auto=True).skipped is None

    def test_explicit_commands_never_skip(self, engine):
        board = FakeBoard.with_text(REAL)
        commands.sanitize(board, Loader(engine))
        assert commands.sanitize(board, Loader(engine)).skipped is None


class TestQuiet:
    @pytest.mark.parametrize("skip", [Skip.EMPTY, Skip.NON_TEXT, Skip.SECRET, Skip.OWN])
    def test_silent_skips(self, skip):
        assert not messages.worth_notifying(Outcome(Action.SANITIZE, skip), auto=True)

    @pytest.mark.parametrize("skip", [Skip.RICH_ONLY, Skip.DENIED])
    def test_loud_skips(self, skip):
        assert messages.worth_notifying(Outcome(Action.SANITIZE, skip), auto=True)

    def test_nothing_replaced_is_silent(self):
        assert not messages.worth_notifying(Outcome(Action.SANITIZE), auto=True)

    def test_copied_answer_with_fakes_is_silent(self):
        # Copying an AI answer while ON: full of fake forms, nothing real to replace.
        assert not messages.worth_notifying(
            Outcome(Action.SANITIZE, preexisting_fakes=4), auto=True
        )

    def test_fakes_plus_replacements_notify(self):
        outcome = Outcome(Action.SANITIZE, replaced={"name": 1}, preexisting_fakes=2)
        assert messages.worth_notifying(outcome, auto=True)

    def test_replacements_notify(self):
        outcome = Outcome(Action.SANITIZE, replaced={"name": 1})
        assert messages.worth_notifying(outcome, auto=True)

    @pytest.mark.parametrize("skip", [*Skip, None])
    def test_commands_you_run_always_notify(self, skip):
        assert messages.worth_notifying(Outcome(Action.SANITIZE, skip), auto=False)


@pytest.mark.usefixtures("imported")
class TestCli:
    def test_auto_sanitizes(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        code, out, err = run(capsys, "sanitize", "--auto")
        assert code == ExitCode.OK
        assert board.text() == FAKE
        assert notifications[-1].summary.startswith("veil: sanitized")
        assert_no_reals(out, err)
        for fake in FAKES:
            assert fake not in err

    def test_auto_is_quiet_without_details(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {"text/plain": b"ordinary words"}
        run(capsys, "sanitize", "--auto")
        assert notifications == []

    def test_copying_an_answer_is_silent(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {
            "text/plain": FAKE.encode(),
            "text/html": b"<p>answer</p>",
        }
        _, _, err = run(capsys, "sanitize", "--auto")
        assert notifications == []
        assert board.types() == ["text/plain"]  # the rich version is still dropped
        assert "already contained" in err  # stderr (the service log) still says it

    def test_auto_image_is_silent(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {"image/png": b"x"}
        run(capsys, "sanitize", "--auto")
        assert notifications == []
        assert board.writes == []

    def test_auto_rich_only_warns(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {"text/html": b"<b>x</b>"}
        run(capsys, "sanitize", "--auto")
        assert notifications[-1].urgency is Urgency.CRITICAL

    def test_auto_fails_closed(self, board, capsys):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        board.fail_write = True
        code, _, _ = run(capsys, "sanitize", "--auto")
        assert code == ExitCode.CLIPBOARD
        assert board.text() is None

    def test_auto_asks_before_sending(self, board, capsys, asker):
        board.offers[Selection.CLIPBOARD] = {"text/plain": SENSITIVE.encode()}
        run(capsys, "sanitize", "--auto")
        assert asker.questions  # the copy still gets the Allow/Generalize/Deny question
        assert board.text() is None  # scripted Deny

    def test_time_up_sanitizes_then_switches_off(self, board, capsys, copy_watcher, notifications):
        assert run(capsys, "sanitize")[0] == ExitCode.OK  # (warm up the store)
        copy_watcher.running = True
        now = killswitch.utc_now()
        killswitch.write(paths.config_dir(), killswitch.Switch(True, now - timedelta(hours=1), now))
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        _, _, err = run(capsys, "sanitize", "--auto")
        assert board.text() == FAKE  # this copy was still sanitized
        assert "veil: OFF (its time is up)" in err
        assert killswitch.read_switch(paths.config_dir())[0] == killswitch.OFF
        assert not copy_watcher.running
        assert notifications[-1].summary == "veil OFF"

    def test_not_due_keeps_watching(self, board, capsys, copy_watcher):
        copy_watcher.running = True
        killswitch.write(paths.config_dir(), killswitch.Switch(True, killswitch.utc_now()))
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        run(capsys, "sanitize", "--auto")
        assert copy_watcher.running

    def test_watch_command(self, capsys, monkeypatch):
        calls = []
        monkeypatch.setattr(watch, "run", lambda: calls.append(1))
        assert run(capsys, "watch")[0] == ExitCode.OK
        assert calls == [1]

    def test_auto_not_listed(self, capsys):
        with pytest.raises(SystemExit):
            run(capsys, "sanitize", "--help")
        assert "--auto" not in capsys.readouterr().out


def test_plain_only():
    assert plain_only(["text/plain", "text/plain;charset=utf-8", "TARGETS"])
    assert not plain_only(["text/plain", "text/html"])
    assert not plain_only([])


@pytest.mark.parametrize(
    "mime",
    ['text/plain;charset="utf-8"', "text/plain; charset=UTF8", "text/plain;charset='utf-8'"],
)
def test_plain_text_with_odd_charset_spelling_is_plain(mime):
    from veil.clip.io import Kind, classify

    kind, chosen = classify([mime, "text/html"])
    assert kind is Kind.TEXT
    assert chosen == mime  # the type is requested exactly as offered


@pytest.mark.usefixtures("imported")
def test_watcher_runs_never_rebuild_the_history(board, capsys, clip_history):
    board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
    run(capsys, "sanitize", "--auto")
    assert clip_history.calls == 0  # its re-adds would wake the watcher again
    run(capsys, "sanitize")
    assert clip_history.calls == 1  # the hotkey still removes the original


def test_real_clipboard_is_guarded_in_tests():
    from veil.clip import io as clipio

    with pytest.raises(AssertionError, match="real clipboard"):
        clipio.detect()
