"""Removing the original from KDE's clipboard history (M2.6): rebuild without it.

Never the owner's real history: a fake with the history's semantics (row 0 = newest, re-adding
moves to the top), and a fake history service on a private dbus-daemon for the jeepney layer.
conftest's autouse `clip_history` fixture keeps every CLI test off the real session bus.
"""

import shutil
import subprocess
import threading
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.helpers.fakeclip import FakeBoard
from tests.unit.test_clip_commands import FAKE, REAL, REALS, Loader, assert_no_reals, run
from tests.unit.test_clip_commands import board as board
from tests.unit.test_clip_commands import engine as engine
from tests.unit.test_textcmd import imported  # noqa: F401 - pytest fixture
from veil.clip import commands, history, messages
from veil.clip.commands import ERROR_PLACEHOLDER, WAITING_PLACEHOLDER, Action, Outcome
from veil.clip.history import (
    INTERFACE,
    OBJECT_PATH,
    SERVICE,
    Forget,
    HistoryError,
    JeepneyBus,
    forget,
    keepable,
    same,
)
from veil.clip.history import detect as real_detect  # bound before conftest patches it
from veil.clip.io import Selection
from veil.exitcodes import ExitCode

IMAGE = "▨ 800x600"


class FakeHistory:
    """The history's D-Bus behaviour, in memory. `fail` names methods that raise."""

    def __init__(self, entries=(), *, running=True) -> None:
        self.items = list(entries)  # row 0 = newest
        self.is_running = running
        self.fail: set[str] = set()
        self.calls: list[str] = []
        self.fail_adds_of: set[str] = set()

    def _check(self, name: str) -> None:
        self.calls.append(name)
        if name in self.fail:
            raise HistoryError(f"D-Bus error {name}")

    def running(self) -> bool:
        self._check("running")
        return self.is_running

    def entries(self) -> list[str]:
        self._check("entries")
        return list(self.items)

    def clear(self) -> None:
        self._check("clear")
        self.items = []

    def add(self, text: str) -> None:
        self._check("add")
        if text in self.fail_adds_of:
            raise HistoryError("D-Bus error add")
        if text in self.items:
            self.items.remove(text)
        self.items.insert(0, text)

    def captures(self, text: str):
        """put_back: the history picks up the sanitized write like any copy."""
        return lambda: self.add(text)


# ── forget ────────────────────────────────────────────────────────────────────


class TestForget:
    def test_removes_original_keeps_order(self):
        bus = FakeHistory([FAKE, REAL, "older one", "oldest"])
        assert forget(bus, REAL, bus.captures(FAKE)) is Forget.REMOVED
        assert bus.items == [FAKE, "older one", "oldest"]

    def test_sanitized_ends_on_top(self):
        bus = FakeHistory([REAL, "a", FAKE, "b"])
        forget(bus, REAL, bus.captures(FAKE))
        assert bus.items[0] == FAKE
        assert bus.items == [FAKE, "a", "b"]

    def test_every_copy_of_the_original_goes(self):
        bus = FakeHistory([FAKE, REAL, "x", f"  {REAL}\n", REAL.strip()])
        assert forget(bus, REAL, bus.captures(FAKE)) is Forget.REMOVED
        assert bus.items == [FAKE, "x"]

    def test_drops_images_and_veil_placeholders(self):
        bus = FakeHistory([FAKE, WAITING_PLACEHOLDER, REAL, IMAGE, ERROR_PLACEHOLDER, "keep"])
        forget(bus, REAL, bus.captures(FAKE))
        assert bus.items == [FAKE, "keep"]

    def test_not_found_touches_nothing(self):
        bus = FakeHistory([FAKE, "other"])
        assert forget(bus, REAL, bus.captures(FAKE)) is Forget.NOT_FOUND
        assert bus.calls == ["running", "entries"]
        assert bus.items == [FAKE, "other"]

    def test_not_running_touches_nothing(self):
        bus = FakeHistory([REAL], running=False)
        assert forget(bus, REAL, bus.captures(FAKE)) is Forget.NOT_RUNNING
        assert bus.calls == ["running"]

    @pytest.mark.parametrize("step", ["running", "entries", "clear"])
    def test_failure_before_rebuild_leaves_history(self, step):
        bus = FakeHistory([FAKE, REAL, "x"])
        bus.fail = {step}
        assert forget(bus, REAL, bus.captures(FAKE)) is Forget.FAILED
        assert bus.items == [FAKE, REAL, "x"]

    def test_failed_adds_are_partial(self):
        bus = FakeHistory([FAKE, REAL, "a", "b"])
        bus.fail_adds_of = {"a"}
        assert forget(bus, REAL, bus.captures(FAKE)) is Forget.PARTIAL
        assert bus.items == [FAKE, "b"]

    def test_put_back_failure_is_failed(self):
        bus = FakeHistory([FAKE, REAL])

        def broken():
            raise OSError

        assert forget(bus, REAL, broken) is Forget.FAILED

    def test_original_still_there_after_rebuild_is_failed(self):
        bus = FakeHistory([FAKE, REAL])
        assert forget(bus, REAL, bus.captures(REAL)) is Forget.FAILED  # recaptured

    def test_never_raises(self):
        class Exploding(FakeHistory):
            def entries(self):
                raise RuntimeError(REAL)

        assert forget(Exploding([REAL]), REAL, lambda: None) is Forget.FAILED

    def test_unicode_entries_survive(self):
        others = ["জেন দো নয়", "名前のない行", "emoji 🙂 line", "tab\tand\nnewline"]
        bus = FakeHistory([FAKE, REAL, *others])
        forget(bus, REAL, bus.captures(FAKE))
        assert bus.items == [FAKE, *others]

    def test_url_entries_are_kept_as_text(self):
        bus = FakeHistory([FAKE, REAL, "file:///tmp/a.txt"])
        forget(bus, REAL, bus.captures(FAKE))
        assert "file:///tmp/a.txt" in bus.items


class TestMatching:
    @pytest.mark.parametrize(
        ("entry", "original", "expected"),
        [
            ("abc", "abc", True),
            (" abc\n", "abc", True),
            ("abc", "abc\n", True),
            ("ab", "abc", False),
            ("ABC", "abc", False),
            ("", "   ", False),
            ("   ", "   ", True),
        ],
    )
    def test_same(self, entry, original, expected):
        assert same(entry, original) is expected

    @pytest.mark.parametrize(
        ("entry", "expected"),
        [
            ("text", True),
            ("", False),
            (IMAGE, False),
            ("▨ 12 × 34", False),
            ("▨ is a square", True),
            (WAITING_PLACEHOLDER, False),
            (ERROR_PLACEHOLDER, False),
            ("[veil is a word]", True),
        ],
    )
    def test_keepable(self, entry, expected):
        assert keepable(entry) is expected


TEXTS = st.text(st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=12)


@given(
    others=st.lists(TEXTS, unique=True, max_size=8),
    copies=st.integers(1, 3),
    data=st.data(),
)
def test_property_original_gone_rest_in_order(others, copies, data):
    original, sanitized = "the original text", "the sanitized text"
    others = [o for o in others if not same(o, original) and o != sanitized and keepable(o)]
    entries = [sanitized, *others]
    for _ in range(copies):
        entries.insert(data.draw(st.integers(0, len(entries))), original)
    entries = list(dict.fromkeys(entries))  # the history holds each entry once
    bus = FakeHistory(entries)
    assert forget(bus, original, bus.captures(sanitized)) is Forget.REMOVED
    assert original not in bus.items
    assert bus.items[0] == sanitized
    assert bus.items[1:] == [e for e in entries if e not in (original, sanitized)]


# ── commands, messages, CLI ───────────────────────────────────────────────────


class Spy:
    def __init__(self, result=Forget.REMOVED) -> None:
        self.result, self.originals = result, []

    def __call__(self, original, put_back):
        self.originals.append(original)
        put_back()
        return self.result


class TestCommands:
    def test_sanitize_forgets_the_original(self, engine):
        board = FakeBoard.with_text(REAL)
        spy = Spy()
        outcome = commands.sanitize(board, Loader(engine), forget=spy)
        assert outcome.history is Forget.REMOVED
        assert spy.originals == [REAL]
        assert board.writes == [FAKE, FAKE]  # put_back rewrites the sanitized text
        assert board.text() == FAKE

    def test_from_selection_forgets_the_selection(self, engine):
        board = FakeBoard(primary={"text/plain": REAL.encode()})
        spy = Spy(Forget.NOT_FOUND)
        outcome = commands.from_selection(board, Loader(engine), forget=spy)
        assert spy.originals == [REAL]
        assert outcome.history is Forget.NOT_FOUND

    def test_no_forgetter(self, engine):
        outcome = commands.sanitize(FakeBoard.with_text(REAL), Loader(engine))
        assert outcome.history is None

    def test_skips_do_not_forget(self, engine):
        spy = Spy()
        commands.sanitize(FakeBoard({"image/png": b"x"}), Loader(engine), forget=spy)
        assert spy.originals == []

    def test_errors_do_not_forget(self, engine):
        board = FakeBoard.with_text(REAL)
        board.fail_write = True
        spy = Spy()
        with pytest.raises(Exception):  # noqa: B017, PT011 - any error
            commands.sanitize(board, Loader(engine), forget=spy)
        assert spy.originals == []

    def test_deny_does_not_forget(self, engine):
        spy = Spy()
        board = FakeBoard.with_text("Jane has asthma.")
        outcome = commands.sanitize(board, Loader(engine), forget=spy)  # default asker: Deny
        assert outcome.asked == {"health": 1}
        assert outcome.skipped is commands.Skip.DENIED
        assert spy.originals == []

    def test_forget_failure_keeps_sanitized_clipboard(self, engine):
        board = FakeBoard.with_text(REAL)
        outcome = commands.sanitize(board, Loader(engine), forget=Spy(Forget.FAILED))
        assert outcome.changed
        assert board.text() == FAKE


class TestMessages:
    def outcome(self, result):
        return Outcome(Action.SANITIZE, replaced={"name": 1}, history=result)

    def test_removed(self):
        assert "veil: original removed from the clipboard history (Klipper)" in (
            messages.stderr_lines(self.outcome(Forget.REMOVED))
        )
        body = messages.notification(self.outcome(Forget.REMOVED)).body
        assert body.endswith("Original removed from Klipper's history.")

    def test_failed_warns(self):
        lines = messages.stderr_lines(self.outcome(Forget.FAILED))
        assert any(line.startswith("veil: warning: the original may still be") for line in lines)
        assert "Warning: the original may still be in Klipper's history." in (
            messages.notification(self.outcome(Forget.FAILED)).body
        )

    def test_partial(self):
        assert any(
            "could not be put back" in x
            for x in messages.stderr_lines(self.outcome(Forget.PARTIAL))
        )

    @pytest.mark.parametrize("result", [Forget.NOT_FOUND, Forget.NOT_RUNNING, None])
    def test_silent(self, result):
        quiet = messages.stderr_lines(self.outcome(None))
        assert messages.stderr_lines(self.outcome(result)) == quiet
        assert messages.notification(self.outcome(result)) == messages.notification(
            self.outcome(None)
        )

    @pytest.mark.parametrize("result", list(Forget))
    def test_value_free(self, result):
        lines = messages.stderr_lines(self.outcome(result))
        assert_no_reals(*lines, messages.notification(self.outcome(result)).body)


class TestCli:
    @pytest.mark.usefixtures("imported")
    def test_sanitize_forgets(self, board, capsys, clip_history):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        clip_history.result = Forget.REMOVED
        code, _, err = run(capsys, "sanitize")
        assert code == ExitCode.OK
        assert clip_history.calls == 1
        assert "original removed from the clipboard history" in err

    @pytest.mark.usefixtures("imported")
    def test_failure_is_a_warning_not_an_error(self, board, capsys, clip_history):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        clip_history.result = Forget.FAILED
        code, out, err = run(capsys, "sanitize")
        assert code == ExitCode.OK
        assert board.text() == FAKE
        assert "warning: the original may still be in the clipboard history" in err
        assert_no_reals(out, err)

    @pytest.mark.usefixtures("imported")
    def test_restore_never_forgets(self, board, capsys, clip_history):
        board.offers[Selection.CLIPBOARD] = {"text/plain": FAKE.encode()}
        assert run(capsys, "restore")[0] == ExitCode.OK
        assert clip_history.calls == 0


def test_detect_without_session_bus():
    assert real_detect({}) is None
    assert callable(real_detect({"DBUS_SESSION_BUS_ADDRESS": "unix:path=/nonexistent"}))


# ── jeepney against a private bus (never the session bus) ─────────────────────

CONFIG = """<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={path}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow own="*"/>
  </policy>
</busconfig>
"""


@pytest.fixture
def private_bus(tmp_path):
    daemon = shutil.which("dbus-daemon")
    if daemon is None:
        pytest.skip("dbus-daemon not installed")
    config = tmp_path / "bus.conf"
    config.write_text(CONFIG.format(path=tmp_path / "bus"), encoding="utf-8")
    proc = subprocess.Popen(
        [daemon, f"--config-file={config}", "--nofork", "--print-address"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        address = proc.stdout.readline().strip()
        assert address.startswith("unix:")
        yield address
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        proc.stdout.close()


class FakeService(threading.Thread):
    """A history service on the private bus, backed by FakeHistory."""

    def __init__(self, address: str, entries) -> None:
        super().__init__(daemon=True)
        from jeepney import message_bus
        from jeepney.io.blocking import open_dbus_connection

        self.store = FakeHistory(entries)
        self.stop = threading.Event()
        self.connection = open_dbus_connection(address)
        self.connection.send_and_get_reply(message_bus.RequestName(SERVICE))

    def run(self) -> None:
        from jeepney import HeaderFields, MessageType, new_error, new_method_return

        while not self.stop.is_set():
            try:
                message = self.connection.receive(timeout=0.1)
            except TimeoutError:
                continue
            except OSError:
                return
            header = message.header
            if header.message_type is not MessageType.method_call:
                continue
            member = header.fields.get(HeaderFields.member)
            if header.fields.get(HeaderFields.interface) != INTERFACE:
                continue
            if member == "getClipboardHistoryMenu":
                reply = new_method_return(message, "as", (self.store.entries(),))
            elif member == "clearClipboardHistory":
                self.store.clear()
                reply = new_method_return(message)
            elif member == "setClipboardContents":
                self.store.add(message.body[0])
                reply = new_method_return(message)
            else:
                reply = new_error(message, "org.freedesktop.DBus.Error.UnknownMethod")
            self.connection.send(reply)

    def close(self) -> None:
        self.stop.set()
        self.join(timeout=2)
        self.connection.close()


@pytest.fixture
def service(private_bus):
    started = []

    def start(entries):
        svc = FakeService(private_bus, entries)
        svc.start()
        started.append(svc)
        return svc

    yield start
    for svc in started:
        svc.close()


class TestJeepneyBus:
    def test_rebuild_over_dbus(self, private_bus, service):
        svc = service([FAKE, REAL, "জেন দো নয় 🙂", IMAGE, "oldest"])
        bus = JeepneyBus(private_bus)
        try:
            assert bus.running()
            assert forget(bus, REAL, lambda: bus.add(FAKE)) is Forget.REMOVED
        finally:
            bus.close()
        assert svc.store.items == [FAKE, "জেন দো নয় 🙂", "oldest"]

    def test_not_running(self, private_bus):
        bus = JeepneyBus(private_bus)
        try:
            assert bus.running() is False
            assert forget(bus, REAL, lambda: None) is Forget.NOT_RUNNING
        finally:
            bus.close()

    def test_dbus_error_carries_the_name_only(self, private_bus, service):
        service([])
        bus = JeepneyBus(private_bus)
        try:
            with pytest.raises(HistoryError) as caught:
                bus._method("noSuchMethod", "s", (REAL,))
        finally:
            bus.close()
        assert str(caught.value) == "D-Bus error org.freedesktop.DBus.Error.UnknownMethod"

    def test_no_auto_start(self, private_bus):
        from jeepney import DBusAddress, new_method_call
        from jeepney.low_level import MessageFlag

        bus = JeepneyBus(private_bus)
        sent = []
        try:
            bus.running()  # opens the connection
            original = bus._connection.send_and_get_reply

            def record(message, **kwargs):
                sent.append(message.header.flags)
                return original(message, **kwargs)

            bus._connection.send_and_get_reply = record
            with pytest.raises(HistoryError):
                bus._call(new_method_call(DBusAddress(OBJECT_PATH, SERVICE, INTERFACE), "x"))
        finally:
            bus.close()
        assert sent
        assert all(flags & MessageFlag.no_auto_start for flags in sent)

    def test_unreachable_bus_is_failed(self, tmp_path):
        bus = JeepneyBus(f"unix:path={tmp_path / 'none'}", timeout=0.5)
        assert forget(bus, REAL, lambda: None) is Forget.FAILED

    def test_history_text_never_in_argv(self):
        # jeepney talks over the socket; nothing is spawned with history text as an argument.
        source = Path(history.__file__).read_text(encoding="utf-8")
        for spawner in ("subprocess", "busctl", "qdbus", "gdbus", "os.system"):
            assert spawner not in source, spawner

    def test_reprs_hold_no_values(self, private_bus):
        bus = JeepneyBus(private_bus)
        assert all(real not in repr(bus) for real in REALS)
