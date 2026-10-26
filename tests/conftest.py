import hashlib
import os
import subprocess
import sys
import threading
from dataclasses import dataclass

import pytest
from hypothesis import settings

from veil import hardening

settings.register_profile("default", deadline=None)
settings.register_profile("ci", deadline=None, max_examples=500)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))


@pytest.fixture(autouse=True)
def _no_process_hardening_in_test_process(monkeypatch):
    """`veil.cli.main` hardens the process (umask, non-dumpable, exception hooks).

    Doing that to the pytest process would leak into other tests, so in-process tests get a
    recording stub. The real hardening is exercised in subprocesses (see `run_python`).
    """
    calls: list[str] = []
    monkeypatch.setattr(
        hardening, "apply", lambda: calls.append("apply") or hardening.HardeningReport(1, 1, 1)
    )
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    return calls


@pytest.fixture(autouse=True)
def _no_real_config_dirs(monkeypatch, tmp_path_factory):
    """No test may read or write the owner's real ~/.config/veil or ~/.local/share/veil."""
    sandbox = tmp_path_factory.mktemp("xdg-sandbox")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(sandbox / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(sandbox / "data"))
    monkeypatch.setenv("HOME", str(sandbox / "home"))


@pytest.fixture(autouse=True)
def _no_real_desktop(monkeypatch):
    """No test may reach the owner's display, clipboard, session bus, runtime dir or systemd
    (sweep 2026-10-26: these were guarded only where a test remembered to).

    - display and bus: unset / pointed at a socket that doesn't exist;
    - XDG_RUNTIME_DIR: a path that doesn't exist (never /run/user/<uid>/veil);
    - the clipboard: the CLI's `detect()` (no arguments) fails loudly unless a test installs
      the in-memory board (the `board` fixtures); calls with an explicit env/which (the tests
      of detect itself) still run the real logic;
    - systemctl / systemd-run: `killswitch._run` fails unless a test injects `run=`.
    """
    from veil import killswitch
    from veil.clip import io as clipio

    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/veil-test-bus")
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/nonexistent/veil-test-runtime")
    real_detect = clipio.detect

    def guarded_detect(env=None, which=None):
        if env is None and which is None:
            raise AssertionError("a test reached the real clipboard (use the `board` fixture)")
        return real_detect(env, which) if which is not None else real_detect(env)

    def forbidden_run(argv):
        raise AssertionError("a test tried to run systemctl/systemd-run")

    monkeypatch.setattr(clipio, "detect", guarded_detect)
    monkeypatch.setattr(killswitch, "_run", forbidden_run)


@pytest.fixture(autouse=True)
def _no_real_editor(monkeypatch):
    """The owner's $VISUAL/$EDITOR must never launch during tests (it would wait for a human)."""
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.delenv("EDITOR", raising=False)


@pytest.fixture(autouse=True)
def _no_real_keyring(monkeypatch):
    """No test may reach the owner's real KDE Wallet / Secret Service."""
    from veil.crypto import keystore

    def forbidden():
        raise AssertionError("a test tried to use the real Secret Service keyring")

    monkeypatch.setattr(keystore, "secret_service_backend", forbidden)


class RecordingNotifier:
    """Stands in for notify-send: records each Message instead of showing it."""

    def __init__(self) -> None:
        self.messages: list = []

    def notify(self, message) -> bool:
        self.messages.append(message)
        return True


@pytest.fixture(autouse=True)
def notifications(monkeypatch):
    """No test may pop up a real desktop notification. Returns what would have been shown."""
    from veil.clip import notify

    recorder = RecordingNotifier()
    monkeypatch.setattr(notify, "detect", lambda *a, **k: recorder)
    return recorder.messages


class ScriptedAsker:
    """Stands in for the Allow/Generalize/Deny notification: answers `answer` (default Deny)."""

    def __init__(self) -> None:
        self.answer = "deny"
        self.questions: list = []

    def __call__(self, categories, timeout):
        from veil.clip.ask import Decision

        self.questions.append((dict(categories), timeout))
        return Decision(self.answer)


@pytest.fixture(autouse=True)
def asker(monkeypatch):
    """No test may show a real ask-before-send prompt. Set `asker.answer` to script it."""
    from veil.clip import ask

    scripted = ScriptedAsker()
    monkeypatch.setattr(ask, "detect", lambda *a, **k: scripted)
    return scripted


class RecordingForgetter:
    """Stands in for the clipboard-history rebuild: records calls, never touches D-Bus."""

    def __init__(self) -> None:
        from veil.clip.history import Forget

        self.result = Forget.NOT_RUNNING
        self.calls = 0

    def __call__(self, original, put_back):
        self.calls += 1
        return self.result


@pytest.fixture(autouse=True)
def clip_history(monkeypatch):
    """No test may rebuild the owner's real clipboard history. Set `.result` to script it."""
    from veil.clip import history

    recorder = RecordingForgetter()
    monkeypatch.setattr(history, "detect", lambda *a, **k: recorder)
    return recorder


class RecordingTimers:
    """Stands in for the kill switch's systemd timers: records, never runs systemd-run."""

    def __init__(self) -> None:
        self.scheduled: list = []
        self.checks: list = []
        self.cancelled = 0
        self.ok = True

    def schedule(self, switch, now) -> bool:
        self.scheduled.append((switch, now))
        return self.ok

    def schedule_check(self, delay) -> bool:
        self.checks.append(delay)
        return self.ok

    def cancel(self) -> None:
        self.cancelled += 1


@pytest.fixture(autouse=True)
def switch_timers(monkeypatch):
    """No test may schedule a real systemd user timer (kill-switch notifications)."""
    from veil import killswitch

    recorder = RecordingTimers()
    monkeypatch.setattr(killswitch, "detect_timers", lambda *a, **k: recorder)
    return recorder


class ScriptedChooser:
    """Stands in for the kill-switch hotkey's confirmation notification. `reply` is the button
    "clicked" (default None: no answer, so veil stays ON); `asked` records each question."""

    def __init__(self) -> None:
        self.reply = None
        self.asked: list = []

    def __call__(self, message, actions, timeout):
        self.asked.append((message, list(actions), timeout))
        return self.reply


@pytest.fixture(autouse=True)
def switch_chooser(monkeypatch):
    """No test may pop up a real kill-switch confirmation."""
    from veil import killswitch

    scripted = ScriptedChooser()
    monkeypatch.setattr(killswitch, "detect_chooser", lambda *a, **k: scripted)
    return scripted


class FakeShortcutService:
    """KDE's global-shortcut service in memory (kglobalaccel semantics veil relies on)."""

    def __init__(self) -> None:
        self.is_running = True
        self.keys_by_component: dict[str, list[int]] = {}
        self.taken: dict[int, str] = {}  # key → another component that holds it
        self.registered: list[str] = []
        self.fail: set[str] = set()
        self.dropped: list[str] = []
        self.blocks: list[bool] = []
        self.closed = 0

    def _check(self, name):
        if name in self.fail:
            raise RuntimeError(name)

    def running(self) -> bool:
        self._check("running")
        return self.is_running

    def available(self, code, component) -> bool:
        self._check("available")
        holder = self.taken.get(code)
        return holder is None or holder == component

    def register(self, shortcut) -> None:
        self._check("register")
        self.registered.append(shortcut.component)

    def set_keys(self, shortcut, codes) -> None:
        self._check("set_keys")
        self.keys_by_component[shortcut.component] = list(codes)

    def keys(self, shortcut):
        self._check("keys")
        return self.keys_by_component.get(shortcut.component, [])

    def forget(self, shortcut) -> None:
        self._check("forget")
        self.keys_by_component.pop(shortcut.component, None)

    def drop_legacy(self, shortcut) -> None:
        self._check("drop_legacy")
        self.dropped.append(shortcut.component)

    def block(self, blocked) -> None:
        self._check("block")
        self.blocks.append(blocked)

    def close(self) -> None:
        self.closed += 1


@pytest.fixture(autouse=True)
def shortcut_service(monkeypatch):
    """No test may change the owner's real KDE shortcuts or run kbuildsycoca6."""
    from veil import shortcuts

    fake = FakeShortcutService()
    fake.rebuilds = 0

    def rebuild() -> bool:
        fake.rebuilds += 1
        return True

    monkeypatch.setattr(shortcuts, "JeepneyShortcuts", lambda *a, **k: fake)
    monkeypatch.setattr(shortcuts, "kbuildsycoca", lambda *a, **k: rebuild)
    return fake


class FakeKeyboard:
    """Stands in for the desktop portal's keyboard: records chords, never types anything.
    Set `.refuse` / `.fail` to script the portal; `.opened_with` records the restore tokens."""

    def __init__(self, *args, **kwargs) -> None:
        self.pressed: list = []
        self.opened_with: list = []
        self.closed = False
        self.refuse = self.fail = False
        self.timings: dict = {}

    def open(self, token=None):
        from veil.clip import portal

        self.opened_with.append(token)
        if self.refuse:
            raise portal.Refused("cancelled in the dialog")
        if self.fail:
            raise portal.PortalError("portal error x")
        return "restored-token"

    def press(self, keys) -> None:
        self.pressed.append(tuple(keys))

    def close(self) -> None:
        self.closed = True


class KeyboardRecorder:
    def __init__(self) -> None:
        self.keyboards: list = []
        self.refuse = self.fail = False

    def __call__(self, *args, **kwargs):
        keyboard = FakeKeyboard()
        keyboard.refuse, keyboard.fail = self.refuse, self.fail
        self.keyboards.append(keyboard)
        return keyboard

    @property
    def pressed(self) -> list:
        return [chord for k in self.keyboards for chord in k.pressed]


@pytest.fixture(autouse=True)
def portal_keyboard(monkeypatch):
    """No test may press keys through the real desktop portal (it types into the owner's
    windows). Returns the recorder: `.pressed` lists every chord "pressed"."""
    from veil.clip import paste, portal

    recorder = KeyboardRecorder()
    monkeypatch.setattr(portal, "RemoteKeyboard", recorder)
    monkeypatch.setattr(paste, "RELEASE_WAIT", 0.0)
    return recorder


@pytest.fixture(autouse=True)
def recent_writes(monkeypatch, tmp_path_factory):
    """The recent-writes list lives in a per-test folder, never the real runtime directory."""
    from veil.clip import recent

    folder = tmp_path_factory.mktemp("runtime")
    folder.chmod(0o700)
    monkeypatch.setattr(recent, "location", lambda: folder / recent.FILE)
    return folder / recent.FILE


class FakeWatcher:
    """Stands in for the veil-watch systemd service: never runs systemctl."""

    def __init__(self) -> None:
        self.running = False
        self.starts = self.stops = 0
        self.can_start = True

    def start(self) -> bool:
        self.starts += 1
        self.running = self.can_start
        return self.running

    def stop(self) -> None:
        self.stops += 1
        self.running = False

    def active(self) -> bool:
        return self.running


@pytest.fixture(autouse=True)
def copy_watcher(monkeypatch):
    """No test may start or stop the owner's real copy watcher service (veil ON / OFF)."""
    from veil import killswitch

    fake = FakeWatcher()
    monkeypatch.setattr(killswitch, "detect_watcher", lambda *a, **k: fake)
    return fake


@pytest.fixture
def hardening_calls(_no_process_hardening_in_test_process):
    """Records each call to `veil.hardening.apply` made during the test."""
    return _no_process_hardening_in_test_process


@dataclass(frozen=True)
class Completed:
    returncode: int
    stdout: str
    stderr: str


def run_python(code: str, *, timeout: float = 60) -> Completed:
    """Run a Python snippet in a fresh interpreter using the project's environment."""
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    return Completed(proc.returncode, proc.stdout, proc.stderr)


@pytest.fixture
def python_subprocess():
    return run_python


@pytest.fixture
def fast_scrypt(monkeypatch):
    """Replace age scrypt (~1.5 s per call) with a fast stand-in that keeps the same contract."""

    from veil.crypto import age
    from veil.errors import DecryptFailed

    def tag(passphrase: str) -> bytes:
        return hashlib.sha256(passphrase.encode()).digest()

    def encrypt(plaintext: bytes, passphrase: str) -> bytes:
        age.check_passphrase(passphrase)
        return (
            age.AGE_MAGIC + b"FAKE-SCRYPT " + tag(passphrase) + bytes(b ^ 0x5A for b in plaintext)
        )

    def decrypt(ciphertext: bytes, passphrase: str) -> bytes:
        prefix = age.AGE_MAGIC + b"FAKE-SCRYPT "
        if not ciphertext.startswith(prefix) or ciphertext[len(prefix) : len(prefix) + 32] != tag(
            passphrase
        ):
            raise DecryptFailed(
                "could not decrypt the key file: wrong passphrase, or it is corrupt"
            )
        return bytes(b ^ 0x5A for b in ciphertext[len(prefix) + 32 :])

    monkeypatch.setattr(age, "passphrase_encrypt", encrypt)
    monkeypatch.setattr(age, "passphrase_decrypt", decrypt)


@dataclass
class VeilHome:
    ring: object
    config: object  # pathlib.Path of <XDG_CONFIG_HOME>/veil
    tmp: object


@pytest.fixture
def veil_home(tmp_path, monkeypatch, fast_scrypt):
    """A throwaway config dir + in-memory keyring wired in where the CLI looks for them."""
    from tests.helpers.memkeyring import MemoryKeyring
    from veil.crypto import keystore

    ring = MemoryKeyring()
    monkeypatch.setattr(keystore, "secret_service_backend", lambda: ring)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg-data"))
    return VeilHome(ring=ring, config=tmp_path / "xdg-config" / "veil", tmp=tmp_path)
