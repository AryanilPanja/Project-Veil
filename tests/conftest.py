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
