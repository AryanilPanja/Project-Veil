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
def _no_real_keyring(monkeypatch):
    """No test may reach the owner's real KDE Wallet / Secret Service."""
    from veil.crypto import keystore

    def forbidden():
        raise AssertionError("a test tried to use the real Secret Service keyring")

    monkeypatch.setattr(keystore, "secret_service_backend", forbidden)


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
