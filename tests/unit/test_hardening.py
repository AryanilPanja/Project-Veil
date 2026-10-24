"""Hardening is tested in fresh subprocesses so the pytest process itself is never hardened."""

import json
import sys

import pytest

from tests.conftest import run_python
from veil import hardening
from veil.exitcodes import ExitCode

linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="prctl is Linux-only")

# A synthetic secret standing in for persona data that might end up in an exception message.
SECRET = "Jane Doe 9876543210 jane.doe@example.test"

APPLY_AND_REPORT = """
import json, os, resource
from veil import hardening
report = hardening.apply()
mask = os.umask(0); os.umask(mask)
print(json.dumps({
    "report": [report.umask_set, report.core_dumps_disabled, report.non_dumpable],
    "complete": report.complete,
    "umask": mask,
    "core": list(resource.getrlimit(resource.RLIMIT_CORE)),
    "dumpable": hardening.is_dumpable(),
}))
"""


@pytest.fixture(scope="module")
def applied():
    result = run_python(APPLY_AND_REPORT)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_umask_is_077(applied):
    assert applied["umask"] == 0o077


def test_core_dumps_disabled(applied):
    assert applied["core"] == [0, 0]


@linux_only
def test_process_is_not_dumpable(applied):
    assert applied["dumpable"] is False


@linux_only
def test_report_is_complete(applied):
    assert applied["report"] == [True, True, True]
    assert applied["complete"] is True


def test_files_created_after_hardening_are_private(tmp_path):
    target = tmp_path / "created.txt"
    result = run_python(
        "import os; from veil import hardening; hardening.apply();"
        f"open({str(target)!r}, 'w').close(); print(oct(os.stat({str(target)!r}).st_mode & 0o777))"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "0o600"


@pytest.mark.parametrize(
    "raise_stmt",
    [
        f"raise RuntimeError({SECRET!r})",
        f"raise ValueError({SECRET!r})",
        f"raise KeyError({SECRET!r})",
        # The secret only in a chained cause must not appear either.
        (
            f"try:\n    raise ValueError({SECRET!r})\n"
            "except ValueError as e:\n    raise RuntimeError('wrap') from e"
        ),
        # An exception whose __str__ itself leaks.
        (
            "class Leaky(Exception):\n    def __str__(self):\n"
            f"        return {SECRET!r}\nraise Leaky()"
        ),
    ],
)
def test_uncaught_exception_shows_class_only_and_exits_70(raise_stmt):
    result = run_python("from veil import hardening\nhardening.apply()\n" + raise_stmt)
    assert result.returncode == ExitCode.INTERNAL
    assert "internal error" in result.stderr
    assert "Traceback" not in result.stderr
    for fragment in ("Jane", "9876543210", "example.test"):
        assert fragment not in result.stderr
        assert fragment not in result.stdout


def test_uncaught_exception_names_the_class():
    result = run_python("from veil import hardening\nhardening.apply()\nraise LookupError('x')")
    assert "LookupError" in result.stderr


def test_keyboard_interrupt_exits_130():
    result = run_python("from veil import hardening\nhardening.apply()\nraise KeyboardInterrupt")
    assert result.returncode == ExitCode.INTERRUPTED
    assert "interrupted" in result.stderr
    assert "Traceback" not in result.stderr


def test_pending_stdout_is_flushed_before_exit():
    result = run_python(
        "import sys\nfrom veil import hardening\nhardening.apply()\n"
        "sys.stdout.write('partial output')\nraise RuntimeError('x')"
    )
    assert result.stdout == "partial output"


def test_thread_exception_is_redacted_and_process_continues():
    code = (
        "import threading\nfrom veil import hardening\nhardening.apply()\n"
        f"def boom():\n    raise ValueError({SECRET!r})\n"
        "t = threading.Thread(target=boom); t.start(); t.join()\nprint('main continued')"
    )
    result = run_python(code)
    assert result.returncode == 0
    assert "main continued" in result.stdout
    assert "ValueError" in result.stderr
    assert "Jane" not in result.stderr


def test_without_hardening_python_would_leak():
    """Sanity check of the test itself: the default hook does print the secret."""
    result = run_python(f"raise RuntimeError({SECRET!r})")
    assert "Jane" in result.stderr


# ── failure paths, tested in-process on the private helpers ──


def test_non_linux_platform_has_no_libc(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert hardening._libc() is None
    assert hardening._set_non_dumpable() is False
    assert hardening.is_dumpable() is None


def test_libc_load_failure_is_tolerated(monkeypatch):
    def fail(*_a, **_k):
        raise OSError("no libc")

    monkeypatch.setattr(hardening.ctypes, "CDLL", fail)
    assert hardening._libc() is None
    assert hardening._set_non_dumpable() is False


def test_prctl_failure_is_reported(monkeypatch):
    class FailingLibc:
        def prctl(self, *_args):
            return -1

    monkeypatch.setattr(hardening, "_libc", FailingLibc)
    assert hardening._set_non_dumpable() is False


def test_setrlimit_failure_is_reported(monkeypatch):
    def fail(*_a):
        raise ValueError("not allowed")

    monkeypatch.setattr(hardening.resource, "setrlimit", fail)
    assert hardening._disable_core_dumps() is False


def test_report_complete_requires_all_three():
    assert hardening.HardeningReport(True, True, True).complete
    assert not hardening.HardeningReport(True, True, False).complete
    assert not hardening.HardeningReport(True, False, True).complete
    assert not hardening.HardeningReport(False, True, True).complete


def test_flush_streams_tolerates_closed_streams(monkeypatch):
    class Broken:
        def flush(self):
            raise ValueError("closed")

    monkeypatch.setattr(sys, "stdout", Broken())
    monkeypatch.setattr(sys, "stderr", Broken())
    hardening._flush_streams()  # must not raise
