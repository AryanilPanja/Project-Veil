"""How `veil.cli.main` maps failures to exit codes and value-free messages (ADR-0027)."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.conftest import run_python
from veil import cli, hardening
from veil.errors import (
    Aborted,
    Busy,
    DecryptFailed,
    KeyUnavailable,
    UnsafeEnvironment,
    ValidationFailed,
    VeilError,
)
from veil.exitcodes import ExitCode

SECRET = "Jane Doe 9876543210"


def _raise(exc: BaseException):
    def runner(_argv):
        raise exc

    return runner


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (ValidationFailed("3 errors in persona"), ExitCode.FINDINGS),
        (KeyUnavailable("keyring is locked"), ExitCode.KEY_UNAVAILABLE),
        (DecryptFailed("persona store could not be decrypted"), ExitCode.DECRYPT_FAILED),
        (Busy("persona store is locked"), ExitCode.BUSY),
        (UnsafeEnvironment("needs a terminal"), ExitCode.UNSAFE_ENVIRONMENT),
        (Aborted("cancelled"), ExitCode.ABORTED),
        (VeilError("generic"), ExitCode.INTERNAL),
    ],
)
def test_veil_errors_map_to_their_exit_code(monkeypatch, capsys, error, code):
    monkeypatch.setattr(cli, "run", _raise(error))
    assert cli.main([]) == code
    captured = capsys.readouterr()
    assert captured.err == f"veil: {error.safe_message}\n"
    assert captured.out == ""


def test_chained_cause_never_printed(monkeypatch, capsys):
    def runner(_argv):
        try:
            raise ValueError(SECRET)
        except ValueError as exc:
            raise DecryptFailed("persona store could not be decrypted") from exc

    monkeypatch.setattr(cli, "run", runner)
    assert cli.main([]) == ExitCode.DECRYPT_FAILED
    assert "Jane" not in capsys.readouterr().err


@pytest.mark.parametrize("exc_type", [RuntimeError, ValueError, KeyError, OSError, TypeError])
def test_unexpected_exceptions_exit_70_without_message(monkeypatch, capsys, exc_type):
    monkeypatch.setattr(cli, "run", _raise(exc_type(SECRET)))
    assert cli.main([]) == ExitCode.INTERNAL
    err = capsys.readouterr().err
    assert exc_type.__name__ in err
    assert "Jane" not in err
    assert "9876543210" not in err


def test_keyboard_interrupt_exits_130(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run", _raise(KeyboardInterrupt()))
    assert cli.main([]) == ExitCode.INTERRUPTED
    assert "interrupted" in capsys.readouterr().err


def test_system_exit_from_argparse_passes_through(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--no-such-flag"])
    assert exc.value.code == ExitCode.USAGE


def test_main_applies_hardening_once(hardening_calls):
    cli.main([])
    assert hardening_calls == ["apply"]


def test_success_returns_ok(capsys):
    assert cli.main([]) == ExitCode.OK
    assert "hardening incomplete" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "report",
    [
        hardening.HardeningReport(True, True, False),
        hardening.HardeningReport(True, False, True),
        hardening.HardeningReport(False, False, False),
    ],
)
def test_incomplete_hardening_is_never_silent(monkeypatch, capsys, report):
    monkeypatch.setattr(hardening, "apply", lambda: report)
    assert cli.main([]) == ExitCode.OK
    err = capsys.readouterr().err
    assert "warning: process hardening incomplete" in err
    assert f"non_dumpable={report.non_dumpable}" in err


@given(secret=st.text(min_size=6, max_size=60).filter(lambda s: s.strip()))
def test_no_exception_text_ever_reaches_the_terminal(secret):
    """Property: whatever an unexpected exception says, none of it is printed."""
    import io
    import sys

    template = "veil: internal error (RuntimeError); details withheld to protect personal data\n"
    if secret in template:
        return
    stderr, real = io.StringIO(), sys.stderr
    original_run = cli.run
    sys.stderr = stderr
    cli.run = _raise(RuntimeError(secret))
    try:
        assert cli.main([]) == ExitCode.INTERNAL
    finally:
        sys.stderr = real
        cli.run = original_run
    assert stderr.getvalue() == template


def test_end_to_end_subprocess_exit_codes():
    """The real entry point, with real hardening, in a fresh interpreter."""
    code = (
        "import sys\nfrom veil import cli\nfrom veil.errors import Busy\n"
        "def run(argv):\n    raise Busy('persona store is locked')\n"
        "cli.run = run\nsys.exit(cli.main([]))"
    )
    result = run_python(code)
    assert result.returncode == ExitCode.BUSY
    assert result.stderr == "veil: persona store is locked\n"
