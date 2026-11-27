"""Value-free handling of failures before/during argument parsing (#38, ADR-0027).

Every "secret" here comes from the synthetic persona (Jane Doe → Alex Smith) and is never
echoed. The redacting hook is tested with real subprocesses, not by printing a traceback.
"""

import sys
import threading

import pytest

from veil import cli, hardening
from veil.exitcodes import ExitCode

SECRET = "Jane Doe"  # synthetic persona value, never a real detail
DIGITS = "9876543210"  # synthetic phone number
INDIC = "जANE दो"  # mixed-script text must never be echoed (RUF001 ignored in tests)
TEMPLATE = "veil: internal error (RuntimeError); details withheld to protect personal data\n"


@pytest.fixture(autouse=True)
def _hooks_never_leak(monkeypatch):
    """Isolation lives in the tests: main installs hooks for the whole process lifetime.

    Other modules may have installed them already; snapshot and restore whatever is current.
    """
    monkeypatch.setattr(sys, "excepthook", sys.excepthook)
    monkeypatch.setattr(threading, "excepthook", threading.excepthook)
    monkeypatch.setattr(sys, "unraisablehook", sys.unraisablehook)


def test_hooks_installed_before_hardening_and_parsing(monkeypatch):
    order: list[str] = []
    real_install = hardening.install_exception_hooks

    def install():
        order.append("hooks")
        real_install()

    def apply():
        order.append("hardening")
        return hardening.HardeningReport(True, True, True)

    monkeypatch.setattr(hardening, "install_exception_hooks", install)
    monkeypatch.setattr(hardening, "apply", apply)
    assert cli.main([]) == ExitCode.OK
    assert order == ["hooks", "hardening"]
    assert cli.build_parser is not None  # the real parser was still built after both


def test_parser_construction_error_is_value_free(monkeypatch, capsys):
    def broken_parser():
        raise RuntimeError(f"building parser for {SECRET} {DIGITS}")

    monkeypatch.setattr(cli, "build_parser", broken_parser)
    assert cli.main([]) == ExitCode.INTERNAL
    out = capsys.readouterr()
    assert out.err == TEMPLATE
    assert out.out == ""
    assert "Traceback" not in out.err
    assert SECRET not in out.err + out.out
    assert DIGITS not in out.err + out.out


def test_lazy_import_error_is_value_free(monkeypatch, capsys):
    # _persona_check starts with the lazy import; stubbing it keeps the real store untouched.
    def broken_import(_args):
        raise OSError(f"cannot import {SECRET} {DIGITS}")

    monkeypatch.setattr(cli, "_persona_check", broken_import)
    assert cli.main(["persona", "check"]) == ExitCode.INTERNAL
    err = capsys.readouterr().err
    assert "internal error (OSError)" in err
    assert SECRET not in err
    assert DIGITS not in err
    assert "Traceback" not in err


@pytest.mark.parametrize(
    "argv",
    [
        [f"--{SECRET.replace(' ', '-')}-flag"],
        ["persona", "check", "--format", SECRET],
        ["status", SECRET, "extra"],
    ],
)
def test_argument_parsing_never_echoes_values(argv, capsys):
    with pytest.raises(SystemExit) as caught:
        cli.main(argv)
    assert caught.value.code == ExitCode.USAGE
    text = "".join(capsys.readouterr())
    assert SECRET not in text
    assert "error:" in text


def test_help_and_normal_command_still_work(capsys):
    assert cli.main([]) == ExitCode.OK
    with pytest.raises(SystemExit) as caught:
        cli.main(["--help"])
    assert caught.value.code == ExitCode.OK
    out = capsys.readouterr().out
    assert "usage: veil" in out
    assert SECRET not in out


def test_repeated_main_keeps_the_same_redacting_hooks(monkeypatch):
    calls: list[int] = []
    real_install = hardening.install_exception_hooks

    def counted():
        calls.append(1)
        real_install()

    monkeypatch.setattr(hardening, "install_exception_hooks", counted)
    assert cli.main([]) == ExitCode.OK
    after_first = (sys.excepthook, threading.excepthook, sys.unraisablehook)
    assert cli.main([]) == ExitCode.OK
    assert len(calls) == 2
    # Same function objects twice: no wrapper chain, and no fallback to Python's defaults.
    assert (sys.excepthook, threading.excepthook, sys.unraisablehook) == after_first
    assert sys.excepthook is hardening._redacting_excepthook
    assert threading.excepthook is hardening._redacting_thread_excepthook
    assert sys.unraisablehook is hardening._redacting_unraisablehook


def test_unraisable_error_after_main_is_redacted(python_subprocess):
    """A finalizer error once main() has returned must not print the default repr or message."""
    code = (
        "import gc\n"
        "from veil import cli\n"
        "cli.main([])\n"
        "class Leaky:\n"
        "    def __del__(self):\n"
        f"        raise RuntimeError({SECRET!r})\n"
        "leaky = Leaky()\n"
        "del leaky\n"
        "gc.collect()\n"
    )
    result = python_subprocess(code)
    assert result.returncode == ExitCode.OK
    assert "internal error (RuntimeError)" in result.stderr
    assert SECRET not in result.stderr + result.stdout
    assert "Traceback" not in result.stderr


def test_failure_before_the_try_block_is_redacted(python_subprocess):
    """A failing hardening step happens before `main`'s try block: the hook must already be up."""
    code = (
        "from veil import cli, hardening\n"
        "def boom():\n"
        f"    raise RuntimeError({SECRET!r})\n"
        "hardening.apply = boom\n"
        "cli.main([])\n"
    )
    result = python_subprocess(code)
    assert result.returncode == ExitCode.INTERNAL
    assert result.stderr == TEMPLATE
    assert result.stdout == ""
    assert SECRET not in result.stderr
    assert "Traceback" not in result.stderr


def test_python_module_entry_installs_hook_before_cli_import(python_subprocess):
    """`python -m veil` must redact a failure while importing cli, before `main` can run."""
    code = (
        "import runpy\n"
        "import sys\n"
        "class BlockCli:\n"
        "    def find_spec(self, fullname, path=None, target=None):\n"
        f"        if fullname == 'veil.cli':\n            raise RuntimeError({SECRET!r})\n"
        "sys.meta_path.insert(0, BlockCli())\n"
        "runpy.run_module('veil', run_name='__main__')\n"
    )
    result = python_subprocess(code)
    assert result.returncode == ExitCode.INTERNAL
    assert result.stderr == TEMPLATE
    assert SECRET not in result.stderr
    assert "Traceback" not in result.stderr


def test_unicode_and_indic_message_is_never_echoed(python_subprocess):
    code = (
        "from veil import cli, hardening\n"
        "def boom():\n"
        f"    raise RuntimeError({INDIC!r} + ' ' + {SECRET!r})\n"
        "hardening.apply = boom\n"
        "cli.main([])\n"
    )
    result = python_subprocess(code)
    assert result.returncode == ExitCode.INTERNAL
    assert result.stderr == TEMPLATE
    assert INDIC not in result.stderr + result.stdout
    assert SECRET not in result.stderr + result.stdout
