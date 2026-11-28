"""Process hardening applied at the start of every `veil` command (ADR-0025).

- umask 077: every file veil creates is private to the user.
- No core dumps (RLIMIT_CORE=0) and not dumpable: plaintext in memory is not written to a core
  file, and same-uid processes cannot attach a debugger. Linux: PR_SET_DUMPABLE=0 (also closes
  /proc/<pid>/mem). macOS: ptrace(PT_DENY_ATTACH); task_for_pid already needs root or the
  debugger entitlement there, so this closes the remaining same-uid lldb/dtrace attach.
- Redacting exception hooks: an unexpected crash prints the exception class only, never the
  message or traceback (both can contain persona values), and exits with code 70.
"""

from __future__ import annotations  # sys.UnraisableHookArgs exists only for type checkers

import contextlib
import ctypes
import functools
import os
import resource
import sys
import threading
from dataclasses import dataclass
from types import TracebackType

from veil import ui
from veil.exitcodes import ExitCode

_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_PT_DENY_ATTACH = 31  # <sys/ptrace.h> on macOS

_deny_attach_applied = False


@dataclass(frozen=True)
class HardeningReport:
    umask_set: bool
    core_dumps_disabled: bool
    non_dumpable: bool

    @property
    def complete(self) -> bool:
        return self.umask_set and self.core_dumps_disabled and self.non_dumpable


def apply() -> HardeningReport:
    report = HardeningReport(
        umask_set=_set_umask(),
        core_dumps_disabled=_disable_core_dumps(),
        non_dumpable=_set_non_dumpable(),
    )
    install_exception_hooks()
    return report


def install_exception_hooks() -> None:
    sys.excepthook = _redacting_excepthook
    threading.excepthook = _redacting_thread_excepthook
    sys.unraisablehook = _redacting_unraisablehook


def is_dumpable() -> bool | None:
    """Whether a same-uid debugger could attach: PR_GET_DUMPABLE on Linux, our own
    PT_DENY_ATTACH record on macOS (the kernel has no getter); None when unavailable."""
    if sys.platform == "darwin":
        if _deny_attach_applied:
            return False
        return None if _darwin_libc() is None else True
    libc = _libc()
    if libc is None:
        return None
    return bool(libc.prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0))


def _set_umask() -> bool:
    os.umask(0o077)
    return True


def _disable_core_dumps() -> bool:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        return False
    return resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)


def _set_non_dumpable() -> bool:
    if sys.platform == "darwin":
        return _deny_attach()
    libc = _libc()
    if libc is None:
        return False
    if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        return False
    return is_dumpable() is False


def _deny_attach() -> bool:
    global _deny_attach_applied  # process-wide, set once
    libc = _darwin_libc()
    if libc is None:
        return False
    if libc.ptrace(_PT_DENY_ATTACH, 0, None, 0) != 0:
        return False
    _deny_attach_applied = True
    return True


@functools.cache
def _darwin_libc() -> ctypes.CDLL | None:
    """libSystem (already loaded) for ptrace, or None. Same CDLL(None) trick as _libc()."""
    if sys.platform != "darwin":
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None
    if not hasattr(libc, "ptrace"):
        return None
    libc.ptrace.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
    libc.ptrace.restype = ctypes.c_int
    return libc


@functools.cache
def _libc() -> ctypes.CDLL | None:
    """The C library already loaded into this process (for prctl), or None.

    `CDLL(None)` opens the process's own symbol table, which on Linux includes glibc. That avoids
    `ctypes.util.find_library`, which costs ~10 ms (it may spawn ldconfig) plus ~35 ms to import,
    on every veil start.
    """
    if not sys.platform.startswith("linux"):
        return None
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        return None
    return libc if hasattr(libc, "prctl") else None


def _redacting_excepthook(
    exc_type: type[BaseException],
    _exc: BaseException,
    _tb: TracebackType | None,
) -> None:
    if issubclass(exc_type, KeyboardInterrupt):
        ui.err("veil: interrupted")
        code = ExitCode.INTERRUPTED
    else:
        ui.report_internal_error(exc_type)
        code = ExitCode.INTERNAL
    _flush_streams()
    os._exit(int(code))


def _redacting_thread_excepthook(args: threading.ExceptHookArgs) -> None:
    # Fail closed (ADR-0022): a dead worker could leave half-translated output behind, so the
    # whole process stops. SystemExit in a thread is a normal thread exit, as in the default hook.
    if issubclass(args.exc_type, SystemExit):
        return
    ui.report_internal_error(args.exc_type)
    _flush_streams()
    os._exit(int(ExitCode.INTERNAL))


def _redacting_unraisablehook(unraisable: sys.UnraisableHookArgs) -> None:
    # Errors in __del__, GC callbacks and generator finalisers. The default hook prints repr(obj)
    # and the exception message, either of which can hold persona values. Report the class only;
    # these do not stop the process (they happen during cleanup).
    ui.report_internal_error(unraisable.exc_type)


def _flush_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(OSError, ValueError):
            stream.flush()
