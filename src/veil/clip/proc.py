"""Running the clipboard tools (wl-paste, wl-copy, xsel) with hard limits.

- `capture`: run a tool and collect its stdout, at most `limit` bytes, within `timeout` seconds.
  A tool whose clipboard source never answers is killed, not waited on forever.
- `feed`: run a tool with data on stdin. Clipboard text goes through stdin only, never argv
  (argv is world-readable in /proc). stdout/stderr go to /dev/null: wl-copy and xsel fork a
  child that serves the clipboard and inherits those descriptors, so a pipe there would never
  reach EOF.

Errors are ClipboardError with value-free messages; the tool's own stderr is never shown.
"""

import os
import selectors
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass

from veil.errors import ClipboardError

STDERR_LIMIT = 4096


@dataclass(frozen=True)
class Captured:
    returncode: int
    stdout: bytes
    stderr: bytes  # bounded; for classifying a failure, never printed

    def __repr__(self) -> str:
        return f"Captured(returncode={self.returncode}, stdout=<{len(self.stdout)} bytes>)"


def capture(argv: Sequence[str], *, timeout: float, limit: int) -> Captured:
    """Run argv; return its exit status and output. Over `limit` bytes or `timeout` → error."""
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv is a fixed tool path plus fixed flags
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
    except OSError:
        raise ClipboardError("cannot start the clipboard tool") from None
    stdout, stderr = proc.stdout, proc.stderr  # both PIPE, so never None
    out, err = bytearray(), bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(stdout, selectors.EVENT_READ, out)
            selector.register(stderr, selectors.EVENT_READ, err)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ClipboardError("the clipboard tool timed out")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    key.data.extend(chunk)
                    if len(out) > limit:
                        raise ClipboardError(f"the clipboard text is larger than {limit} bytes")
                    del err[STDERR_LIMIT:]
        remaining = max(deadline - time.monotonic(), 0)
        try:
            returncode = proc.wait(remaining)
        except subprocess.TimeoutExpired:
            raise ClipboardError("the clipboard tool timed out") from None
    except BaseException:
        _kill(proc)
        raise
    finally:
        stdout.close()  # type: ignore[union-attr]
        stderr.close()  # type: ignore[union-attr]
    return Captured(returncode, bytes(out), bytes(err))


def feed(argv: Sequence[str], data: bytes, *, timeout: float) -> int:
    """Run argv with `data` on stdin; return its exit status (output discarded)."""
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv is a fixed tool path plus fixed flags
            list(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except OSError:
        raise ClipboardError("cannot start the clipboard tool") from None
    try:
        proc.communicate(data, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(proc)
        raise ClipboardError("the clipboard tool timed out") from None
    except BaseException:
        _kill(proc)
        raise
    return proc.returncode


def _kill(proc: subprocess.Popen) -> None:
    try:
        proc.kill()
        proc.wait(2)
    except (OSError, subprocess.TimeoutExpired):
        pass
