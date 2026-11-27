"""Running the clipboard tools (M2.1): limits, timeouts, forking writers. Real subprocesses."""

import sys
import time

import pytest

from veil.clip import proc
from veil.errors import ClipboardError

PY = sys.executable


def py(code: str) -> list[str]:
    return [PY, "-c", code]


class TestCapture:
    def test_stdout_and_status(self):
        got = proc.capture(
            py("import sys; sys.stdout.write('a\\nb'); sys.exit(3)"), timeout=10, limit=100
        )
        assert (got.returncode, got.stdout) == (3, b"a\nb")

    def test_stderr_is_collected_but_bounded(self):
        got = proc.capture(
            py(f"import sys; sys.stderr.write('e' * {proc.STDERR_LIMIT * 3})"), timeout=10, limit=10
        )
        assert got.returncode == 0
        assert 0 < len(got.stderr) <= proc.STDERR_LIMIT

    def test_binary_and_utf8_bytes_exact(self):
        data = "জেন\x00\r\n".encode() + b"\xff"
        got = proc.capture(
            py(f"import sys; sys.stdout.buffer.write({data!r})"), timeout=10, limit=100
        )
        assert got.stdout == data

    def test_large_output_within_limit(self):
        n = 3 * 1024 * 1024
        got = proc.capture(
            py(f"import sys; sys.stdout.buffer.write(b'x' * {n})"), timeout=30, limit=n
        )
        assert len(got.stdout) == n

    def test_over_limit_kills_and_raises(self):
        start = time.monotonic()
        with pytest.raises(ClipboardError, match="larger than 1000 bytes"):
            proc.capture(
                py("import sys\nwhile True: sys.stdout.write('x' * 4096); sys.stdout.flush()"),
                timeout=20,
                limit=1000,
            )
        assert time.monotonic() - start < 10

    def test_hanging_tool_times_out(self):
        start = time.monotonic()
        with pytest.raises(ClipboardError, match="timed out"):
            proc.capture(py("import time; time.sleep(30)"), timeout=0.5, limit=100)
        assert time.monotonic() - start < 5

    def test_tool_that_closes_stdout_then_hangs_times_out(self):
        code = "import os, time; os.close(1); os.close(2); time.sleep(30)"
        with pytest.raises(ClipboardError, match="timed out"):
            proc.capture(py(code), timeout=0.5, limit=100)

    def test_missing_tool(self, tmp_path):
        with pytest.raises(ClipboardError, match="cannot start"):
            proc.capture([str(tmp_path / "no-such-tool")], timeout=1, limit=10)

    def test_repr_hides_output(self):
        got = proc.capture(py("print('Jane Doe')"), timeout=10, limit=100)
        assert "Jane" not in repr(got)


class TestFeed:
    def test_data_arrives_on_stdin(self, tmp_path):
        out = tmp_path / "got"
        code = (
            f"import sys, pathlib; pathlib.Path({str(out)!r}).write_bytes(sys.stdin.buffer.read())"
        )
        data = "Jane Doe\nজেন\n".encode()
        assert proc.feed(py(code), data, timeout=10) == 0
        assert out.read_bytes() == data

    def test_exit_status(self):
        assert proc.feed(py("import sys; sys.stdin.read(); sys.exit(4)"), b"x", timeout=10) == 4

    def test_tool_that_ignores_stdin(self):
        assert proc.feed(py("pass"), b"x" * 1_000_000, timeout=10) == 0

    def test_forking_writer_does_not_block(self, tmp_path):
        # Like wl-copy/xsel: read stdin, fork a child that keeps serving (and keeps the
        # inherited stdout/stderr open), parent exits at once.
        flag = tmp_path / "child-alive"
        code = (
            "import os, sys, time, pathlib\n"
            "sys.stdin.buffer.read()\n"
            "if os.fork() == 0:\n"
            f"    pathlib.Path({str(flag)!r}).touch(); time.sleep(5); os._exit(0)\n"
        )
        start = time.monotonic()
        assert proc.feed(py(code), b"Alex Smith", timeout=10) == 0
        assert time.monotonic() - start < 4

    def test_hanging_writer_times_out(self):
        start = time.monotonic()
        with pytest.raises(ClipboardError, match="timed out"):
            proc.feed(py("import time; time.sleep(30)"), b"", timeout=0.5)
        assert time.monotonic() - start < 5

    def test_missing_tool(self, tmp_path):
        with pytest.raises(ClipboardError, match="cannot start"):
            proc.feed([str(tmp_path / "nope")], b"", timeout=1)

    def test_data_never_in_argv(self, tmp_path):
        out = tmp_path / "argv"
        code = f"import sys, pathlib; sys.stdin.read(); pathlib.Path({str(out)!r}).write_text(repr(sys.argv))"
        proc.feed(py(code), b"Jane Doe", timeout=10)
        assert "Jane" not in out.read_text()
