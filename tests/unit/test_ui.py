import io
import sys

import pytest

from veil import ui
from veil.errors import Busy, UnsafeEnvironment, VeilError
from veil.exitcodes import ExitCode


class FakeStream(io.StringIO):
    def __init__(self, text: str = "", *, tty: bool) -> None:
        super().__init__(text)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


@pytest.fixture
def interactive(monkeypatch):
    """Simulate a terminal; call it with what the user types.

    The streams must be swapped inside the test body: pytest's output capture resets
    sys.stdout between the setup and call phases, undoing any swap made in a fixture.
    """

    def _type(text: str = "") -> None:
        monkeypatch.setattr("sys.stdin", FakeStream(text, tty=True))
        monkeypatch.setattr("sys.stdout", FakeStream(tty=True))

    return _type


def test_out_writes_to_stdout(capsys):
    ui.out("hello")
    captured = capsys.readouterr()
    assert captured.out == "hello\n"
    assert captured.err == ""


def test_err_writes_to_stderr(capsys):
    ui.err("oops")
    captured = capsys.readouterr()
    assert captured.err == "oops\n"
    assert captured.out == ""


def test_report_error_prefixes_and_uses_safe_message(capsys):
    ui.report_error(Busy("persona store is locked by another veil process"))
    assert capsys.readouterr().err == "veil: persona store is locked by another veil process\n"


def test_report_internal_error_shows_class_name_only(capsys):
    ui.report_internal_error(KeyError)
    err = capsys.readouterr().err
    assert "KeyError" in err
    assert "withheld" in err


def test_require_tty_passes_on_a_terminal(interactive):
    interactive()
    ui.require_tty("veil persona edit")  # no exception


@pytest.mark.parametrize(
    ("stdin_tty", "stdout_tty"), [(False, True), (True, False), (False, False)]
)
def test_require_tty_refuses_without_full_terminal(monkeypatch, stdin_tty, stdout_tty):
    monkeypatch.setattr("sys.stdin", FakeStream(tty=stdin_tty))
    monkeypatch.setattr("sys.stdout", FakeStream(tty=stdout_tty))
    with pytest.raises(UnsafeEnvironment, match="human-only"):
        ui.require_tty("veil persona edit")


def test_require_tty_message_names_the_command(monkeypatch):
    monkeypatch.setattr("sys.stdin", FakeStream(tty=False))
    with pytest.raises(UnsafeEnvironment, match="'veil off'"):
        ui.require_tty("veil off")


@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        ("shred\n", True),
        ("  shred  \n", True),
        ("shred", True),
        ("SHRED\n", False),
        ("shredd\n", False),
        ("yes\n", False),
        ("\n", False),
        ("", False),  # EOF
    ],
)
def test_confirm_typed(interactive, typed, expected):
    interactive(typed)
    assert ui.confirm_typed("Delete the plaintext file?", "shred") is expected


def test_confirm_typed_prompts_on_stderr_not_stdout(interactive, monkeypatch):
    stderr = io.StringIO()
    monkeypatch.setattr("sys.stderr", stderr)
    interactive("off\n")
    assert ui.confirm_typed("Switch veil off?", "off") is True
    assert "Type 'off' to confirm" in stderr.getvalue()
    assert sys.stdout.getvalue() == ""


def test_confirm_typed_refuses_without_terminal(monkeypatch):
    monkeypatch.setattr("sys.stdin", FakeStream("off\n", tty=False))
    monkeypatch.setattr("sys.stdout", FakeStream(tty=True))
    with pytest.raises(UnsafeEnvironment):
        ui.confirm_typed("Switch veil off?", "off")


def test_isatty_handles_streams_without_isatty():
    assert ui._isatty(object()) is False


def test_isatty_handles_closed_streams():
    class Closed:
        def isatty(self):
            raise ValueError("I/O operation on closed file")

    assert ui._isatty(Closed()) is False


# ── secret prompts ────────────────────────────────────────────────────────────


@pytest.fixture
def getpass_answers(monkeypatch):
    calls: list[tuple[str, object]] = []
    answers: list[object] = []

    def fake(prompt, stream=None):
        calls.append((prompt, stream))
        answer = answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr(ui.getpass, "getpass", fake)
    return calls, answers


def test_prompt_secret_reads_without_echo_on_stderr(interactive, getpass_answers):
    interactive()
    calls, answers = getpass_answers
    answers.append("s3cret phrase")
    assert ui.prompt_secret("Passphrase") == "s3cret phrase"
    assert calls == [("Passphrase: ", sys.stderr)]


def test_prompt_secret_refuses_without_terminal(monkeypatch, getpass_answers):
    monkeypatch.setattr("sys.stdin", FakeStream("piped secret\n", tty=False))
    with pytest.raises(UnsafeEnvironment):
        ui.prompt_secret("Passphrase")
    assert getpass_answers[0] == []


def test_prompt_secret_eof_is_empty(interactive, getpass_answers):
    interactive()
    getpass_answers[1].append(EOFError())
    assert ui.prompt_secret("Passphrase") == ""


def test_new_secret_asks_twice(interactive, getpass_answers):
    interactive()
    calls, answers = getpass_answers
    answers.extend(["पासवर्ड सुरक्षित", "पासवर्ड सुरक्षित"])
    assert ui.new_secret("New passphrase") == "पासवर्ड सुरक्षित"
    assert [c[0] for c in calls] == ["New passphrase: ", "New passphrase (again): "]


def test_new_secret_mismatch_is_usage_error_without_echo(interactive, getpass_answers):
    interactive()
    getpass_answers[1].extend(["first phrase", "second phrase"])
    with pytest.raises(VeilError) as info:
        ui.new_secret("New passphrase")
    assert info.value.exit_code == ExitCode.USAGE
    assert "first" not in str(info.value)
    assert "second" not in str(info.value)
