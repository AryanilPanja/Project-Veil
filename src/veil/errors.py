"""Exception hierarchy for expected failures (ADR-0027).

Every message is a fixed template filled with field paths, codes and counts only. Never pass a
persona value, a file's contents or another exception's message into a VeilError. When wrapping a
lower-level exception, chain it (`raise KeyUnavailable(...) from exc`): the cause is never printed.
"""

from veil.exitcodes import ExitCode


class VeilError(Exception):
    """Base class: carries a value-free message and the exit code to return."""

    exit_code: ExitCode = ExitCode.INTERNAL

    def __init__(self, safe_message: str, *, exit_code: ExitCode | None = None) -> None:
        super().__init__(safe_message)
        self.safe_message = safe_message
        if exit_code is not None:
            self.exit_code = exit_code

    def __str__(self) -> str:
        return self.safe_message

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.safe_message!r})"


class ValidationFailed(VeilError):
    exit_code = ExitCode.FINDINGS


class PersonaFormatError(ValidationFailed):
    """The persona file cannot be read as YAML or has the wrong overall shape.

    Carries a finding code and a position only. The offending text is never included: YAML
    parser messages quote source lines, and those lines hold persona values.
    """

    def __init__(self, code: str, problem: str, line: int | None = None, column: int | None = None):
        where = f" at line {line}, column {column}" if line is not None else ""
        super().__init__(f"{code} {problem}{where}")
        self.code = code
        self.problem = problem
        self.line = line
        self.column = column


class KeyUnavailable(VeilError):
    exit_code = ExitCode.KEY_UNAVAILABLE


class DecryptFailed(VeilError):
    exit_code = ExitCode.DECRYPT_FAILED


class Busy(VeilError):
    exit_code = ExitCode.BUSY


class UnsafeEnvironment(VeilError):
    exit_code = ExitCode.UNSAFE_ENVIRONMENT


class Aborted(VeilError):
    exit_code = ExitCode.ABORTED


class StorageError(VeilError):
    exit_code = ExitCode.STORAGE
