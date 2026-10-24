"""`veil persona check`: load → schema → validate, reported by field path only.

Agent-safe by design: output holds codes, field paths and counts, never values, and never the
file path either (it may contain the user's name).
"""

from pathlib import Path

from veil import ui
from veil.errors import PersonaFormatError, VeilError
from veil.exitcodes import ExitCode
from veil.persona.report import Finding, Report, Severity, make_report, render_json, render_text
from veil.persona.schema import PersonaSchemaError, parse_persona
from veil.persona.validate import validate
from veil.persona.yamlio import MAX_BYTES, load_yaml

FILE = "<file>"


def check_file(path: Path, *, strict: bool = False, fmt: str = "text") -> int:
    report = check_bytes(_read(path))
    ui.out(render_json(report) if fmt == "json" else render_text(report))
    return int(ExitCode.FINDINGS if report.failed(strict=strict) else ExitCode.OK)


def check_bytes(data: bytes) -> Report:
    try:
        raw = load_yaml(data)
    except PersonaFormatError as error:
        where = f" (line {error.line}, column {error.column})" if error.line is not None else ""
        return make_report([Finding(Severity.ERROR, error.code, FILE, error.problem + where)])
    try:
        persona = parse_persona(raw)
    except PersonaSchemaError as error:
        return make_report(
            [Finding(Severity.ERROR, i.code, i.path, i.problem) for i in error.issues]
        )
    return validate(persona)


def _read(path: Path) -> bytes:
    try:
        if path.stat().st_size > MAX_BYTES:
            raise VeilError("the persona file is too large", exit_code=ExitCode.USAGE)
        return path.read_bytes()
    except FileNotFoundError:
        raise VeilError("persona file not found", exit_code=ExitCode.USAGE) from None
    except IsADirectoryError:
        raise VeilError("the given path is a directory", exit_code=ExitCode.USAGE) from None
    except PermissionError:
        raise VeilError(
            "cannot read the persona file (permission denied)", exit_code=ExitCode.USAGE
        ) from None
    except OSError:
        raise VeilError("cannot read the persona file", exit_code=ExitCode.USAGE) from None
