"""Validation findings and their rendering.

A Finding holds a severity, a code, a field path and a message built from a fixed template plus
other field paths. It never holds a persona value, so reports are safe to print, log, or show to
an AI agent (`veil persona check` is on the agent-safe list).
"""

import json
from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    ERROR = 0
    WARNING = 1
    INFO = 2

    @property
    def label(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class Finding:
    severity: Severity
    code: str
    path: str
    message: str

    def render(self) -> str:
        return f"{self.severity.label:<7} {self.code} {self.path}: {self.message}"


@dataclass(frozen=True, slots=True)
class Report:
    findings: tuple[Finding, ...]

    @property
    def errors(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity is Severity.ERROR)

    @property
    def warnings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity is Severity.WARNING)

    def failed(self, *, strict: bool = False) -> bool:
        return bool(self.errors) or (strict and bool(self.warnings))

    def codes(self) -> list[str]:
        return [f.code for f in self.findings]


def make_report(findings: list[Finding]) -> Report:
    """Deduplicate and order: errors first, then by first appearance."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.code, finding.path, finding.message)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    unique.sort(key=lambda f: f.severity)  # stable: keeps appearance order within a severity
    return Report(tuple(unique))


def render_text(report: Report) -> str:
    lines = [f.render() for f in report.findings]
    lines.append(
        f"{len(report.errors)} error(s), {len(report.warnings)} warning(s), "
        f"{len(report.findings) - len(report.errors) - len(report.warnings)} note(s)"
    )
    return "\n".join(lines)


def render_json(report: Report) -> str:
    return json.dumps(
        {
            "errors": len(report.errors),
            "warnings": len(report.warnings),
            "findings": [
                {
                    "severity": f.severity.label,
                    "code": f.code,
                    "path": f.path,
                    "message": f.message,
                }
                for f in report.findings
            ],
        },
        indent=2,
        ensure_ascii=False,
    )
