"""`veil translate`, `veil reverse`, `veil audit` (M1.7): text in, text (or a report) out.

- translate: real → fake. stdin (or --file) to stdout, byte-exact apart from the replaced spans.
  Warns on stderr, with counts only, when the input already contains fake forms (those can't
  be told apart from translated ones later).
- reverse: fake → real. **Human-only**: its output contains real values (ADR-0027 amendment,
  denied to agents in .claude/settings.json).
- audit: reports every real form as `line:column  field-path  (kind)`, never the text; exit 1
  if anything is found (ADR-0027 FINDINGS), 0 if the text is clean.

Input limit MAX_INPUT_BYTES; input must be UTF-8. Every failure exits with an ADR-0027 code and
prints nothing on stdout, so a pipeline never receives untranslated text by mistake.
"""

from collections.abc import Callable
from pathlib import Path

from veil import ui
from veil.engine.matcher import Engine
from veil.exitcodes import ExitCode
from veil.timing import STAGES

MAX_INPUT_BYTES = 10 * 1024 * 1024

EngineLoader = Callable[[], Engine]


def translate(load: EngineLoader, path: Path | None) -> int:
    text = ui.read_input(path, MAX_INPUT_BYTES)
    engine = load()
    out = engine.forward(text)  # computed fully before anything is written (fail closed)
    STAGES.mark("translate")
    ambiguous = engine.ambiguous(text)
    if ambiguous:
        ui.err(
            f"veil: warning: the input already contains {sum(ambiguous.values())} fake form(s) "
            f"({len(ambiguous)} field(s)); they won't be told apart from translated ones later"
        )
    ui.write(out)
    STAGES.report()
    return int(ExitCode.OK)


def reverse(load: EngineLoader, path: Path | None) -> int:
    text = ui.read_input(path, MAX_INPUT_BYTES)
    out = load().reverse(text)
    STAGES.mark("reverse")
    ui.write(out)
    STAGES.report()
    return int(ExitCode.OK)


def audit(load: EngineLoader, path: Path | None) -> int:
    text = ui.read_input(path, MAX_INPUT_BYTES)
    hits = load().audit(text)
    STAGES.mark("audit")
    for hit in hits:
        ui.out(f"{hit.line}:{hit.column}  {hit.path}  ({hit.kind})")
    ui.out(f"{len(hits)} real form(s) found")
    STAGES.report()
    return int(ExitCode.FINDINGS if hits else ExitCode.OK)
