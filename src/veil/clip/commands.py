"""`veil clip sanitize | restore | from-selection` (M2.2, spec §4, ADR-0023).

- sanitize: CLIPBOARD plain text → forward → CLIPBOARD as `text/plain` only.
- from-selection: PRIMARY (highlighted text) → forward → CLIPBOARD. PRIMARY is left as is.
- restore: CLIPBOARD → reverse → CLIPBOARD. Its result holds real values (denied to agents).

The clipboard is read before the persona is decrypted, so an empty or image clipboard costs no
key access. Then:
- no plain text (nothing copied, an image or file, rich text only) → the clipboard is left
  unchanged (owner decision 2026-10-25, decision tracks §AK);
- the source marked it as a password (x-kde-passwordManagerHint) → left unchanged, so veil
  never turns a password into a plain entry that clipboard histories keep;
- otherwise the result is **always** written back, even with zero replacements: the original
  copy may carry rich types (an HTML `mailto:` link) that hold details the plain text doesn't.

The result is computed in full before anything is written. Errors propagate to the caller;
clearing the clipboard on error (fail closed) is M2.5.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from veil.clip.io import Clipboard, Kind, Selection
from veil.engine.matcher import Engine
from veil.timing import STAGES

EngineLoader = Callable[[], Engine]


class Action(Enum):
    SANITIZE = "sanitize"
    FROM_SELECTION = "from-selection"
    RESTORE = "restore"


class Skip(Enum):
    """Why the clipboard was left unchanged."""

    EMPTY = "nothing copied"
    NOTHING_SELECTED = "nothing selected"
    NON_TEXT = "no plain text (an image or a file)"
    RICH_ONLY = "no plain text (rich text only)"
    SECRET = "marked as a password by a password manager"  # noqa: S105 - a message


@dataclass(frozen=True)
class Outcome:
    """What a clip command did: counts and reasons only, never text."""

    action: Action
    skipped: Skip | None = None
    replaced: dict[str, int] = field(default_factory=dict)  # entity kind → count
    preexisting_fakes: int = 0  # sanitize: fake forms already in the input (can't round-trip)

    @property
    def changed(self) -> bool:
        return self.skipped is None

    @property
    def total(self) -> int:
        return sum(self.replaced.values())


def sanitize(board: Clipboard, load: EngineLoader) -> Outcome:
    return _forward(board, load, Selection.CLIPBOARD, Action.SANITIZE)


def from_selection(board: Clipboard, load: EngineLoader) -> Outcome:
    return _forward(board, load, Selection.PRIMARY, Action.FROM_SELECTION)


def restore(board: Clipboard, load: EngineLoader) -> Outcome:
    content = board.read(Selection.CLIPBOARD)
    STAGES.mark("read")
    skipped = _skip(content.kind, content.secret, Selection.CLIPBOARD)
    if skipped is not None:
        return Outcome(Action.RESTORE, skipped)
    out, counts = load().reverse_counted(content.text or "")
    STAGES.mark("reverse")
    board.write_text(out)
    STAGES.mark("write")
    return Outcome(Action.RESTORE, replaced=counts)


def _forward(board: Clipboard, load: EngineLoader, source: Selection, action: Action) -> Outcome:
    content = board.read(source)
    STAGES.mark("read")
    skipped = _skip(content.kind, content.secret, source)
    if skipped is not None:
        return Outcome(action, skipped)
    engine = load()
    text = content.text or ""  # TEXT always carries text
    out, counts = engine.forward_counted(text)
    preexisting = sum(engine.ambiguous(text).values())
    STAGES.mark("translate")
    board.write_text(out)  # always CLIPBOARD, plain text only
    STAGES.mark("write")
    return Outcome(action, replaced=counts, preexisting_fakes=preexisting)


def _skip(kind: Kind, secret: bool, source: Selection) -> Skip | None:
    if kind is Kind.EMPTY:
        return Skip.NOTHING_SELECTED if source is Selection.PRIMARY else Skip.EMPTY
    if kind is Kind.NON_TEXT:
        return Skip.NON_TEXT
    if kind is Kind.RICH_ONLY:
        return Skip.RICH_ONLY
    if secret:
        return Skip.SECRET
    return None


def summary(outcome: Outcome) -> str:
    """One value-free line: the action, and counts per category."""
    if outcome.skipped is not None:
        verb = "restored" if outcome.action is Action.RESTORE else "sanitized"
        return f"veil: clipboard NOT {verb}: {outcome.skipped.value}; left unchanged"
    by_kind = sorted(outcome.replaced.items(), key=lambda item: (-item[1], item[0]))
    detail = f" ({', '.join(f'{kind} {n}' for kind, n in by_kind)})" if by_kind else ""
    if outcome.action is Action.RESTORE:
        return f"veil: restored {outcome.total} detail(s){detail}"
    found = f"{outcome.total} replacement(s){detail}" if outcome.total else "no personal details"
    source = " from the selection" if outcome.action is Action.FROM_SELECTION else ""
    return f"veil: sanitized{source}: {found}; clipboard holds plain text only"


def warnings(outcome: Outcome) -> list[str]:
    if outcome.preexisting_fakes:
        return [
            f"veil: warning: the text already contained {outcome.preexisting_fakes} fake form(s); "
            "restore can't tell them apart from translated ones"
        ]
    return []
