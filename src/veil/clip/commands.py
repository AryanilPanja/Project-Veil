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

Ask before send (M2.4, ADR-0012), sanitize and from-selection only. Listed special-category
terms with policy GENERALIZE are always replaced by their phrase; ASK terms trigger the question:
- while waiting, the clipboard holds a harmless placeholder (a reflexive Ctrl+V pastes nothing
  real, and it becomes the newest Klipper entry, so "prevent empty clipboard" can't bring the
  original back after a Deny);
- Allow: sent as is; Generalize: replaced by the phrase; Deny (or no answer): clipboard cleared.
Generalizing happens before translation, so the phrase is translated like any other text.

After a successful write, the original is removed from KDE's clipboard history (M2.6,
`history.py`); best effort, reported in the Outcome, never an error.

The result is computed in full before anything is written. Errors propagate to the caller,
which runs `fail_closed` for sanitize and from-selection (M2.5, spec §4.4): the clipboard may
still hold the real text the user believes is about to be sanitized. Restore errors leave the
clipboard alone: it holds the fake text, nothing to protect (decision tracks §AP).
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from veil.clip import recent
from veil.clip.ask import Asker, Decision, deny_all
from veil.clip.history import Forget, Forgetter
from veil.clip.io import Clipboard, Kind, Selection
from veil.engine.matcher import Engine, RawMatch
from veil.persona.policy import Policy
from veil.timing import STAGES

EngineLoader = Callable[[], Engine]

WAITING_PLACEHOLDER = "[veil: waiting for your answer about a sensitive detail]"
ERROR_PLACEHOLDER = "[veil: error, nothing to paste. Copy the text again and retry]"


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
    DENIED = "sensitive detail withheld"
    OWN = "veil's own write"  # the copy watcher saw veil's result (or a restore) come back


class Pasted(Enum):
    """`veil clip paste` (ADR-0030): what happened after sanitizing."""

    PASTED = "pasted"
    REFUSED = "refused"  # the desktop's permission dialog said no
    FAILED = "failed"  # the desktop portal didn't work


@dataclass(frozen=True)
class Outcome:
    """What a clip command did: counts and reasons only, never text."""

    action: Action
    skipped: Skip | None = None
    replaced: dict[str, int] = field(default_factory=dict)  # entity kind → count
    preexisting_fakes: int = 0  # sanitize: fake forms already in the input (can't round-trip)
    asked: dict[str, int] = field(default_factory=dict)  # ASK category → count
    decision: Decision | None = None  # set when the user was asked
    generalized: int = 0  # spans replaced by their generalized phrase
    history: Forget | None = None  # removing the original from the clipboard history (M2.6)
    residue: dict[str, int] = field(default_factory=dict)  # restore: fake-name leftovers (M2.7)
    pasted: Pasted | None = None  # `clip paste` only (ADR-0030)

    @property
    def changed(self) -> bool:
        return self.skipped is None

    @property
    def total(self) -> int:
        return sum(self.replaced.values())


class Scrub(Enum):
    """What fail_closed managed to do."""

    CLEARED = "cleared"
    REPLACED = "replaced"  # clearing failed, but the placeholder replaced the original
    FAILED = "failed"  # the original may still be on the clipboard


def sanitize(
    board: Clipboard,
    load: EngineLoader,
    ask: Asker = deny_all,
    forget: Forgetter | None = None,
    *,
    auto: bool = False,
) -> Outcome:
    """`auto`: run by the copy watcher after every clipboard change (ADR-0031): veil's own
    writes are skipped before anything is decrypted, and a plain-text clipboard that sanitizing
    wouldn't change isn't rewritten (so the watcher never loops on its own result)."""
    return _forward(board, load, Selection.CLIPBOARD, Action.SANITIZE, ask, forget, auto=auto)


def from_selection(
    board: Clipboard, load: EngineLoader, ask: Asker = deny_all, forget: Forgetter | None = None
) -> Outcome:
    return _forward(board, load, Selection.PRIMARY, Action.FROM_SELECTION, ask, forget)


def restore(board: Clipboard, load: EngineLoader) -> Outcome:
    content = board.read(Selection.CLIPBOARD)
    STAGES.mark("read")
    skipped = _skip(content.kind, content.secret, Selection.CLIPBOARD)
    if skipped is not None:
        return Outcome(Action.RESTORE, skipped)
    engine = load()
    text = content.text or ""
    out, counts = engine.reverse_counted(text)
    residue = engine.residue(text)
    STAGES.mark("reverse")
    board.write_text(out)
    STAGES.mark("write")
    return Outcome(Action.RESTORE, replaced=counts, residue=residue)


def _forward(
    board: Clipboard,
    load: EngineLoader,
    source: Selection,
    action: Action,
    ask: Asker,
    forget: Forgetter | None,
    *,
    auto: bool = False,
) -> Outcome:
    content = board.read(source)
    STAGES.mark("read")
    skipped = _skip(content.kind, content.secret, source)
    if skipped is not None:
        return Outcome(action, skipped)
    if auto and recent.seen(content.text or ""):
        return Outcome(action, Skip.OWN)
    engine = load()
    text = content.text or ""  # TEXT always carries text

    hits = engine.sensitive(text)
    to_ask = [h for h in hits if h.form.entity.policy is Policy.ASK]
    to_generalize = [h for h in hits if h.form.entity.policy is Policy.GENERALIZE]
    asked = _categories(to_ask)
    decision = None
    if to_ask:
        board.write_text(WAITING_PLACEHOLDER)
        STAGES.mark("ask")
        decision = ask(asked, engine.lexicon.ask_timeout_seconds)
        if decision is Decision.DENY:
            board.clear(Selection.CLIPBOARD)
            return Outcome(action, Skip.DENIED, asked=asked, decision=decision)
        if decision is Decision.GENERALIZE:
            to_generalize += to_ask
    if to_generalize:
        text = Engine.generalize(text, to_generalize)

    out, counts = engine.forward_counted(text)
    preexisting = sum(engine.ambiguous(text).values())
    STAGES.mark("translate")
    if auto and out == content.text and content.plain_only:
        # Nothing to change and no rich types to drop: rewriting would only wake the watcher.
        return Outcome(action, preexisting_fakes=preexisting)
    board.write_text(out)  # always CLIPBOARD, plain text only
    STAGES.mark("write")
    history = None
    if forget is not None:
        history = forget(content.text or "", lambda: board.write_text(out))
        STAGES.mark("history")
    return Outcome(
        action,
        replaced=counts,
        preexisting_fakes=preexisting,
        asked=asked,
        decision=decision,
        generalized=len(to_generalize),
        history=history,
    )


def fail_closed(board: Clipboard | None) -> Scrub:
    """After an error: leave nothing real on CLIPBOARD (M2.5). Never raises.

    The placeholder goes first: Klipper's "prevent empty clipboard" puts its newest history
    entry back after a clear, and that entry must not be the original. Both steps are tried
    whatever the other did. `board` is None when no clipboard tool could be found.
    """
    if board is None:
        return Scrub.FAILED
    replaced = _attempt(board.write_text, ERROR_PLACEHOLDER)
    if _attempt(board.clear, Selection.CLIPBOARD):
        return Scrub.CLEARED
    return Scrub.REPLACED if replaced else Scrub.FAILED


def _attempt(step: Callable[..., None], *args: object) -> bool:
    try:
        step(*args)
    except Exception:  # noqa: BLE001 - fail closed: try the next step regardless
        return False
    return True


def _categories(hits: list[RawMatch]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for hit in hits:
        category = hit.form.entity.meta_value("category", "sensitive")
        counts[category] = counts.get(category, 0) + 1
    return counts


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
