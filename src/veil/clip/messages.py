"""What the clip commands tell the user (M2.3): one stderr line and one notification per run.

Value-free by construction: built only from an Outcome (action, skip reason, counts per entity
kind) or a VeilError's safe message. Category labels are fixed words, never field contents.

Urgency (spec §1.5: a reflexive Ctrl+V must never paste text you believed was sanitized):
- the clipboard was sanitized, restored, or is empty → normal;
- the clipboard still holds content that was NOT sanitized (rich text, an image or file, a
  password, or older content when nothing was selected) → critical: it stays until dismissed;
- an error → critical (M2.5 clears the clipboard first).
"""

from veil.clip.ask import Decision, describe
from veil.clip.commands import Action, Outcome, Skip
from veil.clip.notify import Message, Urgency

LABELS = {
    "name": "name",
    "person_name": "person",
    "email": "email",
    "phone": "phone",
    "username": "username",
    "handle": "handle",
    "org": "organisation",
    "domain": "domain",
    "place": "place",
    "address": "address",
    "postal_code": "postal code",
    "path": "path",
    "hostname": "hostname",
    "identifier": "ID",
    "date": "date",
    "class_term": "degree/year",
    "year": "year",
    "pet_name": "pet",
    "token": "other",
    "text": "phrase",
}


def categories(replaced: dict[str, int]) -> str:
    """ "name 3, email 1": by count (largest first), then label."""
    labelled: dict[str, int] = {}
    for kind, count in replaced.items():
        label = LABELS.get(kind, "other")
        labelled[label] = labelled.get(label, 0) + count
    ordered = sorted(labelled.items(), key=lambda item: (-item[1], item[0]))
    return ", ".join(f"{label} {count}" for label, count in ordered)


def stderr_lines(outcome: Outcome) -> list[str]:
    lines = [_line(outcome)]
    sensitive = _sensitive_note(outcome)
    if sensitive:
        lines.append(f"veil: {sensitive[:1].lower()}{sensitive[1:]}")
    if outcome.preexisting_fakes:
        lines.append(
            f"veil: warning: the text already contained {outcome.preexisting_fakes} fake "
            "form(s); restore can't tell them apart from translated ones"
        )
    return lines


def notification(outcome: Outcome) -> Message:
    if outcome.skipped is Skip.DENIED:
        return Message(
            "veil: withheld, clipboard cleared",
            f"Sensitive: {describe(outcome.asked)}. Nothing to paste.",
        )
    if outcome.skipped is not None:
        return _skipped(outcome.action, outcome.skipped)
    detail = categories(outcome.replaced)
    if outcome.action is Action.RESTORE:
        if not outcome.total:
            return Message("veil: nothing to restore", "No fake details found. Plain text only.")
        return Message(
            f"veil: {outcome.total} restored",
            f"{detail}\nThe clipboard now holds your real details.",
        )
    where = "selection sanitized" if outcome.action is Action.FROM_SELECTION else "sanitized"
    found = f"{outcome.total} replaced" if outcome.total else "no personal details found"
    body = [detail] if detail else []
    sensitive = _sensitive_note(outcome)
    if sensitive:
        body.append(sensitive)
    body.append("Plain text only. Ready to paste.")
    if outcome.preexisting_fakes:
        body.append(
            f"Note: {outcome.preexisting_fakes} fake form(s) were already in the text; "
            "restoring may change them."
        )
    return Message(f"veil: {where}, {found}", "\n".join(body))


def error_notification(safe_message: str, *, cleared: bool) -> Message:
    """For M2.5's fail-closed path. `safe_message` is a VeilError's value-free message."""
    detail = _plain(safe_message)
    if cleared:
        return Message(
            "veil error: clipboard cleared",
            f"Copy the text again and retry.\n({detail})",
            Urgency.CRITICAL,
            icon="dialog-error",
        )
    return Message(
        "veil error: clipboard NOT cleared",
        f"Do not paste: the clipboard may hold unsanitized text.\n({detail})",
        Urgency.CRITICAL,
        icon="dialog-error",
    )


def _sensitive_note(outcome: Outcome) -> str:
    """What happened to listed special-category terms; categories and counts only."""
    if outcome.decision is Decision.ALLOW:
        note = f"Sensitive sent as is ({describe(outcome.asked)})."
        if outcome.generalized:
            note += f" {outcome.generalized} other detail(s) generalized."
        return note
    if outcome.generalized:
        return f"Generalized {outcome.generalized} sensitive detail(s)."
    return ""


def _line(outcome: Outcome) -> str:
    if outcome.skipped is Skip.DENIED:
        return (
            f"veil: clipboard NOT sanitized: {Skip.DENIED.value} ({describe(outcome.asked)}); "
            "clipboard cleared"
        )
    if outcome.skipped is not None:
        verb = "restored" if outcome.action is Action.RESTORE else "sanitized"
        return f"veil: clipboard NOT {verb}: {outcome.skipped.value}; left unchanged"
    detail = f" ({categories(outcome.replaced)})" if outcome.replaced else ""
    if outcome.action is Action.RESTORE:
        return f"veil: restored {outcome.total} detail(s){detail}"
    found = f"{outcome.total} replacement(s){detail}" if outcome.total else "no personal details"
    source = " from the selection" if outcome.action is Action.FROM_SELECTION else ""
    return f"veil: sanitized{source}: {found}; clipboard holds plain text only"


def _skipped(action: Action, skip: Skip) -> Message:
    if action is Action.RESTORE:
        return Message("veil: clipboard NOT restored", f"{_sentence(skip.value)}. Left unchanged.")
    if action is Action.FROM_SELECTION:
        # The clipboard still holds whatever was copied before: maybe real text.
        return Message(
            "veil: selection NOT sanitized",
            f"{_sentence(skip.value)}. The clipboard is unchanged: don't paste it unchecked.",
            Urgency.CRITICAL,
            icon="dialog-warning",
        )
    if skip is Skip.EMPTY:
        return Message("veil: nothing to sanitize", "Nothing is copied.")
    return Message(
        "veil: clipboard NOT sanitized",
        f"{_sentence(skip.value)}. It still holds the original: don't paste it into a chat.",
        Urgency.CRITICAL,
        icon="dialog-warning",
    )


def _sentence(text: str) -> str:
    return text[:1].upper() + text[1:]


def _plain(text: str) -> str:
    """Notification bodies may be rendered as markup: keep error text markup-free."""
    return "".join(c for c in text if c not in "<>&")
