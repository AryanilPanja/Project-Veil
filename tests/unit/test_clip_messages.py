"""Clip messages and notifications (M2.3): snapshots of every message, notify-send, CLI wiring.

Snapshots are written out in full on purpose: any wording change shows up in review. No real
notification is ever shown (conftest's `notifications` fixture records them instead).
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.helpers.fakeclip import FakeBoard
from tests.unit.test_clip_commands import FAKES, REAL, REALS, run
from tests.unit.test_textcmd import imported  # noqa: F401 - pytest fixture
from veil.clip import io as clipio
from veil.clip import messages
from veil.clip.commands import Action, Outcome, Scrub, Skip
from veil.clip.io import Selection
from veil.clip.notify import (
    APP_NAME,
    EXPIRE_MS,
    Message,
    NotifySend,
    NullNotifier,
    Urgency,
)
from veil.clip.notify import detect as real_detect  # bound before conftest patches it
from veil.errors import ClipboardError
from veil.exitcodes import ExitCode
from veil.persona.model import EntityKind

N, C = Urgency.NORMAL, Urgency.CRITICAL
COUNTS = {"name": 3, "email": 1, "path": 2, "org": 1}

# ── snapshots ─────────────────────────────────────────────────────────────────

SNAPSHOTS = [
    (
        Outcome(Action.SANITIZE, replaced=COUNTS),
        [
            "veil: sanitized: 7 replacement(s) (name 3, path 2, email 1, organisation 1); clipboard holds plain text only"
        ],
        Message(
            "veil: sanitized, 7 replaced",
            "name 3, path 2, email 1, organisation 1\nPlain text only. Ready to paste.",
            N,
        ),
    ),
    (
        Outcome(Action.SANITIZE),
        ["veil: sanitized: no personal details; clipboard holds plain text only"],
        Message(
            "veil: sanitized, no personal details found", "Plain text only. Ready to paste.", N
        ),
    ),
    (
        Outcome(Action.SANITIZE, replaced={"name": 1}, preexisting_fakes=2),
        [
            "veil: sanitized: 1 replacement(s) (name 1); clipboard holds plain text only",
            "veil: warning: the text already contained 2 fake form(s); restore can't tell them apart from translated ones",
        ],
        Message(
            "veil: sanitized, 1 replaced",
            "name 1\nPlain text only. Ready to paste.\nNote: 2 fake form(s) were already in the text; restoring may change them.",
            N,
        ),
    ),
    (
        Outcome(Action.FROM_SELECTION, replaced={"class_term": 1, "token": 2}),
        [
            "veil: sanitized from the selection: 3 replacement(s) (other 2, degree/year 1); clipboard holds plain text only"
        ],
        Message(
            "veil: selection sanitized, 3 replaced",
            "other 2, degree/year 1\nPlain text only. Ready to paste.",
            N,
        ),
    ),
    (
        Outcome(Action.RESTORE, replaced={"name": 2, "person_name": 1}),
        ["veil: restored 3 detail(s) (name 2, person 1)"],
        Message(
            "veil: 3 restored", "name 2, person 1\nThe clipboard now holds your real details.", N
        ),
    ),
    (
        Outcome(Action.RESTORE),
        ["veil: restored 0 detail(s)"],
        Message("veil: nothing to restore", "No fake details found. Plain text only.", N),
    ),
    # sanitize skipped: critical unless nothing is copied
    (
        Outcome(Action.SANITIZE, Skip.EMPTY),
        ["veil: clipboard NOT sanitized: nothing copied; left unchanged"],
        Message("veil: nothing to sanitize", "Nothing is copied.", N),
    ),
    (
        Outcome(Action.SANITIZE, Skip.RICH_ONLY),
        ["veil: clipboard NOT sanitized: no plain text (rich text only); left unchanged"],
        Message(
            "veil: clipboard NOT sanitized",
            "No plain text (rich text only). It still holds the original: don't paste it into a chat.",
            C,
            "dialog-warning",
        ),
    ),
    (
        Outcome(Action.SANITIZE, Skip.NON_TEXT),
        ["veil: clipboard NOT sanitized: no plain text (an image or a file); left unchanged"],
        Message(
            "veil: clipboard NOT sanitized",
            "No plain text (an image or a file). It still holds the original: don't paste it into a chat.",
            C,
            "dialog-warning",
        ),
    ),
    (
        Outcome(Action.SANITIZE, Skip.SECRET),
        [
            "veil: clipboard NOT sanitized: marked as a password by a password manager; left unchanged"
        ],
        Message(
            "veil: clipboard NOT sanitized",
            "Marked as a password by a password manager. It still holds the original: don't paste it into a chat.",
            C,
            "dialog-warning",
        ),
    ),
    # from-selection skipped: always critical (the clipboard holds older content)
    (
        Outcome(Action.FROM_SELECTION, Skip.NOTHING_SELECTED),
        ["veil: clipboard NOT sanitized: nothing selected; left unchanged"],
        Message(
            "veil: selection NOT sanitized",
            "Nothing selected. The clipboard is unchanged: don't paste it unchecked.",
            C,
            "dialog-warning",
        ),
    ),
    (
        Outcome(Action.FROM_SELECTION, Skip.RICH_ONLY),
        ["veil: clipboard NOT sanitized: no plain text (rich text only); left unchanged"],
        Message(
            "veil: selection NOT sanitized",
            "No plain text (rich text only). The clipboard is unchanged: don't paste it unchecked.",
            C,
            "dialog-warning",
        ),
    ),
    # restore skipped: normal (nothing unsanitized is at stake)
    (
        Outcome(Action.RESTORE, Skip.EMPTY),
        ["veil: clipboard NOT restored: nothing copied; left unchanged"],
        Message("veil: clipboard NOT restored", "Nothing copied. Left unchanged.", N),
    ),
    (
        Outcome(Action.RESTORE, Skip.SECRET),
        [
            "veil: clipboard NOT restored: marked as a password by a password manager; left unchanged"
        ],
        Message(
            "veil: clipboard NOT restored",
            "Marked as a password by a password manager. Left unchanged.",
            N,
        ),
    ),
]


@pytest.mark.parametrize(("outcome", "lines", "message"), SNAPSHOTS)
def test_snapshot(outcome, lines, message):
    assert messages.stderr_lines(outcome) == lines
    assert messages.notification(outcome) == message


def test_error_snapshots():
    assert messages.error_notification("wl-copy failed (exit 1)", Scrub.CLEARED) == Message(
        "veil error: clipboard cleared",
        "Nothing to paste. Copy the text again and retry.\n(wl-copy failed (exit 1))",
        C,
        "dialog-error",
    )
    assert messages.error_notification("wl-copy failed (exit 1)", Scrub.REPLACED) == Message(
        "veil error: clipboard replaced",
        "Nothing to paste. Copy the text again and retry.\n(wl-copy failed (exit 1))",
        C,
        "dialog-error",
    )
    assert messages.error_notification("the keyring is locked", Scrub.FAILED) == Message(
        "veil error: clipboard NOT cleared",
        "Do not paste: the clipboard may hold unsanitized text.\n(the keyring is locked)",
        C,
        "dialog-error",
    )
    assert messages.error_notification("the keyring is locked", None) == Message(
        "veil error: nothing restored",
        "The clipboard is unchanged.\n(the keyring is locked)",
        C,
        "dialog-error",
    )


@pytest.mark.parametrize("scrub", [*Scrub, None])
def test_every_error_state_has_a_line_and_a_message(scrub):
    assert messages.error_line(scrub).startswith("veil: ")
    assert messages.error_notification("x", scrub).urgency is C


def test_error_text_is_made_markup_free():
    body = messages.error_notification("size <10> & more", Scrub.CLEARED).body
    assert "<" not in body
    assert ">" not in body
    assert "&" not in body


@pytest.mark.parametrize("action", list(Action))
@pytest.mark.parametrize("skip", list(Skip))
def test_every_skip_has_a_message(action, skip):
    message = messages.notification(Outcome(action, skip))
    assert message.summary.startswith("veil")
    assert message.body


def test_unsanitized_content_is_always_critical():
    for skip in (Skip.RICH_ONLY, Skip.NON_TEXT, Skip.SECRET):
        assert messages.notification(Outcome(Action.SANITIZE, skip)).urgency is C
    for skip in Skip:
        if skip is not Skip.DENIED:  # Deny clears the clipboard: nothing unsanitized is left
            assert messages.notification(Outcome(Action.FROM_SELECTION, skip)).urgency is C


def test_every_entity_kind_has_a_label():
    assert set(messages.LABELS) == {k.value for k in EntityKind}


def test_unknown_kind_is_labelled_other():
    assert messages.categories({"brand-new-kind": 2, "token": 1}) == "other 3"


def test_labels_are_merged():
    assert messages.categories({"token": 1, "brand-new": 1, "name": 1}) == "other 2, name 1"


# ── properties: value-free, markup-free ───────────────────────────────────────

OUTCOMES = st.builds(
    Outcome,
    st.sampled_from(list(Action)),
    st.one_of(st.none(), st.sampled_from(list(Skip))),
    st.dictionaries(
        st.sampled_from([k.value for k in EntityKind]), st.integers(1, 10**6), max_size=8
    ),
    st.integers(0, 1000),
)


@given(OUTCOMES)
def test_messages_hold_counts_and_fixed_words_only(outcome):
    texts = [
        *messages.stderr_lines(outcome),
        messages.notification(outcome).summary,
        messages.notification(outcome).body,
    ]
    for text in texts:
        for real in REALS:
            assert real.lower() not in text.lower()
        assert not set(text) & set("<>&")  # bodies may be rendered as markup
    if outcome.skipped is None and outcome.replaced:
        assert str(outcome.total) in messages.notification(outcome).summary


# ── notify-send ───────────────────────────────────────────────────────────────


class Feed:
    def __init__(self, rc=0, error=None):
        self.rc, self.error, self.calls = rc, error, []

    def __call__(self, argv, data, *, timeout):
        self.calls.append((argv, data, timeout))
        if self.error:
            raise self.error
        return self.rc


class TestNotifySend:
    def test_argv_normal(self):
        argv = NotifySend("/usr/bin/notify-send").argv(Message("veil: s", "b", N))
        assert argv == [
            "/usr/bin/notify-send",
            f"--app-name={APP_NAME}",
            "--urgency=normal",
            "--icon=security-high",
            "--transient",
            f"--expire-time={EXPIRE_MS}",
            "--",
            "veil: s",
            "b",
        ]

    def test_critical_has_no_expiry(self):
        argv = NotifySend("/n").argv(Message("s", "b", C, "dialog-error"))
        assert "--urgency=critical" in argv
        assert "--icon=dialog-error" in argv
        assert not any(a.startswith("--expire-time") for a in argv)

    def test_summary_starting_with_a_dash_is_not_an_option(self):
        argv = NotifySend("/n").argv(Message("-x", "-y"))
        assert argv[-3:] == ["--", "-x", "-y"]

    def test_notify_runs_it(self):
        feed = Feed()
        assert NotifySend("/n", feed=feed).notify(Message("s", "b")) is True
        argv, data, timeout = feed.calls[0]
        assert argv[0] == "/n"
        assert data == b""
        assert 0 < timeout <= 5

    def test_failure_is_reported_not_raised(self):
        assert NotifySend("/n", feed=Feed(rc=1)).notify(Message("s", "b")) is False
        error = ClipboardError("the clipboard tool timed out")
        assert NotifySend("/n", feed=Feed(error=error)).notify(Message("s", "b")) is False

    def test_missing_binary_is_reported_not_raised(self, tmp_path):
        assert NotifySend(str(tmp_path / "nope")).notify(Message("s", "b")) is False

    def test_detect(self):
        assert isinstance(real_detect(lambda name: "/usr/bin/" + name), NotifySend)
        assert isinstance(real_detect(lambda name: None), NullNotifier)
        assert NullNotifier().notify(Message("s", "b")) is False


# ── CLI wiring ────────────────────────────────────────────────────────────────


@pytest.fixture
def board(monkeypatch):
    holder = FakeBoard()
    monkeypatch.setattr(clipio, "detect", lambda: holder)
    return holder


class TestCliNotifications:
    @pytest.mark.usefixtures("imported")
    def test_sanitize_notifies_counts_only(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        code, _, err = run(capsys, "sanitize")
        assert code == ExitCode.OK
        assert len(notifications) == 1
        shown = notifications[0]
        assert shown.summary == "veil: sanitized, 6 replaced"
        assert shown.urgency is N
        for text in (shown.summary, shown.body, err):
            for value in (*REALS, *FAKES):
                assert value.lower() not in text.lower()

    @pytest.mark.usefixtures("imported")
    def test_restore_notifies(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        run(capsys, "sanitize")
        run(capsys, "restore")
        assert notifications[-1].summary == "veil: 6 restored"

    def test_skip_notifies_critical(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {"text/html": b"<b>x</b>"}
        assert run(capsys, "sanitize")[0] == ExitCode.OK
        assert notifications == [messages.notification(Outcome(Action.SANITIZE, Skip.RICH_ONLY))]

    def test_no_notify_flag(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {"image/png": b"x"}
        code, _, err = run(capsys, "sanitize", "--no-notify")
        assert code == ExitCode.OK
        assert notifications == []
        assert "NOT sanitized" in err  # stderr still says it

    def test_failing_notifier_does_not_change_the_result(self, board, capsys, monkeypatch):
        from veil.clip import notify

        monkeypatch.setattr(notify, "detect", lambda: NotifySend("/n", feed=Feed(rc=1)))
        board.offers[Selection.CLIPBOARD] = {"image/png": b"x"}
        assert run(capsys, "sanitize")[0] == ExitCode.OK

    def test_errors_notify_critical(self, board, capsys, notifications):
        # M2.5: fail closed, then one critical notification (more in test_clip_failclosed.py).
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        code, _, _ = run(capsys, "sanitize")
        assert code != ExitCode.OK
        assert [n.summary for n in notifications] == ["veil error: clipboard cleared"]
        assert notifications[0].urgency is C
