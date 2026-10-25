"""Ask before send (M2.4, ADR-0012): sensitive matcher, Allow / Generalize / Deny, askers.

Synthetic persona: `sensitive.health` lists "asthma" (generalized: "a chronic condition", ASK).
No real prompt is ever shown: conftest's `asker` fixture answers instead.
"""

import sys
import time

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.helpers.fakeclip import FakeBoard
from tests.unit.test_clip_commands import REAL, Loader, run
from tests.unit.test_matcher import FIXTURE, lexicon_from
from tests.unit.test_textcmd import imported  # noqa: F401 - pytest fixture
from veil import ui
from veil.clip import commands, messages
from veil.clip import io as clipio
from veil.clip import notify as notifymod
from veil.clip.ask import ACTIONS, Decision, NotifyAsker, TerminalAsker, deny_all, prompt_message
from veil.clip.ask import detect as real_detect  # bound before conftest patches it
from veil.clip.commands import WAITING_PLACEHOLDER, Action, Outcome, Skip
from veil.clip.io import Selection
from veil.clip.notify import Message, Urgency
from veil.clip.proc import Captured
from veil.engine import cache
from veil.engine.matcher import Engine
from veil.errors import ClipboardError
from veil.exitcodes import ExitCode
from veil.persona.policy import Policy

YAML = FIXTURE.read_text(encoding="utf-8")
HEALTH = "  health:    { real: [asthma], generalized: a chronic condition, policy: ASK }"
assert HEALTH in YAML
SENSITIVE_TEXT = "Jane Doe has asthma.\n"


def engine_with(health_line: str = HEALTH, **replace: str) -> Engine:
    text = YAML.replace(HEALTH, health_line)
    for old, new in replace.items():
        text = text.replace(old, new)
    return Engine(lexicon_from(text))


@pytest.fixture(scope="module")
def engine() -> Engine:
    return engine_with()


class Answer:
    def __init__(self, decision: Decision) -> None:
        self.decision, self.calls = decision, []

    def __call__(self, categories, timeout):
        self.calls.append((dict(categories), timeout))
        return self.decision


# ── the sensitive matcher (engine) ────────────────────────────────────────────


class TestSensitiveMatcher:
    def test_lexicon_carries_terms_and_timeout(self, engine):
        assert len(engine.lexicon.sensitive) == 1
        assert engine.lexicon.ask_timeout_seconds == 120
        form = engine.lexicon.sensitive[0]
        assert form.entity.policy is Policy.ASK
        assert form.entity.meta_value("category") == "health"
        assert form.variant.fake == "a chronic condition"
        assert "asthma" not in repr(engine.lexicon)

    @pytest.mark.parametrize(
        ("text", "count"),
        [
            ("asthma", 1),
            ("Asthma and ASTHMA", 2),
            ("my asthma's fine", 1),
            ("asthmatic", 0),  # boundaries: not inside a longer word
            ("nothing here", 0),
            ("", 0),
            ("a asthma\n", 1),
        ],
    )
    def test_finds_listed_terms_with_boundaries(self, engine, text, count):
        assert len(engine.sensitive(text)) == count

    def test_never_part_of_forward_translation(self, engine):
        assert "asthma" in engine.forward("asthma")

    def test_generalize_replaces_verbatim(self, engine):
        text = "Asthma: ASTHMA, asthma."
        assert Engine.generalize(text, engine.sensitive(text)) == (
            "a chronic condition: a chronic condition, a chronic condition."
        )

    @given(
        st.lists(
            st.sampled_from(["asthma", "Asthma", " ", "\n", "x", "জেন", "asthmatic", ","]),
            max_size=20,
        )
    )
    def test_generalize_keeps_everything_else(self, engine, parts):
        text = "".join(parts)
        hits = engine.sensitive(text)
        out = Engine.generalize(text, hits)
        assert out.count("a chronic condition") == len(hits)
        rest = out.replace("a chronic condition", "")
        cursor, kept = 0, []
        for h in hits:
            kept.append(text[cursor : h.start])
            cursor = h.end
        kept.append(text[cursor:])
        assert rest == "".join(kept)
        assert not engine.sensitive(out.replace("a chronic condition", " "))

    def test_keep_policy_is_not_matched(self):
        engine = engine_with(
            "  health:    { real: [asthma], generalized: a chronic condition, policy: KEEP }"
        )
        assert engine.lexicon.sensitive == ()
        assert engine.sensitive("asthma") == []

    def test_generalize_policy(self):
        engine = engine_with(
            "  health:    { real: [asthma], generalized: a chronic condition, policy: GENERALIZE }"
        )
        assert engine.lexicon.sensitive[0].entity.policy is Policy.GENERALIZE

    def test_default_policy_is_used(self):
        engine = engine_with(
            "  health:    { real: [asthma], generalized: a chronic condition }",
            **{"  default_policy: ASK": "  default_policy: GENERALIZE"},
        )
        assert engine.lexicon.sensitive[0].entity.policy is Policy.GENERALIZE

    def test_empty_phrase_generalizes_to_the_category(self):
        engine = engine_with('  health:    { real: [asthma], generalized: "", policy: ASK }')
        assert engine.lexicon.sensitive[0].variant.fake == "[health]"

    def test_several_terms_and_categories(self):
        engine = engine_with(
            "  health:    { real: [asthma, Asthma, migraine], generalized: a condition, policy: ASK }",
            **{
                '  religion:  { real: [], generalized: "", policy: ASK }': "  religion:  { real: [Zoroastrian], generalized: a faith, policy: ASK }"
            },
        )
        assert len(engine.lexicon.sensitive) == 3  # "Asthma" is the same term as "asthma"
        cats = sorted(
            h.form.entity.meta_value("category")
            for h in engine.sensitive("asthma, migraine, zoroastrian")
        )
        assert cats == ["health", "health", "religion"]

    def test_custom_timeout(self):
        engine = engine_with(**{'ask_timeout_seconds: "120"': 'ask_timeout_seconds: "15"'})
        assert engine.lexicon.ask_timeout_seconds == 15

    def test_cache_round_trip(self, engine):
        decoded = cache.decode(cache.encode(engine.lexicon, "k"), "k")
        assert decoded is not None
        assert decoded.ask_timeout_seconds == 120
        assert [
            (f.variant.real, f.variant.fake, f.entity.policy, f.entity.meta)
            for f in decoded.sensitive
        ] == [
            (f.variant.real, f.variant.fake, f.entity.policy, f.entity.meta)
            for f in engine.lexicon.sensitive
        ]
        assert len(Engine(decoded).sensitive("asthma")) == 1

    def test_old_cache_format_is_ignored(self, engine):
        data = cache.encode(engine.lexicon, "k").replace(b'"format":2', b'"format":1')
        assert cache.decode(data, "k") is None


# ── the sanitize flow ─────────────────────────────────────────────────────────


class Recording(FakeBoard):
    """Remembers every clipboard state, to check what was there while veil was asking."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.history: list[str | None] = []

    def write_text(self, text):
        super().write_text(text)
        self.history.append(text)

    def clear(self, selection=Selection.CLIPBOARD):
        super().clear(selection)
        self.history.append(None)


def board_with(text: str) -> Recording:
    return Recording({"text/plain": text.encode()})


class TestFlow:
    def test_allow(self, engine):
        board, answer = board_with(SENSITIVE_TEXT), Answer(Decision.ALLOW)
        outcome = commands.sanitize(board, Loader(engine), answer)
        assert board.text() == "Alex Smith has asthma.\n"
        assert answer.calls == [({"health": 1}, 120)]
        assert outcome.decision is Decision.ALLOW
        assert outcome.asked == {"health": 1}
        assert outcome.generalized == 0

    def test_generalize(self, engine):
        board, answer = board_with(SENSITIVE_TEXT), Answer(Decision.GENERALIZE)
        outcome = commands.sanitize(board, Loader(engine), answer)
        assert board.text() == "Alex Smith has a chronic condition.\n"
        assert outcome.generalized == 1
        assert outcome.replaced == {"name": 1}

    def test_deny_clears(self, engine):
        board, answer = board_with(SENSITIVE_TEXT), Answer(Decision.DENY)
        outcome = commands.sanitize(board, Loader(engine), answer)
        assert board.offers[Selection.CLIPBOARD] is None
        assert board.history == [WAITING_PLACEHOLDER, None]
        assert outcome == Outcome(
            Action.SANITIZE, Skip.DENIED, asked={"health": 1}, decision=Decision.DENY
        )

    @pytest.mark.parametrize("decision", list(Decision))
    def test_placeholder_while_asking(self, engine, decision):
        board = board_with(SENSITIVE_TEXT)
        seen = []

        def answer(categories, timeout):
            seen.append(board.text())
            return decision

        commands.sanitize(board, Loader(engine), answer)
        assert seen == [WAITING_PLACEHOLDER]
        assert board.history[0] == WAITING_PLACEHOLDER
        assert "asthma" not in WAITING_PLACEHOLDER
        assert board.types() in ([], ["text/plain"])

    def test_default_asker_denies(self, engine):
        board = board_with(SENSITIVE_TEXT)
        outcome = commands.sanitize(board, Loader(engine))
        assert outcome.skipped is Skip.DENIED
        assert board.offers[Selection.CLIPBOARD] is None

    def test_no_sensitive_term_no_question(self, engine):
        board, answer = board_with(REAL), Answer(Decision.DENY)
        outcome = commands.sanitize(board, Loader(engine), answer)
        assert answer.calls == []
        assert outcome.decision is None
        assert board.history == [board.text()]  # one write, the result

    def test_generalize_policy_never_asks(self):
        engine = engine_with(
            "  health:    { real: [asthma], generalized: a chronic condition, policy: GENERALIZE }"
        )
        board, answer = board_with(SENSITIVE_TEXT), Answer(Decision.DENY)
        outcome = commands.sanitize(board, Loader(engine), answer)
        assert answer.calls == []
        assert board.text() == "Alex Smith has a chronic condition.\n"
        assert outcome.generalized == 1

    def test_keep_policy_never_asks(self):
        engine = engine_with(
            "  health:    { real: [asthma], generalized: a chronic condition, policy: KEEP }"
        )
        board, answer = board_with(SENSITIVE_TEXT), Answer(Decision.DENY)
        commands.sanitize(board, Loader(engine), answer)
        assert answer.calls == []
        assert board.text() == "Alex Smith has asthma.\n"

    def test_one_question_for_many_hits(self, engine):
        board, answer = board_with("asthma, Asthma, ASTHMA"), Answer(Decision.GENERALIZE)
        commands.sanitize(board, Loader(engine), answer)
        assert answer.calls == [({"health": 3}, 120)]
        assert board.text() == "a chronic condition, a chronic condition, a chronic condition"

    def test_allow_with_mixed_policies(self):
        engine = engine_with(
            HEALTH,
            **{
                '  religion:  { real: [], generalized: "", policy: ASK }': "  religion:  { real: [Zoroastrian], generalized: a faith, policy: GENERALIZE }"
            },
        )
        board, answer = board_with("asthma; Zoroastrian"), Answer(Decision.ALLOW)
        outcome = commands.sanitize(board, Loader(engine), answer)
        assert board.text() == "asthma; a faith"
        assert outcome.asked == {"health": 1}
        assert outcome.generalized == 1

    def test_generalized_phrase_is_translated_too(self):
        engine = engine_with(
            "  health:    { real: [asthma], generalized: a condition Jane Doe has, policy: GENERALIZE }"
        )
        board = board_with("asthma")
        commands.sanitize(board, Loader(engine))
        assert board.text() == "a condition Alex Smith has"

    def test_from_selection_deny_clears_the_clipboard_not_the_selection(self, engine):
        board = Recording({"text/plain": b"older"}, primary={"text/plain": SENSITIVE_TEXT.encode()})
        outcome = commands.from_selection(board, Loader(engine), Answer(Decision.DENY))
        assert outcome.skipped is Skip.DENIED
        assert board.offers[Selection.CLIPBOARD] is None
        assert board.offers[Selection.PRIMARY] == {"text/plain": SENSITIVE_TEXT.encode()}

    def test_restore_never_asks(self, engine):
        board, answer = board_with("Alex Smith has asthma."), Answer(Decision.DENY)
        commands.restore(board, Loader(engine))
        assert answer.calls == []
        assert board.text() == "Jane Doe has asthma."

    def test_asker_crash_propagates_with_placeholder_in_place(self, engine):
        board = board_with(SENSITIVE_TEXT)

        def broken(categories, timeout):
            raise RuntimeError

        with pytest.raises(RuntimeError):
            commands.sanitize(board, Loader(engine), broken)
        assert board.text() == WAITING_PLACEHOLDER  # never the original; M2.5 then clears

    def test_clear_failure_on_deny_propagates(self, engine):
        board = board_with(SENSITIVE_TEXT)
        board.fail_clear = True
        with pytest.raises(ClipboardError):
            commands.sanitize(board, Loader(engine), Answer(Decision.DENY))
        assert board.text() == WAITING_PLACEHOLDER

    @given(
        st.lists(st.sampled_from(["asthma", "Jane", "Doe", " ", "x", "\n"]), max_size=15),
        st.sampled_from(list(Decision)),
    )
    def test_property_no_term_survives_generalize_or_deny(self, engine, parts, decision):
        text = "".join(parts)
        board = board_with(text)
        commands.sanitize(board, Loader(engine), Answer(decision))
        result = board.text() or ""
        if decision is not Decision.ALLOW or not engine.sensitive(text):
            assert not engine.sensitive(result)


# ── messages ──────────────────────────────────────────────────────────────────


class TestMessages:
    def test_prompt(self):
        assert prompt_message({"religion": 1, "health": 2}, 120) == Message(
            "veil: sensitive detail. Send it?",
            "health 2, religion 1\nAllow: send as is. Generalize: use your generic phrase. Deny: clear the clipboard.\nNo answer in 120 s = Deny.",
            Urgency.CRITICAL,
            "dialog-question",
        )

    def test_denied(self):
        outcome = Outcome(Action.SANITIZE, Skip.DENIED, asked={"health": 1}, decision=Decision.DENY)
        assert messages.stderr_lines(outcome) == [
            "veil: clipboard NOT sanitized: sensitive detail withheld (health 1); clipboard cleared"
        ]
        assert messages.notification(outcome) == Message(
            "veil: withheld, clipboard cleared",
            "Sensitive: health 1. Nothing to paste.",
            Urgency.NORMAL,
        )

    def test_allowed(self):
        outcome = Outcome(
            Action.SANITIZE, replaced={"name": 1}, asked={"health": 1}, decision=Decision.ALLOW
        )
        assert messages.stderr_lines(outcome) == [
            "veil: sanitized: 1 replacement(s) (name 1); clipboard holds plain text only",
            "veil: sensitive sent as is (health 1).",
        ]
        assert messages.notification(outcome).body == (
            "name 1\nSensitive sent as is (health 1).\nPlain text only. Ready to paste."
        )

    def test_allowed_with_auto_generalized(self):
        outcome = Outcome(
            Action.SANITIZE, asked={"health": 1}, decision=Decision.ALLOW, generalized=2
        )
        assert (
            "Sensitive sent as is (health 1). 2 other detail(s) generalized."
            in messages.notification(outcome).body
        )

    def test_generalized(self):
        outcome = Outcome(
            Action.SANITIZE,
            replaced={"name": 1},
            asked={"health": 1},
            decision=Decision.GENERALIZE,
            generalized=1,
        )
        assert messages.stderr_lines(outcome)[1] == "veil: generalized 1 sensitive detail(s)."
        assert "Generalized 1 sensitive detail(s)." in messages.notification(outcome).body


# ── askers ────────────────────────────────────────────────────────────────────


class Capture:
    def __init__(self, stdout=b"", rc=0, error=None):
        self.stdout, self.rc, self.error, self.calls = stdout, rc, error, []

    def __call__(self, argv, *, timeout, limit):
        self.calls.append((argv, timeout, limit))
        if self.error:
            raise self.error
        return Captured(self.rc, self.stdout, b"")


class TestNotifyAsker:
    def test_argv(self):
        argv = NotifyAsker("/n").argv({"health": 1}, 120)
        assert argv[:7] == [
            "/n", "--app-name=veil", "--urgency=critical", "--icon=dialog-question",
            "--transient", "--wait", "--expire-time=120000",
        ]  # fmt: skip
        assert argv[7:10] == [
            "--action=allow=Allow",
            "--action=generalize=Generalize",
            "--action=deny=Deny",
        ]
        assert argv[10] == "--"
        assert "asthma" not in " ".join(argv)

    @pytest.mark.parametrize(
        ("stdout", "decision"),
        [
            (b"allow\n", Decision.ALLOW),
            (b"generalize\n", Decision.GENERALIZE),
            (b"deny\n", Decision.DENY),
            (b"", Decision.DENY),  # closed without choosing
            (b"0\n", Decision.DENY),
            (b"ALLOW\n", Decision.DENY),
            (b"allow-ish\n", Decision.DENY),
            (b"\xff\xfe", Decision.DENY),
        ],
    )
    def test_replies(self, stdout, decision):
        assert NotifyAsker("/n", capture=Capture(stdout))({"health": 1}, 5) is decision

    def test_failure_and_timeout_deny(self):
        assert NotifyAsker("/n", capture=Capture(b"allow\n", rc=1))({"h": 1}, 5) is Decision.DENY
        error = ClipboardError("the clipboard tool timed out")
        assert NotifyAsker("/n", capture=Capture(error=error))({"h": 1}, 5) is Decision.DENY

    def test_waits_the_timeout_plus_grace(self):
        capture = Capture(b"deny\n")
        NotifyAsker("/n", capture=capture)({"h": 1}, 30)
        assert capture.calls[0][1] == 30 + notifymod.GRACE_SECONDS

    def test_real_process_answer(self, tmp_path):
        script = tmp_path / "fake-notify-send"
        script.write_text(f"#!{sys.executable}\nprint('generalize')\n")
        script.chmod(0o700)
        assert NotifyAsker(str(script))({"health": 1}, 5) is Decision.GENERALIZE

    def test_real_process_that_never_answers_is_denied(self, tmp_path, monkeypatch):
        monkeypatch.setattr(notifymod, "GRACE_SECONDS", 0)
        script = tmp_path / "fake-notify-send"
        script.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\n")
        script.chmod(0o700)
        start = time.monotonic()
        assert NotifyAsker(str(script))({"health": 1}, 1) is Decision.DENY
        assert time.monotonic() - start < 10

    def test_missing_binary_denies(self, tmp_path):
        assert NotifyAsker(str(tmp_path / "nope"))({"h": 1}, 1) is Decision.DENY

    def test_detect(self):
        assert isinstance(real_detect(lambda name: "/usr/bin/" + name), NotifyAsker)
        assert real_detect(lambda name: None) is deny_all
        assert deny_all({"h": 1}, 1) is Decision.DENY

    def test_actions_are_the_three_decisions(self):
        assert [d for d, _ in ACTIONS] == list(Decision)


class TestTerminalAsker:
    @pytest.mark.parametrize(
        ("key", "decision"),
        [
            ("a", Decision.ALLOW),
            ("g", Decision.GENERALIZE),
            ("d", Decision.DENY),
            ("x", Decision.DENY),
        ],
    )
    def test_choice(self, monkeypatch, key, decision):
        seen = {}

        def choose(prompt, options, *, default, attempts=5):
            seen.update(prompt=prompt, default=default)
            return key

        monkeypatch.setattr(ui, "choose", choose)
        assert TerminalAsker()({"health": 2}, 120) is decision
        assert seen["default"] == "d"
        assert "health 2" in seen["prompt"]


# ── CLI ───────────────────────────────────────────────────────────────────────


@pytest.fixture
def board(monkeypatch):
    holder = Recording()
    monkeypatch.setattr(clipio, "detect", lambda: holder)
    return holder


@pytest.mark.usefixtures("imported")
class TestCli:
    @pytest.mark.parametrize(
        ("answer", "result"),
        [
            ("allow", "Alex Smith has asthma.\n"),
            ("generalize", "Alex Smith has a chronic condition.\n"),
            ("deny", None),
        ],
    )
    def test_answers(self, board, capsys, asker, notifications, answer, result):
        asker.answer = answer
        board.offers[Selection.CLIPBOARD] = {"text/plain": SENSITIVE_TEXT.encode()}
        code, out, err = run(capsys, "sanitize")
        assert code == ExitCode.OK
        assert board.text() == result
        assert asker.questions == [({"health": 1}, 120)]
        for text in (out, err, notifications[-1].summary, notifications[-1].body):
            assert "asthma" not in text.lower()
            assert "Jane" not in text

    def test_no_notify_without_a_terminal_denies_without_asking(self, board, capsys, asker):
        board.offers[Selection.CLIPBOARD] = {"text/plain": SENSITIVE_TEXT.encode()}
        code, _, err = run(capsys, "sanitize", "--no-notify")
        assert code == ExitCode.OK
        assert asker.questions == []
        assert board.offers[Selection.CLIPBOARD] is None
        assert "withheld" in err

    def test_no_notify_in_a_terminal_asks_there(self, board, capsys, monkeypatch, asker):
        monkeypatch.setattr(ui, "stdin_is_tty", lambda: True)
        monkeypatch.setattr(ui, "stdout_is_tty", lambda: True)
        monkeypatch.setattr(ui, "choose", lambda *a, **k: "g")
        board.offers[Selection.CLIPBOARD] = {"text/plain": SENSITIVE_TEXT.encode()}
        assert run(capsys, "sanitize", "--no-notify")[0] == ExitCode.OK
        assert board.text() == "Alex Smith has a chronic condition.\n"
        assert asker.questions == []

    def test_from_selection_asks(self, board, capsys, asker):
        asker.answer = "allow"
        board.offers[Selection.PRIMARY] = {"text/plain": b"asthma"}
        assert run(capsys, "from-selection")[0] == ExitCode.OK
        assert board.text() == "asthma"
        assert len(asker.questions) == 1

    def test_restore_does_not_ask(self, board, capsys, asker):
        board.offers[Selection.CLIPBOARD] = {"text/plain": b"Alex Smith has asthma."}
        assert run(capsys, "restore")[0] == ExitCode.OK
        assert asker.questions == []
