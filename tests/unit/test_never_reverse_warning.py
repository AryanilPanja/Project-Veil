"""T3 / #34: value-free warning when forward creates a `never_reverse` phrase.

Every persona in this file is invented for tests; the clipboard is in memory and notifications
are recorded. Counts and fixed words only ever reach stderr or a notification.
"""

import unicodedata
from dataclasses import replace

import pytest

from tests.helpers.fakeclip import FakeBoard
from tests.unit.test_clip_commands import Loader
from veil import cli
from veil.clip import commands, messages
from veil.clip import io as clipio
from veil.clip.commands import Action
from veil.clip.io import Selection
from veil.engine import residue
from veil.engine.lexicon import build_lexicon
from veil.engine.load import load_engine as real_load_engine
from veil.engine.matcher import Engine
from veil.errors import KeyUnavailable
from veil.exitcodes import ExitCode
from veil.persona.entities import flatten
from veil.persona.schema import parse_persona
from veil.persona.yamlio import load_yaml

PERSONA = """version: "1"
person:
  first_name: { real: Jane, fake: Alex }
  last_name: { real: Doe, fake: Smith }
  full_name: { real: Jane Doe, fake: Alex Smith }
never_reverse:
  - Alex Smith
"""

INDIC_PERSONA = """version: "1"
person:
  name_in_other_scripts:
    - { real: জেন, fake: অ্যালেক্স, allow_short: true }
never_reverse:
  - অ্যালেক্স
"""

REAL_TEXT = "Jane Doe wrote this"
FAKE_TEXT = "Alex Smith wrote this"
ZWS = chr(0x200B)
VALUES = ("Jane", "Doe", "Alex", "Smith", "জেন", "অ্যালেক্স")
LINE = "veil: warning: 1 phrase(s) won't be restored (never_reverse); check the text before sending"
NOTE = "Note: 1 phrase(s) won't be restored (never_reverse)."


def engine_from(text: str) -> Engine:
    return Engine(build_lexicon(flatten(parse_persona(load_yaml(text)))))


@pytest.fixture(scope="module")
def engine() -> Engine:
    return engine_from(PERSONA)


def assert_value_free(*texts: str) -> None:
    for text in texts:
        for value in VALUES:
            assert value.lower() not in text.lower()


# ── the definition: new bounded phrases only ──────────────────────────────────


class TestCount:
    def test_forward_creates_a_phrase(self, engine):
        out = engine.forward(REAL_TEXT)
        assert out == FAKE_TEXT
        assert residue.never_reverse_hits(engine.lexicon, REAL_TEXT, out) == 1

    def test_phrase_already_in_the_input_is_not_new(self, engine):
        assert residue.never_reverse_hits(engine.lexicon, FAKE_TEXT, FAKE_TEXT) == 0

    def test_only_the_increase_counts(self, engine):
        result = residue.never_reverse_hits(engine.lexicon, FAKE_TEXT, "Alex Smith met Alex Smith")
        assert result == 1

    def test_no_entries(self, engine):
        lex = replace(engine.lexicon, never_reverse=frozenset())
        assert residue.never_reverse_hits(lex, "", FAKE_TEXT) == 0

    def test_empty_corrupt_and_unrelated_entries(self, engine):
        lex = replace(
            engine.lexicon,
            never_reverse=frozenset({"", "   ", ZWS, "no such phrase in this text"}),
        )
        assert residue.never_reverse_hits(lex, "", FAKE_TEXT) == 0

    def test_whole_word_boundary(self, engine):
        single = replace(engine.lexicon, never_reverse=frozenset({"Alex"}))
        assert residue.never_reverse_hits(single, "", "Alex's") == 1
        assert residue.never_reverse_hits(single, "", "Alexsmith wrote") == 0
        # Letter→digit is a boundary too (ADR-0026 rule 3): this one is bounded.
        assert residue.never_reverse_hits(single, "", "Alex99") == 1

    def test_invisible_characters_are_ignored(self, engine):
        assert residue.never_reverse_hits(engine.lexicon, "", "A" + ZWS + "lex Smith") == 1

    def test_indic_and_nfd(self):
        engine = engine_from(INDIC_PERSONA)
        fake = engine.forward("জেন")
        assert residue.never_reverse_hits(engine.lexicon, "জেন", fake) == 1
        nfd = unicodedata.normalize("NFD", "অ্যালেক্স")
        assert residue.never_reverse_hits(engine.lexicon, "", nfd) == 1

    def test_empty_input(self, engine):
        assert residue.never_reverse_hits(engine.lexicon, "", "") == 0


# ── the clip paths and their messages ─────────────────────────────────────────


class TestSanitize:
    def test_sanitize_warns_with_counts_only(self, engine):
        board = FakeBoard.with_text(REAL_TEXT)
        outcome = commands.sanitize(board, Loader(engine))
        assert board.text() == FAKE_TEXT
        assert outcome.action is Action.SANITIZE
        assert outcome.never_reverse == 1
        assert messages.stderr_lines(outcome)[-1] == LINE
        note = messages.notification(outcome)
        assert note.body.endswith(NOTE)
        assert_value_free(LINE, note.summary, note.body)

    def test_phrase_already_present_does_not_warn(self, engine):
        outcome = commands.sanitize(FakeBoard.with_text(FAKE_TEXT), Loader(engine))
        assert outcome.never_reverse == 0
        assert all("never_reverse" not in line for line in messages.stderr_lines(outcome))
        assert "never_reverse" not in messages.notification(outcome).body

    def test_no_phrase_does_not_warn(self, engine):
        outcome = commands.sanitize(FakeBoard.with_text("nothing personal here"), Loader(engine))
        assert outcome.never_reverse == 0
        assert all("never_reverse" not in line for line in messages.stderr_lines(outcome))
        assert "never_reverse" not in messages.notification(outcome).body

    def test_empty_input_keeps_text_and_is_quiet(self, engine):
        board = FakeBoard.with_text("")
        outcome = commands.sanitize(board, Loader(engine))
        assert board.writes == [""]
        assert outcome.never_reverse == 0
        assert all("never_reverse" not in line for line in messages.stderr_lines(outcome))

    def test_from_selection_warns(self, engine):
        board = FakeBoard({"text/plain": b"old"}, primary={"text/plain": REAL_TEXT.encode()})
        outcome = commands.from_selection(board, Loader(engine))
        assert board.text() == FAKE_TEXT
        assert board.offers[Selection.PRIMARY] == {"text/plain": REAL_TEXT.encode()}
        assert outcome.never_reverse == 1
        assert messages.stderr_lines(outcome)[-1] == LINE
        assert messages.notification(outcome).body.endswith(NOTE)

    def test_auto_run_warns_and_is_worth_notifying(self, engine):
        board = FakeBoard.with_text(REAL_TEXT)
        outcome = commands.sanitize(board, Loader(engine), auto=True)
        assert outcome.never_reverse == 1
        assert messages.stderr_lines(outcome)[-1] == LINE
        assert messages.worth_notifying(outcome, auto=True) is True
        assert messages.notification(outcome).body.endswith(NOTE)

    def test_warning_does_not_change_the_sanitized_text(self, engine):
        quiet = Engine(replace(engine.lexicon, never_reverse=frozenset()))
        warned = FakeBoard.with_text(REAL_TEXT)
        silent = FakeBoard.with_text(REAL_TEXT)
        with_warning = commands.sanitize(warned, Loader(engine))
        without = commands.sanitize(silent, Loader(quiet))
        assert warned.writes == silent.writes == [FAKE_TEXT]
        assert with_warning.replaced == without.replaced
        assert with_warning.never_reverse == 1
        assert without.never_reverse == 0

    @pytest.mark.parametrize(
        "offer",
        [
            None,
            {"image/png": b"x"},
            {"text/plain": b"x", "x-kde-passwordManagerHint": b"secret"},
        ],
    )
    def test_skipped_clipboard_never_warns_or_loads(self, offer, engine):
        load = Loader(error=AssertionError("must not load"))
        outcome = commands.sanitize(FakeBoard(offer), load)
        assert outcome.skipped is not None
        assert outcome.never_reverse == 0
        assert load.calls == 0
        assert all("never_reverse" not in line for line in messages.stderr_lines(outcome))

    def test_load_error_still_fails_closed(self):
        board = FakeBoard.with_text(REAL_TEXT)
        with pytest.raises(KeyUnavailable):
            commands.sanitize(board, Loader(error=KeyUnavailable("the keyring is locked")))
        assert board.writes == []


# ── end to end through the CLI (no real store, no real desktop) ───────────────


@pytest.fixture
def board(monkeypatch):
    holder = FakeBoard()
    monkeypatch.setattr(clipio, "detect", lambda: holder)
    return holder


def test_cli_reports_a_count_without_values(engine, board, capsys, monkeypatch, notifications):
    from veil.engine import load as load_module

    # The real loader is imported inside the command; replace it with the synthetic engine.
    assert real_load_engine is load_module.load_engine
    monkeypatch.setattr(load_module, "load_engine", lambda *a, **k: engine)
    board.offers[Selection.CLIPBOARD] = FakeBoard.with_text(REAL_TEXT).offers[Selection.CLIPBOARD]
    code = cli.main(["clip", "sanitize"])
    out, err = capsys.readouterr()
    assert code == ExitCode.OK
    assert board.text() == FAKE_TEXT
    assert LINE in err
    assert len(notifications) == 1
    assert notifications[0].body.endswith(NOTE)
    assert_value_free(out, err, notifications[0].summary, notifications[0].body)
