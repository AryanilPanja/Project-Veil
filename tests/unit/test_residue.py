"""Fake-residue warning (M2.7): leftover pieces of fake person names that reverse can't restore.

Synthetic persona: Jane Doe → Alex Smith, family Sam/Kim Smith, mother's maiden name Lane,
friend Ravi Kumar → Om Prakash. Counts and kinds only ever leave the engine.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.helpers.fakeclip import FakeBoard
from tests.unit.test_clip_commands import Loader, assert_no_reals, run
from tests.unit.test_clip_commands import board as board
from tests.unit.test_clip_commands import engine as engine
from tests.unit.test_textcmd import imported  # noqa: F401 - pytest fixture
from tests.unit.test_textcmd import run as run_text
from veil.clip import commands, messages
from veil.clip.commands import Action, Outcome
from veil.clip.io import Selection
from veil.engine import residue
from veil.engine.residue import MIN_LETTERS, Residue
from veil.exitcodes import ExitCode

FAKE_NAMES = ("Alex", "Smith", "Lane", "Prakash")
REAL_NAMES = ("Jane", "Doe", "Roe", "Ravi", "Kumar")


def total(counts: dict[str, int]) -> int:
    return sum(counts.values())


# ── what counts ───────────────────────────────────────────────────────────────


class TestFound:
    @pytest.mark.parametrize(
        "text",
        [
            "Smit said hi",  # shortening
            "SMIT",
            "Prak and the team",
            "Alexsmithx wrote it",  # glued, unrestorable
            "Smithy",
            "prakash99x",
            "A. Smith",  # an initial no real name starts with
            "A." + chr(0xA0) + "Smith",  # no-break space
            "the Lanes came",  # glued: counted even when it is an ordinary plural
        ],
    )
    def test_one_leftover(self, engine, text):
        assert total(engine.residue(text)) == 1, text

    def test_counts_add_up(self, engine):
        assert total(engine.residue("Smit, Prak and Alexsmithx")) == 3

    def test_kinds(self, engine):
        counts = engine.residue("Smit and Prak")
        assert set(counts) <= {"name", "person_name"}
        assert total(counts) == 2

    def test_indic_glued(self, engine):
        # The Bengali fake given name glued to a suffix: a leftover unless reverse restores it.
        bengali = "".join(
            chr(c) for c in (0x985, 0x9CD, 0x9AF, 0x9BE, 0x9B2, 0x9C7, 0x995, 0x9CD, 0x9B8)
        )
        for text in (bengali + "x", bengali + chr(0x995)):
            expected = 0 if engine.reverse(text) != text else 1
            assert total(engine.residue(text)) == expected, len(text)


class TestNotFound:
    @pytest.mark.parametrize(
        "text",
        [
            "",
            "nothing personal here",
            "Alex Smith wrote this.",  # restored in full
            "alex.smith@abc.example.test",
            "see alex_test_db and alexsmith99",  # restored; "99" is left, not a name piece
            "smith-dev",
            "AlexSmith",
            "J. Smith",  # the real initial: "J. Doe" is right
            "D. Smith",
            "Alex Smith Stadium is big",  # never_reverse
            "Smi",  # under 4 letters
            "Al",
            "Ruby and Julia",  # never_translate
            "Mochi Bruno",  # pet names are not person names
            "planet",  # a fake name inside a word (not at its start) is not counted
            "A.Smith",  # a declared username form: restored
        ],
    )
    def test_none(self, engine, text):
        assert engine.residue(text) == {}, text

    def test_real_text_has_none(self, engine):
        assert engine.residue("Jane Doe, Ravi Kumar's friend, wrote to Roe.") == {}


class TestResidueIndex:
    def test_repr_holds_no_values(self, engine):
        index = Residue(engine.lexicon.reverse)
        assert repr(index).startswith("Residue(words=")
        for name in (*FAKE_NAMES, *REAL_NAMES):
            assert name.lower() not in repr(index).lower()

    def test_only_long_words(self, engine):
        index = Residue(engine.lexicon.reverse)
        assert all(len(w) >= MIN_LETTERS for w in index.words)
        assert "al" not in index.words

    def test_empty_lexicon(self):
        assert Residue(()).count("Smit A. Smith", [], [(3, 8)]) == {}

    def test_shared_initials_are_dropped(self, engine):
        index = Residue(engine.lexicon.reverse)
        assert "j" not in index.initials  # Jane
        assert "d" not in index.initials  # Doe
        assert "a" in index.initials  # Alex


class TestWarning:
    def test_none_when_clean(self):
        assert residue.warning({}) is None
        assert residue.warning({"name": 0}) is None

    def test_text(self):
        assert residue.warning({"name": 2, "person_name": 1}) == (
            "veil: warning: 3 leftover piece(s) of fake names not restored (your name 2, "
            "other people's names 1): shortened or joined forms reverse can't map; "
            "check the text before using it"
        )


# ── properties ────────────────────────────────────────────────────────────────

FILLER = st.sampled_from(["the", "plan", "works", "and", "data", "is", "ok", "42", "x_y", "e.g."])
SEPARATORS = st.sampled_from([" ", "\n", ", ", ". ", "\t"])


@given(st.lists(st.tuples(FILLER, SEPARATORS), max_size=20))
def test_property_ordinary_text_is_clean(engine, parts):
    assert engine.residue("".join(w + s for w, s in parts)) == {}


@given(
    st.lists(
        st.tuples(st.sampled_from(["Jane", "Doe", "Jane Doe", "the", "met"]), SEPARATORS),
        max_size=12,
    )
)
def test_property_translated_text_is_clean(engine, parts):
    # forward output reverses in full: nothing may be left over.
    real = "".join(w + s for w, s in parts)
    assert engine.residue(engine.forward(real)) == {}


@given(
    name=st.sampled_from(FAKE_NAMES),
    suffix=st.text(st.sampled_from("qxz"), min_size=1, max_size=4),
    before=FILLER,
)
def test_property_glued_fake_names_are_found(engine, name, suffix, before):
    text = f"{before} {name}{suffix} {before}"
    if engine.reverse(text) == text:  # reverse left it alone, so it's a leftover
        assert total(engine.residue(text)) >= 1


@given(name=st.sampled_from(FAKE_NAMES), data=st.data())
def test_property_shortenings_are_found(engine, name, data):
    if len(name) <= MIN_LETTERS:
        return
    end = data.draw(st.integers(MIN_LETTERS, len(name) - 1))
    assert total(engine.residue(f"ask {name[:end]} today")) == 1


@given(st.text(max_size=60))
def test_property_never_raises_and_bounded(engine, text):
    counts = engine.residue(text)
    assert set(counts) <= {"name", "person_name"}
    assert total(counts) <= len(text)


# ── restore and reverse ───────────────────────────────────────────────────────


class TestRestore:
    def test_outcome_counts(self, engine):
        board = FakeBoard.with_text("Alex Smith and Smit")
        outcome = commands.restore(board, Loader(engine))
        assert board.text() == "Jane Doe and Smit"
        assert total(outcome.residue) == 1

    def test_clean_restore(self, engine):
        outcome = commands.restore(FakeBoard.with_text("Alex Smith"), Loader(engine))
        assert outcome.residue == {}

    def test_messages(self):
        outcome = Outcome(Action.RESTORE, replaced={"name": 2}, residue={"name": 1})
        lines = messages.stderr_lines(outcome)
        assert lines[-1].startswith("veil: warning: 1 leftover piece(s) of fake names")
        assert messages.notification(outcome).body.endswith(
            "Check: 1 leftover fake-name piece(s) not restored."
        )

    def test_messages_nothing_restored(self):
        outcome = Outcome(Action.RESTORE, residue={"person_name": 2})
        message = messages.notification(outcome)
        assert message.summary == "veil: nothing to restore"
        assert message.body.endswith("Check: 2 leftover fake-name piece(s) not restored.")

    def test_sanitize_never_reports_residue(self, engine):
        outcome = commands.sanitize(FakeBoard.with_text("Smit wrote"), Loader(engine))
        assert outcome.residue == {}

    @pytest.mark.usefixtures("imported")
    def test_cli(self, board, capsys, notifications):
        board.offers[Selection.CLIPBOARD] = {"text/plain": b"Alex Smith met Prak."}
        code, _, err = run(capsys, "restore")
        assert code == ExitCode.OK
        assert "warning: 1 leftover piece(s) of fake names" in err
        assert notifications[-1].body.endswith("not restored.")
        for fake in FAKE_NAMES:
            assert fake not in err
            assert fake not in notifications[-1].body
        assert_no_reals(err, notifications[-1].body)


class TestReverseCommand:
    @pytest.mark.usefixtures("imported")
    def test_warns_on_stderr(self, monkeypatch, capsys):
        code, out, err = run_text(monkeypatch, capsys, "reverse", "Alex Smith met Prak.\n")
        assert code == ExitCode.OK
        assert out == "Jane Doe met Prak.\n"
        assert "warning: 1 leftover piece(s) of fake names" in err
        for name in (*FAKE_NAMES, *REAL_NAMES):
            assert name not in err

    @pytest.mark.usefixtures("imported")
    def test_clean_is_silent(self, monkeypatch, capsys):
        code, _, err = run_text(monkeypatch, capsys, "reverse", "Alex Smith\n")
        assert code == ExitCode.OK
        assert "leftover" not in err
