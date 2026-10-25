"""`veil clip sanitize | from-selection | restore` (M2.2). In-memory clipboard, synthetic persona.

Two layers: the command functions over an engine built straight from the fixture (fast, and
property-testable), and the CLI end to end over an imported synthetic store.
"""

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from tests.helpers.fakeclip import FakeBoard
from tests.unit.test_matcher import FIXTURE, lexicon_from
from tests.unit.test_textcmd import imported  # noqa: F401 - pytest fixture
from veil import cli
from veil.clip import commands
from veil.clip import io as clipio
from veil.clip.commands import Action, Outcome, Skip
from veil.clip.io import Selection
from veil.engine.matcher import Engine
from veil.errors import ClipboardError, KeyUnavailable
from veil.exitcodes import ExitCode

REAL = "Hi, I'm Jane Doe (jane.doe@xyz.example.test), MS thesis at XYZIT.\nFiles: /home/janed/jane-thesis/main.tex\n"
FAKE = "Hi, I'm Alex Smith (alex.smith@abc.example.test), PhD thesis at ABCU.\nFiles: /home/alexs/alex-thesis/main.tex\n"
REALS = ("Jane", "Doe", "jane.doe", "xyz.example", "XYZIT", "janed", "jane-thesis", "MS thesis")
FAKES = ("Alex", "Smith", "alex.smith", "abc.example", "ABCU", "alexs", "alex-thesis")
HTML = '<p>Mail <a href="mailto:jane.doe@xyz.example.test">me</a></p>'


@pytest.fixture(scope="module")
def engine() -> Engine:
    return Engine(lexicon_from(FIXTURE.read_text(encoding="utf-8")))


class Loader:
    """Counts engine loads: a skipped clipboard must not decrypt the persona."""

    def __init__(self, engine=None, error: Exception | None = None) -> None:
        self.engine, self.error, self.calls = engine, error, 0

    def __call__(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.engine


def assert_no_reals(*texts: str) -> None:
    for text in texts:
        for real in REALS:
            assert real.lower() not in text.lower(), real


# ── sanitize ──────────────────────────────────────────────────────────────────


class TestSanitize:
    def test_replaces_and_writes_plain_text(self, engine):
        board = FakeBoard.with_text(REAL)
        outcome = commands.sanitize(board, Loader(engine))
        assert board.writes == [FAKE]
        assert board.types() == ["text/plain"]
        assert outcome.changed
        assert outcome.action is Action.SANITIZE
        assert outcome.replaced == {
            "name": 1,
            "email": 1,
            "class_term": 1,
            "org": 1,
            "path": 1,
            "token": 1,
        }
        assert outcome.total == 6

    def test_rich_types_are_dropped(self, engine):
        board = FakeBoard.with_text(REAL, html=HTML)
        commands.sanitize(board, Loader(engine))
        assert board.types() == ["text/plain"]
        assert_no_reals(board.text())

    def test_written_back_even_without_replacements(self, engine):
        # The HTML carries a real address the plain text doesn't show: it must not survive.
        board = FakeBoard.with_text("Mail me", html=HTML)
        outcome = commands.sanitize(board, Loader(engine))
        assert board.writes == ["Mail me"]
        assert board.types() == ["text/plain"]
        assert outcome.changed
        assert outcome.total == 0

    @pytest.mark.parametrize("text", ["", "\n", "  \t", "no details here"])
    def test_texts_without_details_are_kept_exactly(self, engine, text):
        board = FakeBoard.with_text(text)
        commands.sanitize(board, Loader(engine))
        assert board.writes == [text]

    def test_bytes_outside_replacements_are_identical(self, engine):
        text = "\r\n  Jane Doe\t\x00 ﬁn ＱＪ \N{ZERO WIDTH JOINER}\n\n"
        board = FakeBoard.with_text(text)
        commands.sanitize(board, Loader(engine))
        assert board.writes == [text.replace("Jane Doe", "Alex Smith")]

    def test_indic_scripts(self, engine):
        text = "জেন, जेन\n"
        board = FakeBoard.with_text(text)
        outcome = commands.sanitize(board, Loader(engine))
        assert "জেন" not in board.writes[0]
        assert "जेन" not in board.writes[0]
        assert outcome.replaced == {"name": 2}

    def test_preexisting_fake_forms_are_counted(self, engine):
        outcome = commands.sanitize(FakeBoard.with_text("Alex Smith met Jane Doe"), Loader(engine))
        assert outcome.preexisting_fakes >= 1
        assert commands.warnings(outcome)

    def test_large_text(self, engine):
        text = REAL * 2000  # ~240 KB
        board = FakeBoard.with_text(text)
        outcome = commands.sanitize(board, Loader(engine))
        assert board.writes == [FAKE * 2000]
        assert outcome.total == 6 * 2000

    @pytest.mark.parametrize(
        ("offer", "skip"),
        [
            (None, Skip.EMPTY),
            ({"image/png": b"\x89PNG"}, Skip.NON_TEXT),
            ({"text/html": HTML.encode()}, Skip.RICH_ONLY),
            ({"text/rtf": b"{\\rtf1 Jane Doe}"}, Skip.RICH_ONLY),
            ({"text/plain": b"Jane", "x-kde-passwordManagerHint": b"secret"}, Skip.SECRET),
        ],
    )
    def test_left_unchanged_without_loading_the_persona(self, offer, skip):
        board = FakeBoard(offer)
        before = dict(offer) if offer else None
        load = Loader(error=AssertionError("must not load"))
        outcome = commands.sanitize(board, load)
        assert outcome == Outcome(Action.SANITIZE, skip)
        assert not outcome.changed
        assert load.calls == 0
        assert board.writes == []
        assert board.clears == []
        assert board.offers[Selection.CLIPBOARD] == before

    def test_reads_clipboard_never_primary(self, engine):
        board = FakeBoard.with_text(REAL, primary={"text/plain": b"other"})
        commands.sanitize(board, Loader(engine))
        assert board.reads == [Selection.CLIPBOARD]
        assert board.offers[Selection.PRIMARY] == {"text/plain": b"other"}

    def test_engine_failure_writes_nothing(self):
        board = FakeBoard.with_text(REAL)
        with pytest.raises(KeyUnavailable):
            commands.sanitize(board, Loader(error=KeyUnavailable("the keyring is locked")))
        assert board.writes == []

    def test_engine_crash_mid_translation_writes_nothing(self, engine, monkeypatch):
        board = FakeBoard.with_text(REAL)

        def boom(text):
            raise RuntimeError

        monkeypatch.setattr(engine, "forward_counted", boom)
        with pytest.raises(RuntimeError):
            commands.sanitize(board, Loader(engine))
        assert board.writes == []

    def test_read_and_write_errors_propagate(self, engine):
        board = FakeBoard.with_text(REAL)
        board.fail_read = True
        with pytest.raises(ClipboardError):
            commands.sanitize(board, Loader(engine))
        board = FakeBoard.with_text(REAL)
        board.fail_write = True
        with pytest.raises(ClipboardError):
            commands.sanitize(board, Loader(engine))


# ── from-selection ────────────────────────────────────────────────────────────


class TestFromSelection:
    def test_primary_into_clipboard(self, engine):
        board = FakeBoard({"text/plain": b"old clipboard"}, primary={"text/plain": REAL.encode()})
        outcome = commands.from_selection(board, Loader(engine))
        assert board.reads == [Selection.PRIMARY]
        assert board.text() == FAKE
        assert board.types() == ["text/plain"]
        assert board.offers[Selection.PRIMARY] == {"text/plain": REAL.encode()}  # untouched
        assert outcome.action is Action.FROM_SELECTION
        assert outcome.total == 6

    def test_nothing_selected_leaves_clipboard(self):
        board = FakeBoard({"text/plain": b"keep"}, primary=None)
        load = Loader(error=AssertionError("must not load"))
        outcome = commands.from_selection(board, load)
        assert outcome.skipped is Skip.NOTHING_SELECTED
        assert board.text() == "keep"
        assert load.calls == 0

    def test_rich_only_selection(self):
        board = FakeBoard(None, primary={"text/html": b"<b>x</b>"})
        assert commands.from_selection(board, Loader()).skipped is Skip.RICH_ONLY


# ── restore ───────────────────────────────────────────────────────────────────


class TestRestore:
    def test_round_trip(self, engine):
        board = FakeBoard.with_text(REAL)
        commands.sanitize(board, Loader(engine))
        outcome = commands.restore(board, Loader(engine))
        assert board.text() == REAL
        assert outcome.action is Action.RESTORE
        assert outcome.total == 6
        assert outcome.preexisting_fakes == 0

    def test_restore_writes_plain_text_only(self, engine):
        board = FakeBoard.with_text(FAKE, html="<b>Alex Smith</b>")
        commands.restore(board, Loader(engine))
        assert board.types() == ["text/plain"]

    def test_nothing_to_restore_is_written_back_unchanged(self, engine):
        board = FakeBoard.with_text("plain answer\n")
        outcome = commands.restore(board, Loader(engine))
        assert board.writes == ["plain answer\n"]
        assert outcome.total == 0

    @pytest.mark.parametrize(
        "text",
        ["doeJane", "Doe jane", "JANE.doe", "JaneDOE", "Jane\nDoe", "jane\t doe", "Jane\xa0Doe"],
    )
    def test_case_and_whitespace_round_trip_exactly(self, engine, text):
        # Board Q15 (fixed): per-word case and whitespace inside a match come back exactly.
        board = FakeBoard.with_text(text)
        commands.sanitize(board, Loader(engine))
        assert_no_reals(board.text())
        commands.restore(board, Loader(engine))
        assert board.text() == text

    @pytest.mark.parametrize(
        ("offer", "skip"),
        [
            (None, Skip.EMPTY),
            ({"image/png": b"x"}, Skip.NON_TEXT),
            ({"text/html": b"<b>Alex</b>"}, Skip.RICH_ONLY),
            ({"text/plain": b"x", "x-kde-passwordManagerHint": b"secret"}, Skip.SECRET),
        ],
    )
    def test_skips(self, offer, skip):
        board = FakeBoard(offer)
        load = Loader(error=AssertionError("must not load"))
        assert commands.restore(board, load).skipped is skip
        assert load.calls == 0
        assert board.writes == []

    PARTS = st.lists(
        st.sampled_from([*REALS, "jane.doe@xyz.example.test", ",", "hello", "জেন", "(", "2024"]),
        max_size=25,
    )

    @given(
        PARTS,
        st.lists(st.sampled_from([str.lower, str.upper, str.capitalize, str]), min_size=25),
        st.sampled_from([" ", ", ", "\n", "\t", "\xa0", " \r\n"]),
    )
    def test_property_round_trip_exact(self, engine, parts, cases, sep):
        # Any case per part, any whitespace between parts (spec §4.3, board Q15).
        text = sep.join(case(p) for p, case in zip(parts, cases, strict=False))
        assume(not engine.ambiguous(text))  # no fake forms in the input (spec §4.3)
        board = FakeBoard.with_text(text)
        commands.sanitize(board, Loader(engine))
        commands.restore(board, Loader(engine))
        assert board.text() == text

    @given(PARTS)
    def test_property_round_trip_keeps_letters_when_glued(self, engine, parts):
        # Glued parts with no visible word boundary ("JANEdoe") can come back in another case;
        # the letters always come back.
        text = "".join(parts)
        assume(not engine.ambiguous(text))
        board = FakeBoard.with_text(text)
        commands.sanitize(board, Loader(engine))
        commands.restore(board, Loader(engine))
        assert board.text().casefold().split() == text.casefold().split()


# ── messages ──────────────────────────────────────────────────────────────────


class TestSummary:
    def test_sanitized(self):
        line = commands.summary(
            Outcome(Action.SANITIZE, replaced={"email": 1, "name": 3, "path": 1})
        )
        assert (
            line
            == "veil: sanitized: 5 replacement(s) (name 3, email 1, path 1); clipboard holds plain text only"
        )

    def test_sanitized_nothing_found(self):
        assert commands.summary(Outcome(Action.SANITIZE)) == (
            "veil: sanitized: no personal details; clipboard holds plain text only"
        )

    def test_from_selection(self):
        assert "sanitized from the selection: 1 replacement(s) (org 1)" in commands.summary(
            Outcome(Action.FROM_SELECTION, replaced={"org": 1})
        )

    def test_restored(self):
        assert commands.summary(Outcome(Action.RESTORE, replaced={"name": 2})) == (
            "veil: restored 2 detail(s) (name 2)"
        )

    @pytest.mark.parametrize("skip", list(Skip))
    @pytest.mark.parametrize("action", list(Action))
    def test_skipped(self, action, skip):
        line = commands.summary(Outcome(action, skip))
        assert "NOT" in line
        assert skip.value in line
        assert "left unchanged" in line

    def test_no_warning_without_preexisting_fakes(self):
        assert commands.warnings(Outcome(Action.SANITIZE)) == []

    @given(
        st.dictionaries(st.sampled_from(["name", "email", "path", "org"]), st.integers(1, 10**6))
    )
    def test_counts_add_up(self, replaced):
        line = commands.summary(Outcome(Action.SANITIZE, replaced=replaced))
        if replaced:
            assert f"{sum(replaced.values())} replacement(s)" in line


# ── CLI end to end (imported synthetic store) ─────────────────────────────────


@pytest.fixture
def board(monkeypatch):
    holder = FakeBoard()
    monkeypatch.setattr(clipio, "detect", lambda: holder)
    return holder


def run(capsys, *args: str):
    code = cli.main(["clip", *args])
    out, err = capsys.readouterr()
    return code, out, err


class TestCli:
    @pytest.mark.usefixtures("imported")
    def test_sanitize(self, board, capsys):
        board.offers[Selection.CLIPBOARD] = FakeBoard.with_text(REAL, html=HTML).offers[
            Selection.CLIPBOARD
        ]
        code, out, err = run(capsys, "sanitize")
        assert code == ExitCode.OK
        assert out == ""
        assert err.startswith("veil: sanitized: 6 replacement(s)")
        assert board.text() == FAKE
        assert board.types() == ["text/plain"]
        assert_no_reals(out, err, board.text())

    @pytest.mark.usefixtures("imported")
    def test_restore_round_trip(self, board, capsys):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        assert run(capsys, "sanitize")[0] == ExitCode.OK
        code, out, err = run(capsys, "restore")
        assert code == ExitCode.OK
        assert board.text() == REAL
        assert (
            err
            == "veil: restored 6 detail(s) (class_term 1, email 1, name 1, org 1, path 1, token 1)\n"
        )
        assert_no_reals(out, err)

    @pytest.mark.usefixtures("imported")
    def test_from_selection(self, board, capsys):
        board.offers[Selection.PRIMARY] = {"text/plain": REAL.encode()}
        code, _, err = run(capsys, "from-selection")
        assert code == ExitCode.OK
        assert board.text() == FAKE
        assert "from the selection" in err

    @pytest.mark.usefixtures("imported")
    def test_full_store_details(self, board, capsys):
        # Generated fakes (phone, roll number, date) come from the vault, not the fixture.
        text = "Call +91 90000 00001. Roll 2024701001. Born 14/03/2001.\n"
        board.offers[Selection.CLIPBOARD] = {"text/plain": text.encode()}
        assert run(capsys, "sanitize")[0] == ExitCode.OK
        for real in ("90000 00001", "2024701001", "14/03/2001"):
            assert real not in board.text()
        assert run(capsys, "restore")[0] == ExitCode.OK
        assert board.text() == text

    @pytest.mark.usefixtures("imported")
    def test_preexisting_fake_warning_is_value_free(self, board, capsys):
        board.offers[Selection.CLIPBOARD] = {"text/plain": b"Alex Smith and Jane Doe"}
        _, _, err = run(capsys, "sanitize")
        assert "warning: the text already contained" in err
        for fake in FAKES:
            assert fake not in err

    def test_skipped_does_not_need_a_store(self, board, capsys):
        # No store and no keyring: a skipped clipboard never touches either.
        board.offers[Selection.CLIPBOARD] = {"image/png": b"x"}
        code, _, err = run(capsys, "sanitize")
        assert code == ExitCode.OK
        assert "NOT sanitized: no plain text (an image or a file)" in err

    def test_no_store_is_an_error_and_nothing_written(self, board, capsys):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        code, out, err = run(capsys, "sanitize")
        assert code not in (ExitCode.OK, ExitCode.INTERNAL)
        assert board.writes == []
        assert_no_reals(out, err)

    @pytest.mark.usefixtures("imported")
    def test_clipboard_failure_exit_code(self, board, capsys):
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        board.fail_write = True
        code, out, err = run(capsys, "sanitize")
        assert code == ExitCode.CLIPBOARD
        assert err == "veil: wl-copy failed (exit 1)\n"
        assert_no_reals(out, err)

    def test_no_clipboard_tool(self, monkeypatch, capsys):
        monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
        monkeypatch.delenv("DISPLAY", raising=False)
        code, _, err = run(capsys, "sanitize")
        assert code == ExitCode.CLIPBOARD
        assert "no clipboard tool found" in err

    def test_clip_without_subcommand_shows_help(self, capsys):
        with pytest.raises(SystemExit) as caught:
            cli.main(["clip"])
        assert caught.value.code == 0
        assert "sanitize" in capsys.readouterr().out

    def test_unknown_subcommand(self, capsys):
        with pytest.raises(SystemExit) as caught:
            cli.main(["clip", "nope"])
        assert caught.value.code == ExitCode.USAGE

    @pytest.mark.usefixtures("imported")
    def test_timings_are_value_free(self, board, capsys, monkeypatch):
        from veil import timing

        monkeypatch.setattr(timing.STAGES, "enabled", True)
        monkeypatch.setattr(timing.STAGES, "_marks", [])
        board.offers[Selection.CLIPBOARD] = {"text/plain": REAL.encode()}
        _, _, err = run(capsys, "sanitize")
        assert "timings (ms)" in err
        assert "read" in err
        assert "write" in err
        assert_no_reals(err)
