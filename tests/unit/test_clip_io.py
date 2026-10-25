"""Clipboard I/O (M2.1): MIME classification, wl-clipboard and xsel backends, detection.

The real clipboard is never touched: the tools are replaced by fakes that model what
wl-paste / wl-copy / xsel do with an offered type list. Synthetic persona text only.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil.clip import io as clipio
from veil.clip.io import (
    ClipContent,
    Kind,
    Selection,
    WaylandClipboard,
    XselClipboard,
    classify,
    detect,
)
from veil.clip.proc import Captured
from veil.errors import ClipboardError
from veil.exitcodes import ExitCode

SYNTHETIC = "Hi, I'm Jane Doe (jane.doe@xyz.example.test)\n"
INDIC = "জেন ডো · जेन डो · ஜேன் டோ\n"
FIREFOX_TYPES = ["text/html", "text/_moz_htmlinfo", "text/_moz_htmlcontext", "text/plain;charset=utf-8", "text/plain", "TEXT", "STRING", "UTF8_STRING"]  # fmt: skip


class FakeWayland:
    """Models wl-paste/wl-copy: a selection is a dict {mime type: bytes}."""

    def __init__(self, offers: dict[str, bytes] | None = None, primary=None) -> None:
        self.sel = {Selection.CLIPBOARD: offers, Selection.PRIMARY: primary}
        self.calls: list[list[str]] = []
        self.fed: list[bytes] = []
        self.paste_rc: int | None = None  # force a wl-paste exit status
        self.paste_err = b""
        self.copy_rc = 0

    def capture(self, argv, *, timeout, limit):
        self.calls.append(list(argv))
        assert argv[0] == "/usr/bin/wl-paste"
        assert timeout > 0
        offers = self.sel[Selection.PRIMARY if "--primary" in argv else Selection.CLIPBOARD]
        if self.paste_rc is not None:
            return Captured(self.paste_rc, b"", self.paste_err)
        if offers is None:
            return Captured(
                1, b"", b"No selection\n" if "--list-types" in argv else b"Nothing is copied\n"
            )
        if "--list-types" in argv:
            return Captured(0, "".join(f"{t}\n" for t in offers).encode(), b"")
        wanted = argv[argv.index("--type") + 1]
        assert "--no-newline" in argv
        if wanted not in offers:
            return Captured(1, b"", b"Clipboard content is not available as requested type\n")
        data = offers[wanted]
        if len(data) > limit:
            raise ClipboardError(f"the clipboard text is larger than {limit} bytes")
        return Captured(0, data, b"")

    def feed(self, argv, data, *, timeout):
        self.calls.append(list(argv))
        assert argv[0] == "/usr/bin/wl-copy"
        assert timeout > 0
        self.fed.append(data)
        if self.copy_rc:
            return self.copy_rc
        target = Selection.PRIMARY if "--primary" in argv else Selection.CLIPBOARD
        if "--clear" in argv:
            self.sel[target] = None
        else:
            mime = argv[argv.index("--type") + 1]
            self.sel[target] = {mime: data}
        return 0


def wayland(fake: FakeWayland, **kw) -> WaylandClipboard:
    return WaylandClipboard(
        "/usr/bin/wl-paste", "/usr/bin/wl-copy", capture=fake.capture, feed=fake.feed, **kw
    )


def utf8(text: str) -> bytes:
    return text.encode("utf-8")


# ── classify ──────────────────────────────────────────────────────────────────


class TestClassify:
    @pytest.mark.parametrize(
        ("types", "kind", "pick"),
        [
            (FIREFOX_TYPES, Kind.TEXT, "text/plain;charset=utf-8"),
            (["text/html", "text/plain"], Kind.TEXT, "text/plain"),
            (["text/plain", "UTF8_STRING"], Kind.TEXT, "UTF8_STRING"),
            (["STRING", "TEXT"], Kind.TEXT, "STRING"),
            (["TEXT"], Kind.TEXT, "TEXT"),
            (["text/plain; charset=UTF-8"], Kind.TEXT, "text/plain; charset=UTF-8"),
            (["Text/Plain"], Kind.TEXT, "Text/Plain"),
            (["text/html"], Kind.RICH_ONLY, None),
            (["text/html", "text/_moz_htmlinfo"], Kind.RICH_ONLY, None),
            (["text/rtf"], Kind.RICH_ONLY, None),
            (["application/rtf"], Kind.RICH_ONLY, None),
            (["application/x-qt-richtext"], Kind.RICH_ONLY, None),
            (["text/uri-list", "x-special/gnome-copied-files"], Kind.RICH_ONLY, None),
            (["image/png"], Kind.NON_TEXT, None),
            (["image/png", "image/jpeg", "application/x-qt-image"], Kind.NON_TEXT, None),
            (["application/octet-stream"], Kind.NON_TEXT, None),
            (["image/png", "text/html"], Kind.RICH_ONLY, None),
            ([], Kind.EMPTY, None),
            (["", "   "], Kind.EMPTY, None),
            (["TARGETS", "TIMESTAMP", "MULTIPLE"], Kind.EMPTY, None),
            (["x-kde-passwordManagerHint"], Kind.EMPTY, None),
        ],
    )
    def test_table(self, types, kind, pick):
        assert classify(types) == (kind, pick)

    def test_plain_preference_does_not_depend_on_offer_order(self):
        assert classify(list(reversed(FIREFOX_TYPES)))[1] == "text/plain;charset=utf-8"

    def test_text_plain_with_another_charset_is_not_taken_as_plain(self):
        # Only UTF-8 plain text is read; a latin-1 offer must not be decoded as UTF-8.
        assert classify(["text/plain;charset=iso-8859-1"]) == (Kind.RICH_ONLY, None)

    @given(st.lists(st.text(max_size=40), max_size=12))
    def test_never_crashes_and_only_picks_offered_plain_types(self, types):
        kind, pick = classify(types)
        if kind is Kind.TEXT:
            assert pick in types
            assert "".join(pick.split()).lower() in clipio.PLAIN_TYPES
        else:
            assert pick is None

    @given(st.lists(st.sampled_from([*FIREFOX_TYPES, "image/png", "text/rtf"]), min_size=1))
    def test_rich_types_never_win_over_plain(self, types):
        kind, pick = classify(types)
        if any(
            t in types
            for t in ("text/plain;charset=utf-8", "text/plain", "TEXT", "STRING", "UTF8_STRING")
        ):
            assert kind is Kind.TEXT
            assert pick not in ("text/html", "text/rtf", "image/png")


# ── Wayland read ──────────────────────────────────────────────────────────────


class TestWaylandRead:
    def test_mixed_html_and_text_reads_plain_only(self):
        offers = dict.fromkeys(FIREFOX_TYPES, b"")
        offers["text/html"] = b"<b>Jane Doe</b> <a href='mailto:jane.doe@xyz.example.test'>x</a>"
        offers["text/plain;charset=utf-8"] = utf8(SYNTHETIC)
        fake = FakeWayland(offers)
        got = wayland(fake).read()
        assert got.kind is Kind.TEXT
        assert got.text == SYNTHETIC
        assert got.type_count == len(FIREFOX_TYPES)
        requested = [c[c.index("--type") + 1] for c in fake.calls if "--type" in c]
        assert requested == ["text/plain;charset=utf-8"]  # HTML is never requested

    def test_html_only_is_not_read(self):
        fake = FakeWayland({"text/html": b"<p>Jane Doe</p>"})
        got = wayland(fake).read()
        assert got == ClipContent(Kind.RICH_ONLY, type_count=1)
        assert len(fake.calls) == 1  # only --list-types

    def test_image_only_is_not_read(self):
        fake = FakeWayland({"image/png": b"\x89PNG\r\n\x1a\n...."})
        got = wayland(fake).read()
        assert got.kind is Kind.NON_TEXT
        assert got.text is None
        assert len(fake.calls) == 1

    def test_image_with_plain_text_reads_the_text(self):
        got = wayland(FakeWayland({"image/png": b"\x89PNG", "text/plain": b"caption"})).read()
        assert (got.kind, got.text) == (Kind.TEXT, "caption")

    def test_nothing_copied_is_empty(self):
        assert wayland(FakeWayland(None)).read() == ClipContent(Kind.EMPTY)

    def test_empty_text_is_text(self):
        got = wayland(FakeWayland({"text/plain": b""})).read()
        assert (got.kind, got.text) == (Kind.TEXT, "")

    def test_bytes_are_kept_exactly(self):
        text = "a\r\nb\n\n\t trailing  \n\x00z\N{ZERO WIDTH JOINER}" + chr(0xFB01)
        got = wayland(FakeWayland({"text/plain": utf8(text)})).read()
        assert got.text == text  # no newline stripping, no normalization

    def test_indic_scripts(self):
        assert wayland(FakeWayland({"UTF8_STRING": utf8(INDIC)})).read().text == INDIC

    def test_invalid_utf8_is_an_error(self):
        with pytest.raises(ClipboardError, match="not valid UTF-8") as caught:
            wayland(FakeWayland({"text/plain": b"Jane \xff Doe"})).read()
        assert "Jane" not in str(caught.value)
        assert caught.value.exit_code is ExitCode.CLIPBOARD

    def test_oversized_text_is_an_error(self):
        fake = FakeWayland({"text/plain": b"x" * 101})
        with pytest.raises(ClipboardError, match="larger than 100 bytes"):
            wayland(fake, limit=100).read()

    def test_limit_boundary_is_allowed(self):
        assert wayland(FakeWayland({"text/plain": b"x" * 100}), limit=100).read().text == "x" * 100

    def test_password_manager_hint_is_reported(self):
        got = wayland(
            FakeWayland({"text/plain": b"s3cret", "x-kde-passwordManagerHint": b"secret"})
        ).read()
        assert got.kind is Kind.TEXT
        assert got.secret is True

    def test_no_hint_is_not_secret(self):
        assert wayland(FakeWayland({"text/plain": b"x"})).read().secret is False

    def test_primary_selection(self):
        fake = FakeWayland({"text/plain": b"clipboard"}, primary={"text/plain": b"highlighted"})
        assert wayland(fake).read(Selection.PRIMARY).text == "highlighted"
        assert all("--primary" in c for c in fake.calls)
        assert wayland(fake).read().text == "clipboard"

    def test_list_types_failure_is_an_error(self):
        fake = FakeWayland({"text/plain": b"x"})
        fake.paste_rc, fake.paste_err = 1, b"Failed to connect to a Wayland server\n"
        with pytest.raises(ClipboardError, match=r"wl-paste failed \(exit 1\)"):
            wayland(fake).read()

    def test_tool_stderr_is_never_in_the_message(self):
        fake = FakeWayland({"text/plain": b"x"})
        fake.paste_rc, fake.paste_err = 3, b"weird: Jane Doe\n"
        with pytest.raises(ClipboardError) as caught:
            wayland(fake).read()
        assert "Jane" not in str(caught.value)

    def test_selection_vanishing_between_list_and_read_is_empty(self):
        fake = FakeWayland({"text/plain": b"x"})
        real_capture = fake.capture

        def capture(argv, **kw):
            if "--type" in argv:
                fake.sel[Selection.CLIPBOARD] = None
            return real_capture(argv, **kw)

        board = WaylandClipboard(
            "/usr/bin/wl-paste", "/usr/bin/wl-copy", capture=capture, feed=fake.feed
        )
        assert board.read() == ClipContent(Kind.EMPTY)

    def test_type_read_failure_is_an_error(self):
        fake = FakeWayland({"text/plain": b"x"})
        real_capture = fake.capture

        def capture(argv, **kw):
            if "--type" in argv:
                return Captured(1, b"", b"Clipboard content is not available as requested type\n")
            return real_capture(argv, **kw)

        board = WaylandClipboard(
            "/usr/bin/wl-paste", "/usr/bin/wl-copy", capture=capture, feed=fake.feed
        )
        with pytest.raises(ClipboardError):
            board.read()

    def test_undecodable_type_list_is_an_error(self):
        def capture(argv, **kw):
            return Captured(0, b"text/pl\xffain\n", b"")

        board = WaylandClipboard("/a", "/b", capture=capture, feed=lambda *a, **k: 0)
        with pytest.raises(ClipboardError, match="type list"):
            board.read()

    def test_tool_errors_propagate(self):
        def capture(argv, **kw):
            raise ClipboardError("the clipboard tool timed out")

        with pytest.raises(ClipboardError, match="timed out"):
            WaylandClipboard("/a", "/b", capture=capture, feed=lambda *a, **k: 0).read()

    def test_repr_never_shows_text(self):
        got = wayland(FakeWayland({"text/plain": utf8(SYNTHETIC)})).read()
        for shown in (repr(got), str(got)):
            assert "Jane" not in shown
            assert f"<{len(SYNTHETIC)} chars>" in shown


# ── Wayland write / clear ─────────────────────────────────────────────────────


class TestWaylandWrite:
    def test_offers_plain_text_only_and_drops_rich_types(self):
        offers = dict.fromkeys(FIREFOX_TYPES, b"Jane Doe")
        fake = FakeWayland(offers)
        board = wayland(fake)
        board.write_text("Alex Smith")
        assert fake.sel[Selection.CLIPBOARD] == {"text/plain": b"Alex Smith"}
        assert fake.calls[-1] == ["/usr/bin/wl-copy", "--type", "text/plain"]
        assert board.read().text == "Alex Smith"

    def test_text_goes_through_stdin_never_argv(self):
        fake = FakeWayland()
        wayland(fake).write_text(SYNTHETIC)
        assert fake.fed == [utf8(SYNTHETIC)]
        assert not any("Jane" in arg for call in fake.calls for arg in call)

    def test_writes_the_clipboard_never_primary(self):
        fake = FakeWayland(primary={"text/plain": b"keep"})
        wayland(fake).write_text("x")
        assert "--primary" not in fake.calls[-1]
        assert fake.sel[Selection.PRIMARY] == {"text/plain": b"keep"}

    @pytest.mark.parametrize("text", ["", "\n", INDIC, "a\r\nb", "x" * 100_000])
    def test_round_trip(self, text):
        board = wayland(FakeWayland())
        board.write_text(text)
        assert board.read().text == text

    def test_no_trailing_newline_handling_on_write(self):
        fake = FakeWayland()
        wayland(fake).write_text("end\n")
        assert fake.fed == [b"end\n"]
        assert "--trim-newline" not in fake.calls[-1]
        assert "-n" not in fake.calls[-1]

    def test_write_failure_is_an_error(self):
        fake = FakeWayland()
        fake.copy_rc = 1
        with pytest.raises(ClipboardError, match=r"wl-copy failed \(exit 1\)"):
            wayland(fake).write_text("x")

    def test_clear(self):
        fake = FakeWayland({"text/plain": b"x", "text/html": b"<b>x</b>"})
        wayland(fake).clear()
        assert fake.calls[-1] == ["/usr/bin/wl-copy", "--clear"]
        assert fake.fed[-1] == b""
        assert wayland(fake).read().kind is Kind.EMPTY

    def test_clear_primary(self):
        fake = FakeWayland({"text/plain": b"x"}, primary={"text/plain": b"y"})
        wayland(fake).clear(Selection.PRIMARY)
        assert fake.calls[-1] == ["/usr/bin/wl-copy", "--primary", "--clear"]
        assert fake.sel[Selection.CLIPBOARD] == {"text/plain": b"x"}

    def test_clear_failure_is_an_error(self):
        fake = FakeWayland()
        fake.copy_rc = 2
        with pytest.raises(ClipboardError, match="--clear failed"):
            wayland(fake).clear()


# ── xsel ──────────────────────────────────────────────────────────────────────


class FakeXsel:
    def __init__(self, clipboard: bytes = b"", primary: bytes = b"") -> None:
        self.sel = {"--clipboard": clipboard, "--primary": primary}
        self.calls: list[list[str]] = []
        self.fed: list[bytes] = []
        self.rc = 0

    def capture(self, argv, *, timeout, limit):
        self.calls.append(list(argv))
        assert argv[2] == "--output"
        if self.rc:
            return Captured(self.rc, b"", b"xsel: Can't open display\n")
        return Captured(0, self.sel[argv[1]], b"")

    def feed(self, argv, data, *, timeout):
        self.calls.append(list(argv))
        self.fed.append(data)
        if self.rc:
            return self.rc
        self.sel[argv[1]] = b"" if argv[2] == "--clear" else data
        return 0


def xsel(fake: FakeXsel) -> XselClipboard:
    return XselClipboard("/usr/bin/xsel", capture=fake.capture, feed=fake.feed)


class TestXsel:
    def test_read_text(self):
        got = xsel(FakeXsel(utf8(INDIC))).read()
        assert (got.kind, got.text, got.secret) == (Kind.TEXT, INDIC, False)

    def test_nothing_copied_is_empty(self):
        assert xsel(FakeXsel()).read() == ClipContent(Kind.EMPTY)

    def test_primary(self):
        fake = FakeXsel(b"clip", b"high")
        assert xsel(fake).read(Selection.PRIMARY).text == "high"
        assert fake.calls[-1] == ["/usr/bin/xsel", "--primary", "--output"]

    def test_write_via_stdin_to_clipboard(self):
        fake = FakeXsel(primary=b"keep")
        xsel(fake).write_text(SYNTHETIC)
        assert fake.calls[-1] == ["/usr/bin/xsel", "--clipboard", "--input"]
        assert fake.fed == [utf8(SYNTHETIC)]
        assert fake.sel["--primary"] == b"keep"

    def test_clear(self):
        fake = FakeXsel(b"x")
        xsel(fake).clear()
        assert fake.calls[-1] == ["/usr/bin/xsel", "--clipboard", "--clear"]
        assert xsel(fake).read().kind is Kind.EMPTY

    def test_failures(self):
        fake = FakeXsel(b"x")
        fake.rc = 1
        board = xsel(fake)
        for action in (board.read, lambda: board.write_text("x"), board.clear):
            with pytest.raises(ClipboardError, match="xsel"):
                action()

    def test_invalid_utf8(self):
        with pytest.raises(ClipboardError, match="UTF-8"):
            xsel(FakeXsel(b"\xc3")).read()


# ── detect ────────────────────────────────────────────────────────────────────


def which_from(*present: str):
    return lambda name: f"/usr/bin/{name}" if name in present else None


class TestDetect:
    def test_wayland(self):
        board = detect(
            {"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"},
            which_from("wl-paste", "wl-copy", "xsel"),
        )
        assert isinstance(board, WaylandClipboard)
        assert board.name == "wl-clipboard"

    def test_wayland_without_wl_clipboard_falls_back_to_xsel_on_xwayland(self):
        board = detect({"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"}, which_from("xsel"))
        assert isinstance(board, XselClipboard)

    def test_wayland_with_only_one_wl_tool_falls_back(self):
        board = detect({"WAYLAND_DISPLAY": "w", "DISPLAY": ":0"}, which_from("wl-paste", "xsel"))
        assert isinstance(board, XselClipboard)

    def test_x11(self):
        assert isinstance(
            detect({"DISPLAY": ":0"}, which_from("wl-paste", "wl-copy", "xsel")), XselClipboard
        )

    @pytest.mark.parametrize(
        ("env", "tools"),
        [
            ({}, ("wl-paste", "wl-copy", "xsel")),
            ({"WAYLAND_DISPLAY": ""}, ("wl-paste", "wl-copy")),
            ({"WAYLAND_DISPLAY": "w"}, ("xsel",)),
            ({"DISPLAY": ":0"}, ("wl-paste", "wl-copy")),
            ({"WAYLAND_DISPLAY": "w", "DISPLAY": ":0"}, ()),
        ],
    )
    def test_nothing_usable(self, env, tools):
        with pytest.raises(ClipboardError, match="no clipboard tool") as caught:
            detect(env, which_from(*tools))
        assert caught.value.exit_code is ExitCode.CLIPBOARD

    def test_defaults_to_os_environ(self, monkeypatch):
        monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
        monkeypatch.setenv("DISPLAY", ":99")
        assert isinstance(detect(which=which_from("xsel")), XselClipboard)
