"""macOS pasteboard backend: UTI mapping, detect() dispatch, error hygiene.

The pure tests never touch the pasteboard. The round-trip class needs the real general
pasteboard, so it is opt-in (macOS and VEIL_TEST_PASTEBOARD=1) and puts back the user's current
clipboard string afterwards. Synthetic text only.
"""

import os
import struct
import sys

import pytest

from tests.unit.test_imagemeta import build_png
from veil.clip import io as clipio
from veil.clip import pasteboard
from veil.clip.imagemeta import ImageFormat, strip
from veil.clip.io import ClipContent, Kind, Selection, classify, detect, plain_only
from veil.clip.pasteboard import (
    AUTO_GENERATED,
    CONCEALED,
    SOURCE,
    TRANSIENT,
    PasteboardClipboard,
    map_types,
)
from veil.errors import ClipboardError, ImageError

SYNTHETIC = "Hi, I'm Jane Doe (jane.doe@xyz.example.test)\n"


def _tiny_bmp() -> bytes:
    header = b"BM" + struct.pack("<IHHI", 58, 0, 0, 54)
    dib = struct.pack("<IIIHHIIIIII", 40, 1, 1, 1, 24, 0, 4, 2835, 2835, 0, 0)
    return header + dib + b"\x11\x22\x33\x00"


def kind_of(utis):
    return classify(map_types(utis).names)[0]


class TestMapTypes:
    def test_plain_utis_map_to_classify_names(self):
        mapped = map_types(["public.utf8-plain-text", "public.plain-text", "NSStringPboardType"])
        assert mapped.names == ("text/plain;charset=utf-8", "text/plain", "string")
        assert classify(mapped.names) == (Kind.TEXT, "text/plain;charset=utf-8")
        assert mapped.originals["text/plain;charset=utf-8"] == "public.utf8-plain-text"

    def test_rich_utis(self):
        for uti in ("public.rtf", "com.apple.flat-rtfd", "public.rtfd", "public.html"):
            assert kind_of([uti]) is Kind.RICH_ONLY
        assert map_types(["com.apple.flat-rtfd"]).names == ("application/x-apple-rtfd",)
        assert map_types(["public.rtf"]).names == ("application/rtf",)
        assert map_types(["public.html"]).names == ("text/html",)

    def test_text_wins_over_rich_and_images(self):
        assert kind_of(["public.html", "public.rtf", "public.utf8-plain-text"]) is Kind.TEXT
        assert kind_of(["public.png", "public.utf8-plain-text"]) is Kind.TEXT

    def test_images_and_files_classification(self):
        for uti in (
            "public.png",
            "public.jpeg",
            "public.tiff",
            "public.heic",
            "com.compuserve.gif",
        ):
            assert kind_of([uti]) is Kind.IMAGE
        assert kind_of(["public.png", "public.tiff"]) is Kind.IMAGE
        assert kind_of(["public.file-url"]) is Kind.NON_TEXT

    def test_empty(self):
        assert kind_of([]) is Kind.EMPTY
        assert map_types([]).total == 0

    def test_markers_are_dropped_and_secret_noted(self):
        utis = ["public.utf8-plain-text", CONCEALED, SOURCE]
        mapped = map_types(utis)
        assert mapped.names == ("text/plain;charset=utf-8",)
        assert mapped.secret is True
        assert mapped.total == 3

    @pytest.mark.parametrize(
        "marker",
        [TRANSIENT, AUTO_GENERATED, SOURCE],
    )
    def test_other_markers_are_not_secret(self, marker):
        mapped = map_types(["public.utf8-plain-text", marker])
        assert mapped.secret is False
        assert mapped.names == ("text/plain;charset=utf-8",)

    def test_only_markers_is_empty(self):
        assert kind_of([CONCEALED, TRANSIENT]) is Kind.EMPTY

    def test_veils_own_write_is_plain_only(self):
        veil_types = [TRANSIENT, CONCEALED, SOURCE, "public.utf8-plain-text"]
        assert plain_only(map_types(veil_types).names)

    def test_rich_alongside_text_is_not_plain_only(self):
        assert not plain_only(map_types(["public.utf8-plain-text", "public.html"]).names)


class TestDetect:
    def test_darwin_picks_the_pasteboard(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        board = detect({}, lambda _name: None)
        assert isinstance(board, PasteboardClipboard)
        assert board.name == "pasteboard"

    def test_linux_without_tools_error_mentions_macos(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        with pytest.raises(ClipboardError, match="macOS"):
            detect({}, lambda _name: None)

    def test_linux_still_picks_xsel(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        board = detect({"DISPLAY": ":0"}, lambda name: "/bin/xsel" if name == "xsel" else None)
        assert isinstance(board, clipio.XselClipboard)


class TestImageIOAndErrors:
    def test_convert_to_png_releases_cf_objects_on_error(self, monkeypatch):
        released: list[int] = []

        class FakeCF:
            @staticmethod
            def CFDataCreate(_alloc, _raw, _n):
                return 101

            @staticmethod
            def CFDataCreateMutable(_alloc, _n):
                return 102

            @staticmethod
            def CFStringCreateWithCString(_alloc, _s, _enc):
                return 103

            @staticmethod
            def CFRelease(obj):
                released.append(obj)

        class FakeIIO:
            @staticmethod
            def CGImageSourceCreateWithData(_d, _opts):
                return 201

            @staticmethod
            def CGImageSourceCreateImageAtIndex(_src, _idx, _opts):
                return 202

            @staticmethod
            def CGImageDestinationCreateWithData(_dst, _uti, _n, _opts):
                return 203

            @staticmethod
            def CGImageDestinationAddImage(_dst, _img, _props):
                return None

            @staticmethod
            def CGImageDestinationFinalize(_dst):
                return False

        monkeypatch.setattr(pasteboard, "_imageio", lambda: (FakeCF, FakeIIO))
        with pytest.raises(ImageError, match="encode image as PNG"):
            pasteboard._convert_to_png(b"fake-tiff-bytes")
        assert set(released) == {101, 102, 103, 201, 202, 203}

    @pytest.mark.skipif(sys.platform != "darwin", reason="ImageIO is macOS only")
    def test_real_imageio_converts_bmp_to_png_and_strips_clean(self):
        png = pasteboard._convert_to_png(_tiny_bmp())
        assert png.startswith(b"\x89PNG\r\n\x1a\n")
        res = strip(png, ImageFormat.PNG)
        assert res.data.startswith(b"\x89PNG\r\n\x1a\n")

    @pytest.mark.skipif(sys.platform != "darwin", reason="ImageIO is macOS only")
    def test_real_imageio_rejects_corrupt_bytes(self):
        with pytest.raises(ImageError):
            pasteboard._convert_to_png(b"not an image")


class TestErrorsHideText:
    def test_primary_is_empty_without_touching_appkit(self):
        board = PasteboardClipboard()
        assert board.read(Selection.PRIMARY) == ClipContent(Kind.EMPTY)
        board.clear(Selection.PRIMARY)  # a no-op

    def test_unencodable_text_error_has_no_text(self):
        bad = "Jane Doe \ud800"  # a lone surrogate cannot be UTF-8
        with pytest.raises(ClipboardError) as caught:
            pasteboard._ns_string(bad) if sys.platform == "darwin" else bad.encode("utf-8")
        assert "Jane" not in str(caught.value)

    def test_non_darwin_runtime_error_is_fixed(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        pasteboard._runtime.cache_clear()
        try:
            with pytest.raises(ClipboardError) as caught:
                PasteboardClipboard().write_text(SYNTHETIC.replace("\n", ""))
        finally:
            pasteboard._runtime.cache_clear()
        assert "Jane" not in str(caught.value)
        assert "macOS" in str(caught.value)

    def test_clipcontent_repr_hides_text_and_bytes(self):
        assert "Jane" not in repr(ClipContent(Kind.TEXT, SYNTHETIC))
        img = ClipContent(Kind.IMAGE, image=b"secret-pixels", image_format=ImageFormat.PNG)
        assert "secret-pixels" not in repr(img)
        assert "13 bytes" in repr(img)


live = pytest.mark.skipif(
    sys.platform != "darwin" or os.environ.get("VEIL_TEST_PASTEBOARD") != "1",
    reason="real pasteboard: macOS with VEIL_TEST_PASTEBOARD=1",
)


@live
class TestRealPasteboard:
    @pytest.fixture(autouse=True)
    def keep_user_clipboard(self, monkeypatch):
        from veil.clip import recent

        monkeypatch.setattr(recent, "remember", lambda _text: None)  # never the runtime dir
        monkeypatch.setattr(recent, "remember_bytes", lambda _data: None)
        board = PasteboardClipboard()
        before = board.read()
        yield
        if before.kind is Kind.TEXT and before.text is not None:
            board.write_text(before.text)
        elif before.kind is Kind.IMAGE and before.image is not None and before.image_format:
            board.write_image(before.image, before.image_format)
        else:
            board.clear()

    def test_round_trip(self):
        board = PasteboardClipboard()
        count = pasteboard.change_count()
        board.write_text(SYNTHETIC)
        assert pasteboard.change_count() > count
        got = board.read()
        assert got.kind is Kind.TEXT
        assert got.text == SYNTHETIC
        assert got.plain_only is True
        assert got.secret is False  # veil's own concealed marker is not a password
        assert got.type_count >= 4  # macOS adds NSStringPboardType itself

    def test_image_round_trip_and_markers(self):
        png, _ = build_png()
        board = PasteboardClipboard()
        count = pasteboard.change_count()
        board.write_image(png, ImageFormat.PNG)
        assert pasteboard.change_count() > count
        got = board.read()
        assert got.kind is Kind.IMAGE
        assert got.image == png
        assert got.image_format is ImageFormat.PNG
        assert got.image_converted is False
        assert got.secret is False
        with pasteboard._pool():
            utis = set(pasteboard._types(pasteboard._pasteboard()))
        assert {"public.png", TRANSIENT, AUTO_GENERATED, CONCEALED, SOURCE} <= utis
        assert "public.utf8-plain-text" not in utis

    def test_marker_types_present(self):
        board = PasteboardClipboard()
        board.write_text(SYNTHETIC)
        with pasteboard._pool():
            utis = pasteboard._types(pasteboard._pasteboard())
        assert {"public.utf8-plain-text", TRANSIENT, CONCEALED, SOURCE} <= set(utis)

    def test_nul_and_unicode_survive(self):
        board = PasteboardClipboard()
        text = "Jane\x00Doe ஜேன் \U0001f600"
        board.write_text(text)
        assert board.read().text == text

    def test_clear_makes_it_empty(self):
        board = PasteboardClipboard()
        board.write_text(SYNTHETIC)
        board.clear()
        assert board.read().kind is Kind.EMPTY

    def test_size_limit_refuses_before_copying(self):
        board = PasteboardClipboard(limit=16)
        board.write_text("Jane Doe " * 10)
        with pytest.raises(ClipboardError) as caught:
            board.read()
        assert "Jane" not in str(caught.value)

    def test_primary_is_empty(self):
        PasteboardClipboard().write_text(SYNTHETIC)
        assert PasteboardClipboard().read(Selection.PRIMARY).kind is Kind.EMPTY
