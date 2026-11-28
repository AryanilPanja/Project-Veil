"""Image metadata stripper (Feature A): PNG and JPEG parsing, Orientation, malformed inputs."""

import struct
import zlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil.clip.imagemeta import MAX_IMAGE_BYTES, ImageFormat, StripResult, strip
from veil.errors import ImageError, VeilError
from veil.exitcodes import ExitCode


def png_chunk(ctype: bytes, payload: bytes) -> bytes:
    crc = zlib.crc32(ctype + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + ctype + payload + struct.pack(">I", crc)


def build_png(*extra_chunks: tuple[bytes, bytes]) -> tuple[bytes, bytes]:
    ihdr = png_chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0))
    idat_payload = zlib.compress(b"\x00\x01\x02\x03\x04\x05\x06\x00\x07\x08\x09\x0a\x0b\x0c")
    idat = png_chunk(b"IDAT", idat_payload)
    iend = png_chunk(b"IEND", b"")
    extras = b"".join(png_chunk(t, d) for t, d in extra_chunks)
    return b"\x89PNG\r\n\x1a\n" + ihdr + extras + idat + iend, idat


def parse_png_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    pos = 8
    chunks = []
    while pos < len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        ctype = data[pos + 4 : pos + 8]
        payload = data[pos + 8 : pos + 8 + length]
        crc = struct.unpack_from(">I", data, pos + 8 + length)[0]
        assert (zlib.crc32(ctype + payload) & 0xFFFFFFFF) == crc
        chunks.append((ctype, payload))
        pos += 12 + length
    assert pos == len(data)
    return chunks


def jpeg_seg(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes((marker,)) + struct.pack(">H", 2 + len(payload)) + payload


def build_exif(*, order: bytes = b"II", orientation: int | None = None, gps: bool = False) -> bytes:
    endian = "<" if order == b"II" else ">"
    entries: list[bytes] = []
    if orientation is not None:
        val = struct.pack(f"{endian}H", orientation) + b"\x00\x00"
        entries.append(struct.pack(f"{endian}HHI", 0x0112, 3, 1) + val)
    if gps:
        # GPSInfo IFD pointer tag (0x8825) + dummy GPS payload text
        entries.append(struct.pack(f"{endian}HHII", 0x8825, 4, 1, 999))
    ifd0 = struct.pack(f"{endian}H", len(entries)) + b"".join(entries) + b"\x00\x00\x00\x00"
    extra = b"GPS Jane Doe 12.9716N 77.5946E\x00" if gps else b""
    return b"Exif\x00\x00" + order + struct.pack(f"{endian}HI", 42, 8) + ifd0 + extra


def build_jpeg(*segments: bytes, entropy: bytes | None = None) -> tuple[bytes, bytes]:
    if entropy is None:
        # Include stuffed 0xFF 0x00 and restart marker 0xFF 0xD0 inside entropy-coded data
        entropy = b"\x11\x22\xff\x00\x33\xff\xd0\x44\x55"
    dqt = jpeg_seg(0xDB, b"\x00" + b"\x10" * 64)
    sof0 = jpeg_seg(0xC0, struct.pack(">BHHB", 8, 2, 2, 1) + b"\x01\x11\x00")
    dht = jpeg_seg(0xC4, b"\x00" + b"\x01" * 16 + b"\x00")
    sos = jpeg_seg(0xDA, b"\x01\x01\x00\x00\x3f\x00")
    return b"\xff\xd8" + b"".join(
        segments
    ) + dqt + sof0 + dht + sos + entropy + b"\xff\xd9", entropy


def walk_jpeg_markers(data: bytes) -> list[tuple[int, bytes]]:
    assert data.startswith(b"\xff\xd8")
    pos = 2
    out = []
    while pos < len(data):
        assert data[pos] == 0xFF
        marker = data[pos + 1]
        pos += 2
        if marker == 0xD9:
            assert pos == len(data)
            out.append((marker, b""))
            break
        seg_len = struct.unpack_from(">H", data, pos)[0]
        payload = data[pos + 2 : pos + seg_len]
        out.append((marker, payload))
        pos += seg_len
        if marker == 0xDA:
            while pos < len(data):
                if data[pos] == 0xFF and data[pos + 1] not in (0x00, *range(0xD0, 0xD8)):
                    break
                pos += 1
    return out


class TestPngStrip:
    def test_drops_metadata_and_keeps_allowlisted_chunks(self):
        data, idat = build_png(
            (b"sRGB", b"\x00"),
            (b"pHYs", struct.pack(">IIB", 2835, 2835, 1)),
            (b"tEXt", b"Author\x00Jane Doe"),
            (b"zTXt", b"Comment\x00\x00" + zlib.compress(b"Jane Doe")),
            (b"iTXt", b"Description\x00\x00\x00\x00\x00Jane Doe"),
            (b"eXIf", b"II*\x00\x08\x00\x00\x00\x00\x00\x00\x00"),
            (b"tIME", struct.pack(">HBBBBB", 2026, 11, 27, 12, 0, 0)),
            (b"caNv", b"unknown"),
        )
        res = strip(data, ImageFormat.PNG)
        assert isinstance(res, StripResult)
        assert res.removed == 6
        assert b"Jane Doe" not in res.data
        assert idat in res.data
        chunks = parse_png_chunks(res.data)
        assert [c[0] for c in chunks] == [b"IHDR", b"sRGB", b"pHYs", b"IDAT", b"IEND"]
        assert strip(res.data, ImageFormat.PNG) == StripResult(res.data, 0)

    def test_clean_png_returns_removed_zero_and_identical_bytes(self):
        data, _ = build_png((b"gAMA", struct.pack(">I", 45455)), (b"acTL", b"\x00" * 8))
        res = strip(data, ImageFormat.PNG)
        assert res.removed == 0
        assert res.data == data


class TestJpegStrip:
    @pytest.mark.parametrize("order", [b"II", b"MM"])
    def test_drops_exif_gps_xmp_com_and_preserves_orientation(self, order):
        jfif = jpeg_seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
        icc = jpeg_seg(0xE2, b"ICC_PROFILE\x00\x01\x01\x00\x01")
        non_icc_app2 = jpeg_seg(0xE2, b"FPXR\x00extra")
        adobe = jpeg_seg(0xEE, b"Adobe\x00\x64\x00\x00\x00\x00\x00")
        exif = jpeg_seg(0xE1, build_exif(order=order, orientation=6, gps=True))
        xmp = jpeg_seg(0xE1, b"http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta>Jane Doe</x:xmpmeta>")
        app13 = jpeg_seg(0xED, b"Photoshop 3.0\x00Jane Doe")
        com = jpeg_seg(0xFE, b"Creator: Jane Doe")

        data, entropy = build_jpeg(jfif, exif, xmp, icc, non_icc_app2, app13, adobe, com)
        res = strip(data, ImageFormat.JPEG)
        assert res.removed == 5
        assert b"Jane Doe" not in res.data
        assert b"GPS" not in res.data
        assert entropy in res.data

        markers = walk_jpeg_markers(res.data)
        marker_ids = [m for m, _ in markers]
        assert marker_ids == [0xE0, 0xE1, 0xE2, 0xEE, 0xDB, 0xC0, 0xC4, 0xDA, 0xD9]
        # Minimal EXIF APP1 carries only Orientation=6
        exif_payload = markers[1][1]
        assert len(exif_payload) == 32
        assert exif_payload.startswith(b"Exif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x01\x01\x12")
        # Idempotent on second pass
        assert strip(res.data, ImageFormat.JPEG) == StripResult(res.data, 0)

    def test_orientation_1_is_dropped_completely(self):
        exif = jpeg_seg(0xE1, build_exif(order=b"MM", orientation=1, gps=True))
        data, _ = build_jpeg(exif)
        res = strip(data, ImageFormat.JPEG)
        assert res.removed == 1
        markers = [m for m, _ in walk_jpeg_markers(res.data)]
        assert 0xE1 not in markers

    def test_clean_jpeg_returns_removed_zero(self):
        jfif = jpeg_seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
        data, _ = build_jpeg(jfif)
        res = strip(data, ImageFormat.JPEG)
        assert res.removed == 0
        assert res.data == data


class TestMalformedAndLimits:
    def test_image_error_is_veil_error_with_clipboard_exit(self):
        err = ImageError("bad image")
        assert isinstance(err, VeilError)
        assert err.exit_code is ExitCode.CLIPBOARD

    def test_rejects_above_64mib(self):
        oversized = b"\x89PNG\r\n\x1a\n" + b"\x00" * (MAX_IMAGE_BYTES + 1)
        with pytest.raises(ImageError, match="larger than"):
            strip(oversized, ImageFormat.PNG)

    @pytest.mark.parametrize(
        "bad_png",
        [
            b"not a png" * 5,
            build_png()[0][:-1],  # truncated IEND
            build_png()[0][:-12],  # missing IEND
            b"\x89PNG\r\n\x1a\n" + png_chunk(b"IDAT", b"x") + png_chunk(b"IEND", b""),  # no IHDR
            b"\x89PNG\r\n\x1a\n"
            + png_chunk(b"IHDR", b"\x00" * 13)
            + struct.pack(">I", 0x7FFFFFFF)
            + b"IDAT\x00\x00\x00\x00"
            + png_chunk(b"IEND", b""),  # length overflow
            build_png((b"tEXt", b"a\x00b"))[0].replace(b"tEXt", b"tEXu"),  # bad CRC
        ],
    )
    def test_malformed_png_raises_image_error(self, bad_png):
        with pytest.raises(ImageError):
            strip(bad_png, ImageFormat.PNG)

    @pytest.mark.parametrize(
        "bad_jpeg",
        [
            b"\x00\x00\xff\xd9",  # missing SOI
            build_jpeg()[0][:-2],  # missing EOI
            b"\xff\xd8\xff\xd8\xff\xd9",  # nested SOI
            b"\xff\xd8\xff\xe1\x00\x01\xff\xd9",  # segment length < 2
            b"\xff\xd8\xff\xe1\xff\xff\xff\xd9",  # segment length overflow
            b"\xff\xd8\xff\xd0\xff\xd9",  # RST0 outside entropy scan
            b"\xff\xd8\xff\x00\xff\xd9",  # stuffed byte outside scan
            build_jpeg(entropy=b"\x11\xff")[0][:-2],  # truncated entropy scan
        ],
    )
    def test_malformed_jpeg_raises_image_error(self, bad_jpeg):
        with pytest.raises(ImageError):
            strip(bad_jpeg, ImageFormat.JPEG)

    @given(st.binary(max_size=2048), st.sampled_from([ImageFormat.PNG, ImageFormat.JPEG]))
    def test_fuzz_arbitrary_bytes_never_crash(self, data, fmt):
        try:
            res = strip(data, fmt)
        except ImageError:
            return
        assert strip(res.data, fmt) == StripResult(res.data, 0)

    @given(
        st.integers(0, 120),
        st.binary(min_size=1, max_size=8),
        st.sampled_from(["replace", "truncate", "insert"]),
    )
    def test_fuzz_mutated_png_and_jpeg(self, offset, patch, op):
        base_png, _ = build_png((b"tEXt", b"Author\x00Jane Doe"))
        base_jpeg, _ = build_jpeg(jpeg_seg(0xE1, build_exif(orientation=6, gps=True)))
        for base, fmt in ((base_png, ImageFormat.PNG), (base_jpeg, ImageFormat.JPEG)):
            idx = offset % len(base)
            if op == "replace":
                mutated = base[:idx] + patch + base[idx + len(patch) :]
            elif op == "truncate":
                mutated = base[:idx]
            else:
                mutated = base[:idx] + patch + base[idx:]
            try:
                res = strip(mutated, fmt)
            except ImageError:
                continue
            assert strip(res.data, fmt) == StripResult(res.data, 0)


@pytest.mark.parametrize("fmt", [ImageFormat.PNG, ImageFormat.JPEG])
def test_bytes_after_the_image_end_are_dropped(fmt):
    clean = (build_png() if fmt is ImageFormat.PNG else build_jpeg())[0]
    res = strip(clean + b"appended video: Jane Doe", fmt)
    assert res == StripResult(clean, 1)
    assert strip(res.data, fmt) == StripResult(res.data, 0)


def test_png_hdr_colour_chunks_are_kept():
    data, _ = build_png((b"cICP", b"\x09\x10\x00\x01"), (b"cLLI", b"\x00" * 8))
    assert strip(data, ImageFormat.PNG) == StripResult(data, 0)
