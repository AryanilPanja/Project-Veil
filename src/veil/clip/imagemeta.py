"""Strip metadata from PNG and JPEG images (pure stdlib, fail-closed).

Only structurally verified images are returned; any malformed chunk, CRC mismatch, truncated
segment, length overflow, nested SOI, or missing EOI raises `ImageError` without returning
partial output. Image size is bounded at 64 MiB (`MAX_IMAGE_BYTES`).
"""

import struct
import zlib
from dataclasses import dataclass
from enum import StrEnum

from veil.errors import ImageError

MAX_IMAGE_BYTES = 64 * 1024 * 1024

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PNG_MAX_CHUNK_LEN = 0x7FFFFFFF
_PNG_KEEP = frozenset({
    b"IHDR", b"PLTE", b"IDAT", b"IEND",
    b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"pHYs", b"bKGD",
    b"acTL", b"fcTL", b"fdAT",
    # HDR colour (PNG 3rd edition, and the draft spellings): colour data, no metadata.
    b"cICP", b"mDCV", b"cLLI", b"mDCv", b"cLLi",
})  # fmt: skip

_JPEG_SOI = b"\xff\xd8"
_JPEG_KEEP_DIRECT = frozenset({
    0xC0, 0xC1, 0xC2, 0xC3,  # SOF0..SOF3
    0xC4,                    # DHT
    0xC5, 0xC6, 0xC7,        # SOF5..SOF7
    0xC9, 0xCA, 0xCB,        # SOF9..SOF11
    0xCC,                    # DAC (arithmetic coding conditioning)
    0xCD, 0xCE, 0xCF,        # SOF13..SOF15
    0xDB,                    # DQT
    0xDC,                    # DNL
    0xDD,                    # DRI
})  # fmt: skip
_JPEG_DROP_DIRECT = frozenset({*range(0xE3, 0xEE), 0xEF, 0xFE})  # APP3..APP13, APP15, COM
_JPEG_VALID_SEGMENTS = _JPEG_KEEP_DIRECT | _JPEG_DROP_DIRECT | {0xDA, 0xE0, 0xE1, 0xE2, 0xEE}

_EXIF_HEADER = b"Exif\x00\x00"
_ORIENTATION_TAG = 0x0112
_TIFF_SHORT = 3


class ImageFormat(StrEnum):
    PNG = "png"
    JPEG = "jpeg"


@dataclass(frozen=True)
class StripResult:
    data: bytes
    removed: int


def strip(data: bytes, fmt: ImageFormat | str) -> StripResult:
    """Validate `data` as `fmt` and strip non-essential metadata. Never returns partial output."""
    try:
        image_fmt = ImageFormat(fmt)
    except ValueError:
        raise ImageError("unsupported image format") from None
    if len(data) > MAX_IMAGE_BYTES:
        raise ImageError(f"the clipboard image is larger than {MAX_IMAGE_BYTES} bytes")
    if image_fmt is ImageFormat.PNG:
        return _strip_png(data)
    return _strip_jpeg(data)


def _strip_png(data: bytes) -> StripResult:
    if len(data) < len(_PNG_SIGNATURE) + 24 or not data.startswith(_PNG_SIGNATURE):
        raise ImageError("malformed PNG: invalid signature")
    view = memoryview(data)
    offset = len(_PNG_SIGNATURE)
    total = len(data)
    kept: list[bytes] = []
    removed = 0
    seen_ihdr = False
    seen_iend = False

    while offset < total:
        if offset + 12 > total:
            raise ImageError("malformed PNG: truncated chunk")
        length = struct.unpack_from(">I", data, offset)[0]
        if length > _PNG_MAX_CHUNK_LEN or length > total - offset - 12:
            raise ImageError("malformed PNG: chunk length out of bounds")
        chunk_type = data[offset + 4 : offset + 8]
        if not all((65 <= b <= 90) or (97 <= b <= 122) for b in chunk_type):
            raise ImageError("malformed PNG: invalid chunk type")
        stored_crc = struct.unpack_from(">I", data, offset + 8 + length)[0]
        computed_crc = zlib.crc32(view[offset + 4 : offset + 8 + length]) & 0xFFFFFFFF
        if computed_crc != stored_crc:
            raise ImageError("malformed PNG: chunk CRC mismatch")

        if not seen_ihdr:
            if chunk_type != b"IHDR" or length != 13:
                raise ImageError("malformed PNG: missing or invalid IHDR")
            seen_ihdr = True
        elif chunk_type == b"IHDR":
            raise ImageError("malformed PNG: duplicate IHDR")

        if chunk_type == b"IEND":
            if length != 0:
                raise ImageError("malformed PNG: invalid IEND length")
            seen_iend = True
            if offset + 12 != total:
                # Bytes after IEND (an appended file, another image) are not part of the
                # picture and can carry their own metadata: drop them.
                removed += 1
                kept.append(data[offset : offset + 12])
                break

        end = offset + 12 + length
        if chunk_type in _PNG_KEEP:
            kept.append(data[offset:end])
        else:
            removed += 1
        offset = end

    if not seen_ihdr or not seen_iend:
        raise ImageError("malformed PNG: missing IEND")
    if removed == 0:
        return StripResult(data, 0)
    return StripResult(_PNG_SIGNATURE + b"".join(kept), removed)


def _strip_jpeg(data: bytes) -> StripResult:
    n = len(data)
    if n < 4 or not data.startswith(_JPEG_SOI):
        raise ImageError("malformed JPEG: missing SOI")

    pos = 2
    kept: list[bytes] = []
    removed = 0
    orientation: int | None = None
    minimal_exif_kept = False
    insert_idx: int | None = None
    seen_eoi = False

    while pos < n:
        if data[pos] != 0xFF:
            raise ImageError("malformed JPEG: expected marker")
        while pos < n and data[pos] == 0xFF:
            pos += 1
        if pos >= n:
            raise ImageError("malformed JPEG: truncated marker")
        marker = data[pos]
        pos += 1

        if marker == 0xD9:  # EOI
            if pos != n:
                # A Motion Photo video or a second (MPF) image after EOI can carry its own
                # EXIF: drop everything after the first EOI.
                removed += 1
            kept.append(b"\xff\xd9")
            seen_eoi = True
            break
        if marker == 0xD8:
            raise ImageError("malformed JPEG: nested SOI marker")
        if marker not in _JPEG_VALID_SEGMENTS:
            raise ImageError("malformed JPEG: unexpected or unsupported marker")

        if pos + 2 > n:
            raise ImageError("malformed JPEG: truncated segment length")
        seg_len = struct.unpack_from(">H", data, pos)[0]
        if seg_len < 2 or pos + seg_len > n:
            raise ImageError("malformed JPEG: segment length out of bounds")
        if marker == 0xDD and seg_len != 4:
            raise ImageError("malformed JPEG: invalid DRI length")

        payload = data[pos + 2 : pos + seg_len]
        segment = b"\xff" + bytes((marker,)) + data[pos : pos + seg_len]
        pos += seg_len

        if marker == 0xDA:  # SOS + entropy-coded data
            scan_start = pos
            while pos < n:
                if data[pos] != 0xFF:
                    pos += 1
                    continue
                run = pos + 1
                while run < n and data[run] == 0xFF:
                    run += 1
                if run >= n:
                    raise ImageError("malformed JPEG: truncated entropy-coded data")
                nxt = data[run]
                if nxt == 0x00 or (0xD0 <= nxt <= 0xD7):
                    pos = run + 1
                    continue
                break
            else:
                raise ImageError("malformed JPEG: missing EOI")
            if pos >= n:
                raise ImageError("malformed JPEG: missing EOI")
            kept.append(segment)
            kept.append(data[scan_start:pos])
        elif marker == 0xE0:
            if payload.startswith(b"JFIF\x00"):
                kept.append(segment)
            else:
                removed += 1
        elif marker == 0xE1:
            orient = _exif_orientation(payload)
            if orient is not None and 2 <= orient <= 8:
                if not minimal_exif_kept and payload == _minimal_exif_payload(orient):
                    kept.append(segment)
                    minimal_exif_kept = True
                else:
                    removed += 1
                    if orientation is None:
                        orientation = orient
                    if insert_idx is None:
                        insert_idx = len(kept)
            else:
                removed += 1
        elif marker == 0xE2:
            if payload.startswith(b"ICC_PROFILE\x00"):
                kept.append(segment)
            else:
                removed += 1
        elif marker == 0xEE:
            if payload.startswith(b"Adobe"):
                kept.append(segment)
            else:
                removed += 1
        elif marker in _JPEG_DROP_DIRECT:
            removed += 1
        else:
            kept.append(segment)

    if not seen_eoi:
        raise ImageError("malformed JPEG: missing EOI")

    if orientation is not None and not minimal_exif_kept:
        exif_payload = _minimal_exif_payload(orientation)
        exif_seg = b"\xff\xe1" + struct.pack(">H", 2 + len(exif_payload)) + exif_payload
        kept.insert(0 if insert_idx is None else insert_idx, exif_seg)

    if removed == 0:
        return StripResult(data, 0)
    return StripResult(_JPEG_SOI + b"".join(kept), removed)


def _exif_orientation(payload: bytes) -> int | None:
    """Best-effort extraction of TIFF IFD0 Orientation (0x0112) from an EXIF APP1 payload."""
    if not payload.startswith(_EXIF_HEADER):
        return None
    tiff = payload[len(_EXIF_HEADER) :]
    if len(tiff) < 8:
        return None
    order = tiff[:2]
    if order == b"II":
        endian = "<"
    elif order == b"MM":
        endian = ">"
    else:
        return None
    magic, ifd0 = struct.unpack_from(f"{endian}HI", tiff, 2)
    if magic != 42 or ifd0 < 8 or ifd0 + 2 > len(tiff):
        return None
    count = struct.unpack_from(f"{endian}H", tiff, ifd0)[0]
    entries_start = ifd0 + 2
    max_entries = min(count, (len(tiff) - entries_start) // 12)
    for i in range(max_entries):
        entry = entries_start + i * 12
        tag, field_type, value_count = struct.unpack_from(f"{endian}HHI", tiff, entry)
        if tag == _ORIENTATION_TAG and field_type == _TIFF_SHORT and value_count == 1:
            return int(struct.unpack_from(f"{endian}H", tiff, entry + 8)[0])
    return None


def _minimal_exif_payload(orientation: int) -> bytes:
    """A minimal big-endian TIFF EXIF APP1 payload carrying only the Orientation tag."""
    return (
        _EXIF_HEADER
        + b"MM\x00\x2a\x00\x00\x00\x08"
        + b"\x00\x01"
        + struct.pack(">HHII", _ORIENTATION_TAG, _TIFF_SHORT, 1, orientation << 16)
        + b"\x00\x00\x00\x00"
    )
