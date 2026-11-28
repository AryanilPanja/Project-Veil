"""Convert HTML-only and RTF-only clipboard offers to plain text (pure stdlib, fail-closed).

Used when the clipboard carries rich text without a plain-text alternative (`Kind.RICH_ONLY`).
Malformed input raises `ClipboardError` so the caller fails closed.
"""

import codecs
import re
from enum import StrEnum
from html.parser import HTMLParser

from veil.errors import ClipboardError

_MAX_RTF_DEPTH = 256
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_WS_RUN = re.compile(r"[ \t\r\n\f\v]+")

_HTML_SKIP_TAGS = frozenset({"script", "style", "head", "title", "noscript", "template"})
_HTML_BLOCK_TAGS = frozenset({
    "p", "div", "section", "article", "header", "footer", "aside", "nav", "main",
    "blockquote", "pre", "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "dl", "dt", "dd",
    "table", "tr", "thead", "tbody", "tfoot", "figure", "figcaption", "address",
})  # fmt: skip
_HTML_CELL_TAGS = frozenset({"td", "th"})

_RTF_SKIP_DESTINATIONS = frozenset({
    "fonttbl", "colortbl", "stylesheet", "info", "pict", "object", "datafield", "fldinst",
    "header", "footer", "headerl", "headerr", "headerf", "footerl", "footerr", "footerf",
    "footnote", "xe", "tc", "rxe", "bkmkstart", "bkmkend", "listtable", "listoverridetable",
    "revtbl", "rsidtbl", "generator", "xmlnstbl", "themedata", "colorschememapping",
    "latentstyles", "datastore", "pgdsctbl", "mmathPr", "shppict",
})  # fmt: skip

_RTF_SPECIAL_CHARS = {
    "emdash": "\u2014",
    "endash": "\u2013",
    "lquote": "\u2018",
    "rquote": "\u2019",
    "ldblquote": "\u201c",
    "rdblquote": "\u201d",
    "bullet": "\u2022",
}

_RTF_CODEPAGES = {
    65001: "utf-8",
    10000: "mac_roman",
}


class RichFormat(StrEnum):
    HTML = "html"
    RTF = "rtf"


def to_text(raw: bytes, fmt: RichFormat | str) -> str:
    """Convert raw HTML or RTF clipboard bytes to plain text."""
    try:
        rich_fmt = RichFormat(fmt)
    except ValueError:
        raise ClipboardError("unsupported rich text format") from None
    if rich_fmt is RichFormat.HTML:
        return html_to_text(raw)
    return rtf_to_text(raw)


def html_to_text(raw: bytes) -> str:
    """Extract visible text from HTML bytes (drops script/style/head, decodes entities)."""
    text = _decode_html(raw)
    parser = _HTMLTextExtractor()
    try:
        parser.feed(text)
        parser.close()
    except Exception:  # noqa: BLE001 - fail closed on parser error
        raise ClipboardError("malformed HTML on the clipboard") from None
    return parser.result()


def _decode_html(raw: bytes) -> str:
    try:
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            decoded = raw.decode("utf-16")
        else:
            decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ClipboardError("the clipboard HTML is not valid UTF-8") from None
    return decoded.removeprefix("\ufeff")


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0
        self._pre_depth = 0
        self._in_cell = False
        self._need_cell_sep = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag == "body":
            self._skip_depth = 0
            return
        if tag in _HTML_SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "pre":
            self._newline(explicit=False)
            self._pre_depth += 1
        elif tag in ("br", "hr"):
            self._newline(explicit=True)
        elif tag in _HTML_CELL_TAGS:
            if self._need_cell_sep and self._parts and not self._parts[-1].endswith(("\n", "\t")):
                self._parts.append("\t")
            self._in_cell = True
            self._need_cell_sep = False
        elif tag in _HTML_BLOCK_TAGS:
            if tag == "tr":
                self._need_cell_sep = False
            self._newline(explicit=False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if self._skip_depth:
            return
        if tag in ("br", "hr"):
            self._newline(explicit=True)
        elif tag in _HTML_BLOCK_TAGS:
            self._newline(explicit=False)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in _HTML_SKIP_TAGS:
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag == "pre":
            if self._pre_depth > 0:
                self._pre_depth -= 1
            if self._parts and not self._parts[-1].endswith("\n"):
                self._parts.append("\n")
        elif tag in _HTML_CELL_TAGS:
            self._in_cell = False
            self._need_cell_sep = True
        elif tag in _HTML_BLOCK_TAGS:
            if tag == "tr":
                self._need_cell_sep = False
            self._newline(explicit=False)

    def handle_data(self, data: str) -> None:
        if self._skip_depth or not data:
            return
        if self._pre_depth:
            self._parts.append(data)
            return
        collapsed = _WS_RUN.sub(" ", data)
        if not collapsed:
            return
        if not self._parts or self._parts[-1].endswith(("\n", "\t", " ")):
            collapsed = collapsed.lstrip(" ")
        if collapsed:
            self._parts.append(collapsed)

    def _newline(self, *, explicit: bool) -> None:
        while self._parts and self._parts[-1] in (" ", "\t"):
            self._parts.pop()
        if self._parts and self._parts[-1].endswith((" ", "\t")):
            self._parts[-1] = self._parts[-1].rstrip(" \t")
            if not self._parts[-1]:
                self._parts.pop()
        if explicit or (self._parts and not self._parts[-1].endswith("\n")):
            self._parts.append("\n")

    def result(self) -> str:
        text = "".join(self._parts)
        return text.rstrip("\n") if text.endswith("\n") and not self._pre_depth else text


def rtf_to_text(raw: bytes) -> str:
    """Convert RTF bytes to plain text (pure Python, fail-closed on malformed RTF)."""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ClipboardError("malformed RTF on the clipboard") from None
    if "\x00" in text:
        raise ClipboardError("malformed RTF on the clipboard")

    start = 0
    while start < len(text) and text[start] in " \t\r\n":
        start += 1
    if not text.startswith("{\\rtf", start):
        raise ClipboardError("malformed RTF on the clipboard")

    stack: list[tuple[int, bool]] = []
    uc = 1
    skip = False
    codepage = "cp1252"
    fallback_skip = 0
    hex_buf = bytearray()
    pending_high: int | None = None
    out: list[str] = []

    def flush_hex() -> None:
        nonlocal pending_high
        if not hex_buf:
            return
        if pending_high is not None:
            raise ClipboardError("malformed RTF: unpaired surrogate")
        try:
            out.append(bytes(hex_buf).decode(codepage))
        except (UnicodeDecodeError, LookupError):
            raise ClipboardError("malformed RTF: invalid character escape") from None
        hex_buf.clear()

    def emit(piece: str) -> None:
        nonlocal pending_high
        flush_hex()
        if pending_high is not None:
            raise ClipboardError("malformed RTF: unpaired surrogate")
        out.append(piece)

    i = start
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "{":
            flush_hex()
            if len(stack) >= _MAX_RTF_DEPTH:
                raise ClipboardError("malformed RTF: nesting too deep")
            stack.append((uc, skip))
            i += 1
        elif ch == "}":
            flush_hex()
            if not stack:
                raise ClipboardError("malformed RTF: unbalanced braces")
            uc, skip = stack.pop()
            fallback_skip = 0
            i += 1
            if not stack:
                if text[i:].strip():
                    raise ClipboardError("malformed RTF: trailing data")
                break
        elif ch in ("\r", "\n"):
            i += 1
        elif ch == "\\":
            i += 1
            if i >= n:
                raise ClipboardError("malformed RTF: trailing backslash")
            esc = text[i]
            if esc == "'":
                if i + 3 > n:
                    raise ClipboardError("malformed RTF: truncated hex escape")
                hh = text[i + 1 : i + 3]
                if hh[0] not in _HEX_DIGITS or hh[1] not in _HEX_DIGITS:
                    raise ClipboardError("malformed RTF: invalid hex escape")
                val = int(hh, 16)
                i += 3
                if not skip:
                    if fallback_skip > 0:
                        fallback_skip -= 1
                    else:
                        hex_buf.append(val)
            elif esc == "*":
                skip = True
                i += 1
            elif esc in ("\\", "{", "}"):
                i += 1
                if not skip:
                    if fallback_skip > 0:
                        fallback_skip -= 1
                    else:
                        emit(esc)
            elif esc == "~":
                i += 1
                if not skip:
                    if fallback_skip > 0:
                        fallback_skip -= 1
                    else:
                        emit("\xa0")
            elif esc == "_":
                i += 1
                if not skip:
                    if fallback_skip > 0:
                        fallback_skip -= 1
                    else:
                        emit("-")
            elif esc == "-":
                i += 1
            elif esc in ("\r", "\n"):
                i += 1
                if not skip:
                    fallback_skip = 0
                    emit("\n")
            elif esc.isalpha():
                j = i
                while j < n and text[j].isalpha():
                    j += 1
                word = text[i:j]
                param: int | None = None
                k = j
                if k < n and text[k] == "-":
                    k += 1
                    if k >= n or not text[k].isdigit():
                        raise ClipboardError("malformed RTF: invalid parameter")
                if k < n and text[k].isdigit():
                    while k < n and text[k].isdigit():
                        k += 1
                    param = int(text[j:k])
                    j = k
                if j < n and text[j] == " ":
                    j += 1
                i = j

                if word in _RTF_SKIP_DESTINATIONS:
                    skip = True
                elif word == "ansicpg":
                    if param is None:
                        raise ClipboardError("malformed RTF: missing code page")
                    codepage = _resolve_codepage(param)
                elif word == "ansi":
                    codepage = "cp1252"
                elif word == "mac":
                    codepage = "mac_roman"
                elif word == "pc":
                    codepage = "cp437"
                elif word == "pca":
                    codepage = "cp850"
                elif word == "uc":
                    if param is None or param < 0:
                        raise ClipboardError("malformed RTF: invalid uc count")
                    uc = param
                elif word == "u":
                    if param is None:
                        raise ClipboardError("malformed RTF: missing unicode value")
                    if not skip:
                        flush_hex()
                        if -32768 <= param < 0:
                            cp = param + 65536
                        elif 0 <= param <= 0x10FFFF:
                            cp = param
                        else:
                            raise ClipboardError("malformed RTF: unicode out of range")
                        if 0xD800 <= cp <= 0xDBFF:
                            if pending_high is not None:
                                raise ClipboardError("malformed RTF: unpaired surrogate")
                            pending_high = cp
                        elif 0xDC00 <= cp <= 0xDFFF:
                            if pending_high is None:
                                raise ClipboardError("malformed RTF: unpaired surrogate")
                            combined = 0x10000 + ((pending_high - 0xD800) << 10) + (cp - 0xDC00)
                            pending_high = None
                            out.append(chr(combined))
                        else:
                            if pending_high is not None:
                                raise ClipboardError("malformed RTF: unpaired surrogate")
                            out.append(chr(cp))
                        fallback_skip = uc
                elif not skip:
                    if word in ("par", "line"):
                        fallback_skip = 0
                        emit("\n")
                    elif word == "tab":
                        fallback_skip = 0
                        emit("\t")
                    elif word in _RTF_SPECIAL_CHARS:
                        fallback_skip = 0
                        emit(_RTF_SPECIAL_CHARS[word])
            else:
                i += 1
        else:
            i += 1
            if not skip:
                if fallback_skip > 0:
                    fallback_skip -= 1
                else:
                    emit(ch)

    if stack:
        raise ClipboardError("malformed RTF: unclosed group")
    flush_hex()
    if pending_high is not None:
        raise ClipboardError("malformed RTF: unpaired surrogate")
    return "".join(out)


def _resolve_codepage(num: int) -> str:
    if num <= 0:
        raise ClipboardError("malformed RTF: invalid code page")
    enc = _RTF_CODEPAGES.get(num, f"cp{num}")
    try:
        codecs.lookup(enc)
    except LookupError:
        raise ClipboardError("malformed RTF: unsupported code page") from None
    return enc
