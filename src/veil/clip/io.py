"""Clipboard I/O (M2.1, ADR-0023): read plain text only, write plain text only.

Reading classifies what the clipboard offers before asking for any data:
- TEXT: a plain-text type is offered; its bytes are read as UTF-8. Rich types offered alongside
  (HTML, RTF) are never requested.
- RICH_ONLY: only rich text (HTML, RTF, a file list…): nothing to sanitize as plain text.
- NON_TEXT: something else only (an image, a file): not handled in v0.1 (ADR-0014).
- EMPTY: nothing is copied.

Writing offers exactly one type, `text/plain` (wl-copy may add its plain-text aliases such as
UTF8_STRING), so a site can't paste a rich, unsanitized version. Writing a clipboard replaces
every type the previous owner offered.

Backends: wl-clipboard on Wayland; xsel on X11 (basic fallback: xsel can't list types, so it
only ever sees TEXT or EMPTY). `detect()` picks one from the environment.
"""

import os
import shutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import Protocol

from veil.clip import proc, recent
from veil.errors import ClipboardError

MAX_CLIP_BYTES = 10 * 1024 * 1024
TIMEOUT_SECONDS = 5.0
WRITE_TYPE = "text/plain"

# Plain-text types, best first. Compared after `_norm` (lower case, no spaces).
PLAIN_TYPES = ("text/plain;charset=utf-8", "utf8_string", "text/plain", "string", "text")
# Rich or structured text that is not plain text: present without a plain type → RICH_ONLY.
RICH_TYPES = frozenset({
    "application/rtf", "application/x-rtf", "application/x-qt-richtext", "application/xhtml+xml",
    "x-special/gnome-copied-files", "application/x-kde4-urilist", "compound_text",
})  # fmt: skip
# KDE password managers mark copied secrets with this type; clipboard histories skip them.
PASSWORD_HINT = "x-kde-passwordmanagerhint"  # noqa: S105 - a MIME type name, not a secret
_EMPTY_MARKERS = (b"nothing is copied", b"no selection")


class Selection(StrEnum):
    CLIPBOARD = "clipboard"
    PRIMARY = "primary"  # the highlighted text (middle-click paste)


class Kind(Enum):
    TEXT = "text"
    RICH_ONLY = "rich-only"
    NON_TEXT = "non-text"
    EMPTY = "empty"


@dataclass(frozen=True)
class ClipContent:
    kind: Kind
    text: str | None = None  # only for TEXT
    secret: bool = False  # the source marked it as a password (x-kde-passwordManagerHint)
    type_count: int = 0
    plain_only: bool = False  # TEXT offered only as plain-text types (as veil writes it)

    def __repr__(self) -> str:  # never the text
        size = "None" if self.text is None else f"<{len(self.text)} chars>"
        return (
            f"ClipContent(kind={self.kind.name}, text={size}, secret={self.secret}, "
            f"type_count={self.type_count})"
        )

    __str__ = __repr__


class Clipboard(Protocol):
    name: str

    def read(self, selection: Selection = Selection.CLIPBOARD) -> ClipContent: ...

    def write_text(self, text: str) -> None: ...

    def clear(self, selection: Selection = Selection.CLIPBOARD) -> None: ...


Capture = Callable[..., proc.Captured]
Feed = Callable[..., int]


def classify(types: Sequence[str]) -> tuple[Kind, str | None]:
    """The content kind for an offered type list, and the plain type to request (if TEXT)."""
    offered = {_norm(t): t for t in types if t.strip()}
    for plain in PLAIN_TYPES:
        if plain in offered:
            return Kind.TEXT, offered[plain]
    content = [t for t in offered if not _is_meta(t)]
    if not content:
        return Kind.EMPTY, None
    if any(t.startswith("text/") or t in RICH_TYPES for t in content):
        return Kind.RICH_ONLY, None
    return Kind.NON_TEXT, None


class WaylandClipboard:
    name = "wl-clipboard"

    def __init__(
        self,
        wl_paste: str,
        wl_copy: str,
        *,
        capture: Capture = proc.capture,
        feed: Feed = proc.feed,
        timeout: float = TIMEOUT_SECONDS,
        limit: int = MAX_CLIP_BYTES,
    ) -> None:
        self._paste, self._copy = wl_paste, wl_copy
        self._capture, self._feed = capture, feed
        self._timeout, self._limit = timeout, limit

    def read(self, selection: Selection = Selection.CLIPBOARD) -> ClipContent:
        listed = self._capture(
            [self._paste, *_primary(selection), "--list-types"],
            timeout=self._timeout,
            limit=64 * 1024,
        )
        if listed.returncode != 0:
            if _says_empty(listed.stderr):
                return ClipContent(Kind.EMPTY)
            raise ClipboardError(f"wl-paste failed (exit {listed.returncode})")
        types = _decode_types(listed.stdout)
        kind, plain = classify(types)
        secret = any(_norm(t) == PASSWORD_HINT for t in types)
        if plain is None:
            return ClipContent(kind, secret=secret, type_count=len(types))
        data = self._capture(
            [self._paste, *_primary(selection), "--no-newline", "--type", plain],
            timeout=self._timeout,
            limit=self._limit,
        )
        if data.returncode != 0:
            if _says_empty(data.stderr):  # the owner changed in between
                return ClipContent(Kind.EMPTY)
            raise ClipboardError(f"wl-paste failed (exit {data.returncode})")
        return ClipContent(
            Kind.TEXT,
            _decode(data.stdout),
            secret=secret,
            type_count=len(types),
            plain_only=plain_only(types),
        )

    def write_text(self, text: str) -> None:
        code = self._feed(
            [self._copy, "--type", WRITE_TYPE], text.encode("utf-8"), timeout=self._timeout
        )
        if code != 0:
            raise ClipboardError(f"wl-copy failed (exit {code})")
        recent.remember(text)  # the copy watcher must not take this for a new copy

    def clear(self, selection: Selection = Selection.CLIPBOARD) -> None:
        code = self._feed([self._copy, *_primary(selection), "--clear"], b"", timeout=self._timeout)
        if code != 0:
            raise ClipboardError(f"wl-copy --clear failed (exit {code})")


class XselClipboard:
    """X11 fallback. xsel only transfers strings (UTF8_STRING), so rich types never reach it."""

    name = "xsel"

    def __init__(
        self,
        xsel: str,
        *,
        capture: Capture = proc.capture,
        feed: Feed = proc.feed,
        timeout: float = TIMEOUT_SECONDS,
        limit: int = MAX_CLIP_BYTES,
    ) -> None:
        self._xsel = xsel
        self._capture, self._feed = capture, feed
        self._timeout, self._limit = timeout, limit

    def read(self, selection: Selection = Selection.CLIPBOARD) -> ClipContent:
        data = self._capture(
            [self._xsel, _xsel_flag(selection), "--output"],
            timeout=self._timeout,
            limit=self._limit,
        )
        if data.returncode != 0:
            raise ClipboardError(f"xsel failed (exit {data.returncode})")
        if not data.stdout:
            return ClipContent(Kind.EMPTY)
        return ClipContent(Kind.TEXT, _decode(data.stdout), type_count=1, plain_only=True)

    def write_text(self, text: str) -> None:
        code = self._feed(
            [self._xsel, "--clipboard", "--input"], text.encode("utf-8"), timeout=self._timeout
        )
        if code != 0:
            raise ClipboardError(f"xsel failed (exit {code})")
        recent.remember(text)

    def clear(self, selection: Selection = Selection.CLIPBOARD) -> None:
        code = self._feed(
            [self._xsel, _xsel_flag(selection), "--clear"], b"", timeout=self._timeout
        )
        if code != 0:
            raise ClipboardError(f"xsel --clear failed (exit {code})")


def detect(
    env: Mapping[str, str] | None = None, which: Callable[[str], str | None] = shutil.which
) -> Clipboard:
    """wl-clipboard when a Wayland display is set, else xsel when an X display is set."""
    env = os.environ if env is None else env
    if env.get("WAYLAND_DISPLAY"):
        wl_paste, wl_copy = which("wl-paste"), which("wl-copy")
        if wl_paste and wl_copy:
            return WaylandClipboard(wl_paste, wl_copy)
    if env.get("DISPLAY"):
        xsel = which("xsel")
        if xsel:
            return XselClipboard(xsel)
    raise ClipboardError(
        "no clipboard tool found: needs wl-clipboard (Wayland) or xsel (X11) and a display"
    )


def plain_only(types) -> bool:
    """Only plain-text (and descriptive) types: what veil itself writes."""
    offered = [_norm(t) for t in types if t.strip()]
    return bool(offered) and all(t in PLAIN_TYPES or _is_meta(t) for t in offered)


def _norm(mime: str) -> str:
    return "".join(mime.split()).lower()


def _is_meta(norm_type: str) -> bool:
    """Types that describe the selection rather than carry content."""
    return norm_type == PASSWORD_HINT or norm_type in {
        "targets", "multiple", "timestamp", "save_targets", "delete", "x-kde-onlyreplaceempty",
    }  # fmt: skip


def _primary(selection: Selection) -> list[str]:
    return ["--primary"] if selection is Selection.PRIMARY else []


def _xsel_flag(selection: Selection) -> str:
    return "--primary" if selection is Selection.PRIMARY else "--clipboard"


def _says_empty(stderr: bytes) -> bool:
    lowered = stderr.lower()
    return any(marker in lowered for marker in _EMPTY_MARKERS)


def _decode_types(raw: bytes) -> list[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ClipboardError("the clipboard offered an unreadable type list") from None
    return [line.strip() for line in text.splitlines() if line.strip()]


def _decode(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ClipboardError("the clipboard text is not valid UTF-8") from None
