"""An in-memory clipboard with the `veil.clip.io.Clipboard` interface (never the real one).

Each selection holds an offer {mime type: bytes}, like a Wayland clipboard; reads go through
the real `classify`, so MIME handling matches production.
"""

from veil.clip import recent
from veil.clip.io import WRITE_TYPE, ClipContent, Kind, Selection, classify, plain_only
from veil.errors import ClipboardError


class FakeBoard:
    name = "fake"

    def __init__(self, clipboard: dict[str, bytes] | None = None, primary=None) -> None:
        self.offers: dict[Selection, dict[str, bytes] | None] = {
            Selection.CLIPBOARD: clipboard,
            Selection.PRIMARY: primary,
        }
        self.reads: list[Selection] = []
        self.writes: list[str] = []
        self.clears: list[Selection] = []
        self.fail_read = self.fail_write = self.fail_clear = False

    @classmethod
    def with_text(cls, text: str, *, html: str | None = None, primary=None) -> "FakeBoard":
        offer = {"text/plain;charset=utf-8": text.encode(), "text/plain": text.encode()}
        if html is not None:
            offer["text/html"] = html.encode()
        return cls(offer, primary)

    def read(self, selection: Selection = Selection.CLIPBOARD) -> ClipContent:
        self.reads.append(selection)
        if self.fail_read:
            raise ClipboardError("wl-paste failed (exit 1)")
        offer = self.offers[selection]
        if offer is None:
            return ClipContent(Kind.EMPTY)
        kind, plain = classify(list(offer))
        secret = any(t.lower() == "x-kde-passwordmanagerhint" for t in offer)
        if plain is None:
            return ClipContent(kind, secret=secret, type_count=len(offer))
        return ClipContent(
            kind,
            offer[plain].decode(),
            secret=secret,
            type_count=len(offer),
            plain_only=plain_only(list(offer)),
        )

    def write_text(self, text: str) -> None:
        if self.fail_write:
            raise ClipboardError("wl-copy failed (exit 1)")
        self.writes.append(text)
        self.offers[Selection.CLIPBOARD] = {WRITE_TYPE: text.encode()}
        recent.remember(text)  # as the real backends do

    def clear(self, selection: Selection = Selection.CLIPBOARD) -> None:
        if self.fail_clear:
            raise ClipboardError("wl-copy --clear failed (exit 1)")
        self.clears.append(selection)
        self.offers[selection] = None

    def text(self, selection: Selection = Selection.CLIPBOARD) -> str | None:
        offer = self.offers[selection]
        if offer is None:
            return None
        _, plain = classify(list(offer))
        return None if plain is None else offer[plain].decode()

    def types(self, selection: Selection = Selection.CLIPBOARD) -> list[str]:
        return list(self.offers[selection] or {})
