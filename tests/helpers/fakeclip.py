"""An in-memory clipboard with the `veil.clip.io.Clipboard` interface (never the real one).

Each selection holds an offer {mime type: bytes}, like a Wayland clipboard; reads go through
the real `classify`, so MIME handling matches production.
"""

from veil.clip import recent, richtext
from veil.clip.imagemeta import ImageFormat
from veil.clip.io import (
    IMAGE_MIME_TYPES,
    WRITE_TYPE,
    ClipContent,
    Kind,
    Selection,
    classify,
    image_mime,
    pick_image,
    pick_rich,
    plain_only,
)
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
        self.image_writes: list[tuple[bytes, ImageFormat]] = []
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
        types = list(offer)
        kind, plain = classify(types)
        secret = any(t.lower() == "x-kde-passwordmanagerhint" for t in offer)
        if kind is Kind.TEXT and plain is not None:
            return ClipContent(
                kind,
                offer[plain].decode(),
                secret=secret,
                type_count=len(offer),
                plain_only=plain_only(types),
            )
        if kind is Kind.IMAGE:
            img_type = pick_image(types)
            if secret or img_type is None or img_type.lower() not in IMAGE_MIME_TYPES:
                return ClipContent(Kind.IMAGE, secret=secret, type_count=len(offer))
            return ClipContent(
                Kind.IMAGE,
                secret=secret,
                type_count=len(offer),
                image=offer[img_type],
                image_format=IMAGE_MIME_TYPES[img_type.lower()],
            )
        if kind is Kind.RICH_ONLY:
            rich = pick_rich(types)
            if secret or rich is None:
                return ClipContent(Kind.RICH_ONLY, secret=secret, type_count=len(offer))
            rich_type, rich_fmt = rich
            return ClipContent(
                Kind.RICH_ONLY,
                richtext.to_text(offer[rich_type], rich_fmt),
                secret=secret,
                type_count=len(offer),
                plain_only=False,
            )
        return ClipContent(kind, secret=secret, type_count=len(offer))

    def write_text(self, text: str) -> None:
        recent.remember(text)  # as the real backends do: just before the write
        if self.fail_write:
            raise ClipboardError("wl-copy failed (exit 1)")
        self.writes.append(text)
        self.offers[Selection.CLIPBOARD] = {WRITE_TYPE: text.encode()}

    def write_image(self, data: bytes, fmt: ImageFormat) -> None:
        recent.remember_bytes(data)
        if self.fail_write:
            raise ClipboardError("wl-copy failed (exit 1)")
        self.image_writes.append((data, fmt))
        self.offers[Selection.CLIPBOARD] = {image_mime(fmt): data}

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

    def image(self, selection: Selection = Selection.CLIPBOARD) -> bytes | None:
        offer = self.offers[selection]
        if offer is None:
            return None
        img_type = pick_image(list(offer))
        return None if img_type is None else offer[img_type]

    def types(self, selection: Selection = Selection.CLIPBOARD) -> list[str]:
        return list(self.offers[selection] or {})
