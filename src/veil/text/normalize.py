"""Canonical form of text for comparison (ADR-0026).

canon(s) = NFKC → drop invisible format characters → casefold → collapse whitespace → strip.

Dropped: every Unicode format character (category Cf: zero-width space, word joiner, BOM, soft
hyphen, bidi overrides such as U+202E, …) plus the combining grapheme joiner and variation
selectors. They are invisible and are exactly what someone would use, deliberately or by
copy-paste, to dodge a match. Kept: zero-width joiner and non-joiner (U+200D/U+200C), which change
meaning in Bengali and Devanagari.
"""

import unicodedata

KEPT_FORMAT_CHARS = frozenset({chr(0x200C), chr(0x200D)})
_EXTRA_DROPPED = frozenset(
    {chr(0x034F)}  # combining grapheme joiner (category Mn)
    | {chr(cp) for cp in range(0xFE00, 0xFE10)}  # variation selectors 1-16
)


def is_dropped(ch: str) -> bool:
    if ch in KEPT_FORMAT_CHARS:
        return False
    return ch in _EXTRA_DROPPED or unicodedata.category(ch) == "Cf"


def nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def fold_with_map(text: str) -> tuple[str, list[int]]:
    """Fold an already-NFKC string for matching, remembering where each output char came from.

    Returns (folded, origin) where origin[k] is the index in `text` of the character that
    produced folded[k]. Whitespace runs become one space; dropped characters vanish; casefold may
    expand one character into several (ß → ss), all mapped to the same origin index.

    Offsets refer to the NFKC text, not the raw input. Code that rewrites the user's text (M1)
    must map back to raw offsets itself, or it would silently apply NFKC to the user's text.
    """
    out: list[str] = []
    origin: list[int] = []
    in_space = False
    for i, ch in enumerate(text):
        if is_dropped(ch):
            continue
        if ch.isspace():
            if not in_space:
                out.append(" ")
                origin.append(i)
            in_space = True
            continue
        in_space = False
        for produced in ch.casefold():
            out.append(produced)
            origin.append(i)
    return "".join(out), origin


def canon(text: str) -> str:
    folded, _ = fold_with_map(nfkc(text))
    return folded.strip(" ")
