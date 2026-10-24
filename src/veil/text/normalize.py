"""Canonical form of text for comparison (ADR-0026).

canon(s) = NFKC → drop invisible format characters → casefold → collapse whitespace → strip.

Zero-width joiner/non-joiner (U+200D/U+200C) are kept: they change meaning in Bengali and
Devanagari. Zero-width space, word joiner, BOM and soft hyphen are dropped: they are invisible and
are exactly what someone would use (deliberately or by copy-paste) to dodge a match.
"""

import unicodedata

DROPPED = frozenset({"\u200b", "\u2060", "\ufeff", "\u00ad"})


def nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def fold_with_map(text: str) -> tuple[str, list[int]]:
    """Fold an already-NFKC string for matching, remembering where each output char came from.

    Returns (folded, origin) where origin[k] is the index in `text` of the character that
    produced folded[k]. Whitespace runs become one space; dropped characters vanish; casefold may
    expand one character into several (ß → ss), all mapped to the same origin index.
    """
    out: list[str] = []
    origin: list[int] = []
    in_space = False
    for i, ch in enumerate(text):
        if ch in DROPPED:
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
