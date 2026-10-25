"""Canonical form of text for comparison (ADR-0026).

canon(s) = NFKC → drop invisible format characters → casefold → collapse whitespace → strip.

Dropped: every Unicode format character (category Cf: zero-width space, word joiner, BOM, soft
hyphen, bidi overrides such as U+202E, …) plus the combining grapheme joiner and variation
selectors. They are invisible and are exactly what someone would use, deliberately or by
copy-paste, to dodge a match. Kept: zero-width joiner and non-joiner (U+200D/U+200C), which change
meaning in Bengali and Devanagari.
"""

import functools
import re
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


_WHITESPACE_RUN = re.compile(r"\s+")
_NEEDS_COLLAPSE = re.compile(r"[^\S ]|  ")  # any whitespace but a single space


_ASCII_RUN = re.compile(r"[\x00-\x7f]+")


def fold_with_map(text: str) -> tuple[str, list[int]]:
    """Same result as `_fold_with_map_general`, faster: ASCII stretches are folded in bulk.

    For ASCII, casefold is lower(), no character is ever dropped (no ASCII character is in
    category Cf), and `str.isspace` equals the regex `\\s`; so only whitespace runs need work.
    Non-ASCII characters go through the general per-character rules. The whitespace-run state
    is carried across stretches, so a run spanning both kinds still collapses to one space.
    """
    if text.isascii() and not _NEEDS_COLLAPSE.search(text):
        return text.lower(), list(range(len(text)))
    out: list[str] = []
    origin: list[int] = []
    in_space = False
    pos = 0
    for run in _ASCII_RUN.finditer(text):
        in_space = _fold_general_into(text, pos, run.start(), out, origin, in_space)
        in_space = _fold_ascii_into(text, run.start(), run.end(), out, origin, in_space)
        pos = run.end()
    _fold_general_into(text, pos, len(text), out, origin, in_space)
    return "".join(out), origin


def _fold_ascii_into(
    text: str, start: int, end: int, out: list[str], origin: list[int], in_space: bool
) -> bool:
    lowered = text[start:end].lower()
    pos = 0
    for run in _WHITESPACE_RUN.finditer(lowered):
        if run.start() > pos:
            out.append(lowered[pos : run.start()])
            origin.extend(range(start + pos, start + run.start()))
            in_space = False
        if not in_space:
            out.append(" ")
            origin.append(start + run.start())
        in_space = True
        pos = run.end()
    if pos < len(lowered):
        out.append(lowered[pos:])
        origin.extend(range(start + pos, end))
        in_space = False
    return in_space


def _fold_general_into(
    text: str, start: int, end: int, out: list[str], origin: list[int], in_space: bool
) -> bool:
    for i in range(start, end):
        ch = text[i]
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
    return in_space


def _fold_with_map_general(text: str) -> tuple[str, list[int]]:
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


@functools.lru_cache(maxsize=65536)
def canon(text: str) -> str:
    """Cached: the engine canonicalizes the same few thousand forms over and over. Pure, so
    caching can't change a result. The cache lives only in this process's memory."""
    folded, _ = fold_with_map(nfkc(text))
    return folded.strip(" ")
