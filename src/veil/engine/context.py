"""Context guards, shared by the matcher and the reference translator.

A context-guarded form counts only if one of its entity's keywords occurs, bounded (ADR-0026),
within the entity's window (`meta context_window`, default DEFAULT_WINDOW). Bounded on purpose:
a degree keyword "MS" must not be "found" inside "items".

The window is measured in length-independent units, not characters: every character outside the
already-replaced spans counts 1, every replaced span counts 1 in total. Translation changes
lengths ("JANE DOE" → "ALEX SMITH"), so a character window that held forward could fail in
reverse and break the round trip. The replaced spans come from the *unguarded* forms, which
match the same text in both directions, so the distance between a guarded phrase and its
keyword is the same forward and in reverse.
"""

from veil.persona.model import Entity
from veil.text.containment import PreparedText, Span, find_bounded

DEFAULT_WINDOW = 200


def window_of(entity: Entity) -> int:
    value = entity.meta_value("context_window")
    return int(value) if value.isdigit() else DEFAULT_WINDOW


class Distances:
    """Unit distances over a text, given the (sorted, non-overlapping) replaced spans."""

    def __init__(self, length: int, spans: list[tuple[int, int]]) -> None:
        prefix = [0] * (length + 1)
        units = 0
        span_iter = iter(spans)
        current = next(span_iter, None)
        for pos in range(length):
            while current is not None and pos >= current[1]:
                current = next(span_iter, None)
            if current is None or pos < current[0]:
                units += 1  # an ordinary character
            elif pos == current[0]:
                units += 1  # a replaced span: one unit, whatever its length
            prefix[pos + 1] = units
        self._prefix = prefix

    def gap(self, a: tuple[int, int], b: tuple[int, int]) -> int:
        """Units strictly between two spans (0 if they touch or overlap)."""
        if b[0] >= a[1]:
            return self._prefix[b[0]] - self._prefix[a[1]]
        if a[0] >= b[1]:
            return self._prefix[a[0]] - self._prefix[b[1]]
        return 0


def context_near(
    text: PreparedText,
    start: int,
    end: int,
    entity: Entity,
    distances: Distances | None,
    found: dict[str, list[Span]],
) -> bool:
    """Is a context keyword within the entity's window? `found` caches keyword occurrences."""
    if not entity.contexts:
        return True
    if distances is None:
        raise ValueError("distances are required for context-guarded forms")
    window = window_of(entity)
    for keyword in entity.contexts:
        if not keyword.strip():
            continue
        if keyword not in found:
            found[keyword] = find_bounded(keyword, text)
        if any(distances.gap((start, end), (s.start, s.end)) <= window for s in found[keyword]):
            return True
    return False


def overlaps_any(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < s_end and s_start < end for s_start, s_end in spans)
