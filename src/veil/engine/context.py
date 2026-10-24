"""Context guards, shared by the matcher and the reference translator.

A context-guarded form counts only if one of its entity's keywords occurs, bounded (ADR-0026),
within the window around the match. Bounded on purpose: a degree keyword "MS" must not be "found"
inside "items". The window is per entity (`meta context_window`), default DEFAULT_WINDOW.
"""

from veil.persona.entities import Entity
from veil.text.containment import contains_bounded

DEFAULT_WINDOW = 200


def window_of(entity: Entity) -> int:
    value = entity.meta_value("context_window")
    return int(value) if value.isdigit() else DEFAULT_WINDOW


def context_near(text: str, start: int, end: int, entity: Entity) -> bool:
    if not entity.contexts:
        return True
    window = window_of(entity)
    nearby = text[max(0, start - window) : end + window]
    return any(c.strip() and contains_bounded(c, nearby) for c in entity.contexts)


def overlaps_any(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < s_end and s_start < end for s_start, s_end in spans)
