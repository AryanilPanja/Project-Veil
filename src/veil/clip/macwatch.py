"""The macOS copy watcher (ADR-0031 on macOS): one resident process instead of one per copy.

macOS has no clipboard-change event for ordinary processes, so the watcher polls the
pasteboard's change counter (`NSPasteboard.changeCount`, about 1 us per read) and runs a normal
`veil clip sanitize --auto` in this process when it moves. Starting Python per copy would cost
about 50 ms; here a copy costs only the sanitize itself (about 8 ms).

- Polling interval: ACTIVE_SECONDS while someone used the keyboard or mouse in the last
  IDLE_AFTER_SECONDS, IDLE_SECONDS otherwise (from CoreGraphics' idle time, no permission
  needed). A copy made after an idle stretch can wait up to IDLE_SECONDS.
- Its own writes move the counter too: the counter is re-read after each sanitize, so they
  never trigger another run.
- The ON time is checked every CLOCK_CHECK_SECONDS; when it is up, veil switches OFF, which
  unloads the launchd agent and ends this process. If veil is OFF the loop exits (status 0, so
  launchd does not restart it).
- Nothing is kept between copies: every sanitize loads the engine from the encrypted cache.
"""

import ctypes
import functools
import time
from collections.abc import Callable

ACTIVE_SECONDS = 0.25
IDLE_SECONDS = 1.0
IDLE_AFTER_SECONDS = 60.0
CLOCK_CHECK_SECONDS = 30.0

_CORE_GRAPHICS = "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"
_HID_SYSTEM_STATE = 1  # kCGEventSourceStateHIDSystemState
_ANY_INPUT_EVENT = 0xFFFFFFFF  # kCGAnyInputEventType


@functools.cache
def _core_graphics() -> ctypes.CDLL | None:
    try:
        cg = ctypes.CDLL(_CORE_GRAPHICS)
    except OSError:
        return None
    cg.CGEventSourceSecondsSinceLastEventType.argtypes = (ctypes.c_int32, ctypes.c_uint32)
    cg.CGEventSourceSecondsSinceLastEventType.restype = ctypes.c_double
    return cg


def idle_seconds() -> float:
    """Seconds since the last keyboard or mouse event; 0 (treated as active) if unknown."""
    cg = _core_graphics()
    if cg is None:
        return 0.0
    return float(cg.CGEventSourceSecondsSinceLastEventType(_HID_SYSTEM_STATE, _ANY_INPUT_EVENT))


def interval(idle: float) -> float:
    return ACTIVE_SECONDS if idle < IDLE_AFTER_SECONDS else IDLE_SECONDS


def run(
    change_count: Callable[[], int],
    on_copy: Callable[[], None],
    on_clock: Callable[[], bool],
    *,
    idle: Callable[[], float] = idle_seconds,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Poll until `on_clock()` returns False (veil is OFF or its time is up).

    `on_copy` runs a sanitize; it must not raise (the caller fails closed and reports).
    """
    if not on_clock():
        return
    last = change_count()
    next_clock = monotonic() + CLOCK_CHECK_SECONDS
    while True:
        sleep(interval(idle()))
        count = change_count()
        if count != last:
            on_copy()
            last = change_count()  # veil's own write moved it too
        if monotonic() >= next_clock:
            if not on_clock():
                return
            next_clock = monotonic() + CLOCK_CHECK_SECONDS
