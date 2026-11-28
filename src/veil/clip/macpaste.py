"""macOS sanitize-then-paste via CoreGraphics CGEventPost and Accessibility checks.

No pyobjc and no AppleScript UI-scripting subprocess: uses ctypes against
ApplicationServices (AXIsProcessTrusted) and CoreGraphics (CGEventCreateKeyboardEvent,
CGEventSetFlags, CGEventPost, CGEventSourceFlagsState).

Requires macOS Accessibility permission for the running host (Terminal, iTerm2,
Shortcuts, or a signed app). Fails closed to `Refused` when permission is missing.
"""

import ctypes
import functools
import sys
import time
from collections.abc import Callable, Sequence

_APPLICATION_SERVICES = (
    "/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices"
)
_CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
_CORE_GRAPHICS = "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"

_HID_SYSTEM_STATE = 1  # kCGEventSourceStateHIDSystemState
_HID_EVENT_TAP = 0  # kCGHIDEventTap

_VK_ANSI_V = 0x09

# CGEventFlags
_FLAG_SHIFT = 0x00020000
_FLAG_CONTROL = 0x00040000
_FLAG_OPTION = 0x00080000
_FLAG_COMMAND = 0x00100000
_MODIFIER_MASK = _FLAG_SHIFT | _FLAG_CONTROL | _FLAG_OPTION | _FLAG_COMMAND

_POLL_STEP = 0.01

CHORDS: dict[str, tuple[int, int]] = {
    "cmd+v": (_VK_ANSI_V, _FLAG_COMMAND),
}


class PasteError(Exception):
    """A macOS paste injection failure; the message is value-free."""


class Refused(PasteError):
    """Accessibility permission was not granted to press keys."""


@functools.cache
def _frameworks() -> tuple[ctypes.CDLL, ctypes.CDLL, ctypes.CDLL]:
    if sys.platform != "darwin":
        raise PasteError("macOS paste is only available on macOS")
    try:
        asvc = ctypes.CDLL(_APPLICATION_SERVICES)
        cf = ctypes.CDLL(_CORE_FOUNDATION)
        cg = ctypes.CDLL(_CORE_GRAPHICS)
        asvc.AXIsProcessTrusted.argtypes = ()
        asvc.AXIsProcessTrusted.restype = ctypes.c_bool
        cg.CGEventSourceFlagsState.argtypes = (ctypes.c_int32,)
        cg.CGEventSourceFlagsState.restype = ctypes.c_uint64
        cg.CGEventCreateKeyboardEvent.argtypes = (
            ctypes.c_void_p,
            ctypes.c_uint16,
            ctypes.c_bool,
        )
        cg.CGEventCreateKeyboardEvent.restype = ctypes.c_void_p
        cg.CGEventSetFlags.argtypes = (ctypes.c_void_p, ctypes.c_uint64)
        cg.CGEventSetFlags.restype = None
        cg.CGEventPost.argtypes = (ctypes.c_uint32, ctypes.c_void_p)
        cg.CGEventPost.restype = None
        cf.CFRelease.argtypes = (ctypes.c_void_p,)
        cf.CFRelease.restype = None
    except (OSError, AttributeError):
        raise PasteError("macOS Accessibility/CoreGraphics could not be loaded") from None
    return asvc, cf, cg


def is_trusted() -> bool:
    """Whether this process holds macOS Accessibility permission."""
    asvc, _, _ = _frameworks()
    return bool(asvc.AXIsProcessTrusted())


def held_modifiers() -> int:
    """Bitmask of Shift/Control/Option/Command currently held at the HID level."""
    _, _, cg = _frameworks()
    return int(cg.CGEventSourceFlagsState(_HID_SYSTEM_STATE)) & _MODIFIER_MASK


def wait_for_modifiers(
    deadline: float,
    *,
    flags: Callable[[], int] | None = None,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Wait until hotkey modifiers are released or `deadline` passes.

    Returns immediately when no modifiers are held or `deadline` is already reached, so
    both fast taps and tests with zero wait incur no delay.
    """
    read_flags = held_modifiers if flags is None else flags
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            return
        if read_flags() == 0:
            return
        sleep(min(_POLL_STEP, remaining))


def post_chord(keycode: int, flags: int) -> None:
    """Synthesize a single key-down + key-up with exact modifier flags."""
    _, cf, cg = _frameworks()
    for down in (True, False):
        event = cg.CGEventCreateKeyboardEvent(None, keycode, down)
        if not event:
            raise PasteError("could not create keyboard event")
        try:
            cg.CGEventSetFlags(event, flags)
            cg.CGEventPost(_HID_EVENT_TAP, event)
        finally:
            cf.CFRelease(event)


class MacKeyboard:
    """Same open/press/close contract as `portal.RemoteKeyboard`, backed by CGEventPost."""

    def open(self, restore_token: str | None = None) -> str | None:
        del restore_token
        if not is_trusted():
            raise Refused("Accessibility permission is required to paste")
        return None

    def press(self, keys: Sequence[int]) -> None:
        if len(keys) != 2:
            raise PasteError("invalid macOS paste chord")
        keycode, flags = keys
        post_chord(keycode, flags)

    def close(self) -> None:
        return None
