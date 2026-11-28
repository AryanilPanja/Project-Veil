"""macOS menu-bar status & quick-toggle app (`veil menubar`).

Runs an AppKit accessory application (`NSStatusBar`) via ctypes and the Objective-C runtime:
no pyobjc, no helper app bundle, no plaintext secrets in this process. Displays `veil ON` /
`veil OFF` in the menu bar and lets a human switch ON (forever, 30 min, 2 hours), switch OFF
(confirmed through the desktop dialog), sanitize or restore the clipboard, or open the
exported Shortcuts.app workflows.
"""

import ctypes
import functools
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from veil import killswitch, paths, shortcuts, ui
from veil.clip import notify
from veil.clip.notify import Message
from veil.errors import VeilError
from veil.exitcodes import ExitCode

POLL_SECONDS = 5.0
_TICK_SECONDS = 0.5

_LIBOBJC = "/usr/lib/libobjc.A.dylib"
_APPKIT = "/System/Library/Frameworks/AppKit.framework/AppKit"
_NSUTF8_STRING_ENCODING = 4
_NS_APPLICATION_ACTIVATION_POLICY_ACCESSORY = 1
_NS_VARIABLE_STATUS_ITEM_LENGTH = -1.0

_ptr = ctypes.c_void_p


class MenuAction(StrEnum):
    ON = "on"
    ON_30M = "on_30m"
    ON_2H = "on_2h"
    OFF = "off"
    SANITIZE = "sanitize"
    RESTORE = "restore"
    OPEN_SHORTCUTS = "open_shortcuts"
    QUIT = "quit"


@dataclass(frozen=True)
class MenuState:
    is_on: bool
    watching: bool
    title: str
    status_line: str


@dataclass(frozen=True)
class MenuItemSpec:
    label: str
    action: MenuAction | None = None
    enabled: bool = True
    separator: bool = False


def menu_snapshot(
    config: Path | None = None,
    now: datetime | None = None,
    *,
    watcher: killswitch.Watcher | None = None,
) -> MenuState:
    """Read current kill-switch state without decrypting the persona or reading the clipboard."""
    cfg = paths.config_dir() if config is None else config
    clock = killswitch.utc_now() if now is None else now
    w = killswitch.detect_watcher() if watcher is None else watcher
    reading = killswitch.read(cfg, w)
    active = reading.is_on(clock)
    title = "veil ON" if active else "veil OFF"
    line = killswitch.status_line(reading, clock)
    if reading.problem:
        line = f"veil: {reading.problem}"
    return MenuState(
        is_on=active,
        watching=reading.watching,
        title=title,
        status_line=line,
    )


def build_menu_items(state: MenuState) -> list[MenuItemSpec]:
    """Pure: build menu entries for the current `MenuState`."""
    items: list[MenuItemSpec] = [
        MenuItemSpec(state.status_line, enabled=False),
        MenuItemSpec("", separator=True),
    ]
    if not state.is_on:
        items.extend(
            [
                MenuItemSpec("Switch ON", MenuAction.ON),
                MenuItemSpec("Switch ON for 30 min", MenuAction.ON_30M),
                MenuItemSpec("Switch ON for 2 hours", MenuAction.ON_2H),
            ]
        )
    if state.is_on or state.watching:
        items.append(MenuItemSpec("Switch OFF…", MenuAction.OFF))
    items.extend(
        [
            MenuItemSpec("", separator=True),
            MenuItemSpec("Sanitize Clipboard", MenuAction.SANITIZE),
            MenuItemSpec("Restore Clipboard", MenuAction.RESTORE),
            MenuItemSpec("", separator=True),
            MenuItemSpec("Open Shortcuts Folder", MenuAction.OPEN_SHORTCUTS),
            MenuItemSpec("Quit Menu Bar", MenuAction.QUIT),
        ]
    )
    return items


def _default_subprocess(argv: Sequence[str]) -> int:
    try:
        return subprocess.run(  # noqa: S603 - fixed veil/open argv
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        ).returncode
    except (OSError, subprocess.SubprocessError):
        return -1


def perform_action(
    action: MenuAction,
    *,
    config: Path | None = None,
    now: datetime | None = None,
    watcher: killswitch.Watcher | None = None,
    timers: killswitch.Timers | None = None,
    chooser: killswitch.Chooser | None = None,
    run_subprocess: Callable[[Sequence[str]], int] = _default_subprocess,
    veil_cmd: Sequence[str] | None = None,
) -> bool:
    """Execute a menu action safely with value-free error handling. Returns True if carried out."""
    cfg = paths.config_dir() if config is None else config
    clock = killswitch.utc_now() if now is None else now
    cmd = shortcuts.veil_command() if veil_cmd is None else list(veil_cmd)
    try:
        if action in (MenuAction.ON, MenuAction.ON_30M, MenuAction.ON_2H):
            duration: timedelta | None = None
            if action is MenuAction.ON_30M:
                duration = timedelta(minutes=30)
            elif action is MenuAction.ON_2H:
                duration = timedelta(hours=2)
            w = killswitch.detect_watcher() if watcher is None else watcher
            t = killswitch.detect_timers() if timers is None else timers
            switch, _ = killswitch.switch_on(cfg, w, t, clock, duration)
            notify.detect().notify(killswitch.on_message(switch, clock))
            return True

        if action is MenuAction.OFF:
            w = killswitch.detect_watcher() if watcher is None else watcher
            t = killswitch.detect_timers() if timers is None else timers
            ask_fn = killswitch.detect_chooser() if chooser is None else chooser
            if ask_fn is None or not killswitch.confirm_by_notification(ask_fn):
                return False
            killswitch.switch_off(cfg, w, t)
            notify.detect().notify(killswitch.off_message())
            return True

        if action is MenuAction.SANITIZE:
            return run_subprocess([*cmd, "clip", "sanitize"]) == 0

        if action is MenuAction.RESTORE:
            return run_subprocess([*cmd, "clip", "restore"]) == 0

        if action is MenuAction.OPEN_SHORTCUTS:
            folder = shortcuts.macos_shortcuts_dir()
            if not folder.is_dir() or not any(folder.glob("*.shortcut")):
                shortcuts.export_macos_shortcuts(folder)
            return run_subprocess(["/usr/bin/open", str(folder)]) == 0

        if action is MenuAction.QUIT:
            return True
    except VeilError as err:
        ui.err(f"veil: {err}")
        notify.detect().notify(Message("veil", str(err)))
        return False
    except Exception as exc:  # noqa: BLE001 - never surface raw values
        ui.err(f"veil: menubar action failed ({type(exc).__name__})")
        return False
    return False


# ── AppKit ctypes layer (macOS only) ───────────────────────────────────────────


@functools.cache
def _runtime() -> tuple[ctypes.CDLL, int]:
    if sys.platform != "darwin":
        raise VeilError(
            "veil menubar is only available on macOS", exit_code=ExitCode.UNSAFE_ENVIRONMENT
        )
    try:
        objc = ctypes.CDLL(_LIBOBJC)
        ctypes.CDLL(_APPKIT)
        objc.objc_getClass.argtypes = (ctypes.c_char_p,)
        objc.objc_getClass.restype = _ptr
        objc.sel_registerName.argtypes = (ctypes.c_char_p,)
        objc.sel_registerName.restype = _ptr
        objc.objc_allocateClassPair.argtypes = (_ptr, ctypes.c_char_p, ctypes.c_size_t)
        objc.objc_allocateClassPair.restype = _ptr
        objc.class_addMethod.argtypes = (_ptr, _ptr, _ptr, ctypes.c_char_p)
        objc.class_addMethod.restype = ctypes.c_bool
        objc.objc_registerClassPair.argtypes = (_ptr,)
        objc.objc_registerClassPair.restype = None
        send = ctypes.cast(objc.objc_msgSend, _ptr).value
    except (OSError, AttributeError):
        raise VeilError(
            "could not load macOS AppKit for the menu bar",
            exit_code=ExitCode.UNSAFE_ENVIRONMENT,
        ) from None
    if send is None:
        raise VeilError(
            "could not load macOS AppKit for the menu bar",
            exit_code=ExitCode.UNSAFE_ENVIRONMENT,
        )
    return objc, send


@functools.cache
def _sel(name: str) -> int:
    objc, _ = _runtime()
    return objc.sel_registerName(name.encode("ascii"))


@functools.cache
def _class(name: str) -> int:
    objc, _ = _runtime()
    found = objc.objc_getClass(name.encode("ascii"))
    if not found:
        raise VeilError(
            "could not load macOS AppKit for the menu bar",
            exit_code=ExitCode.UNSAFE_ENVIRONMENT,
        )
    return found


@functools.cache
def _prototype(restype: Any, argtypes: tuple[Any, ...]) -> Callable[..., Any]:
    _, send = _runtime()
    return ctypes.CFUNCTYPE(restype, _ptr, _ptr, *argtypes)(send)


def _msg(obj: int, selector: str, *args: Any, restype: Any = _ptr, argtypes: tuple = ()) -> Any:
    return _prototype(restype, argtypes)(obj, _sel(selector), *args)


def _ns_string(text: str) -> int:
    data = text.encode("utf-8")
    raw = _msg(_class("NSString"), "alloc")
    made = _msg(
        raw,
        "initWithBytes:length:encoding:",
        data,
        len(data),
        _NSUTF8_STRING_ENCODING,
        argtypes=(ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong),
    )
    return _msg(made, "autorelease")


def run(poll_seconds: float = POLL_SECONDS) -> None:
    """Start the macOS menu-bar status item and run the AppKit event loop."""
    objc, _ = _runtime()
    app = _msg(_class("NSApplication"), "sharedApplication")
    _msg(
        app,
        "setActivationPolicy:",
        _NS_APPLICATION_ACTIVATION_POLICY_ACCESSORY,
        restype=ctypes.c_bool,
        argtypes=(ctypes.c_long,),
    )

    status_bar = _msg(_class("NSStatusBar"), "systemStatusBar")
    status_item = _msg(
        status_bar,
        "statusItemWithLength:",
        _NS_VARIABLE_STATUS_ITEM_LENGTH,
        argtypes=(ctypes.c_double,),
    )
    menu = _msg(_msg(_class("NSMenu"), "alloc"), "init")
    _msg(menu, "setAutoenablesItems:", False, restype=None, argtypes=(ctypes.c_bool,))
    _msg(status_item, "setMenu:", menu, restype=None, argtypes=(_ptr,))

    state_lock = threading.Lock()
    current_actions: list[MenuAction] = []
    dirty = threading.Event()
    last_refresh = [0.0]

    def update_status_bar() -> MenuState:
        snap = menu_snapshot()
        button = _msg(status_item, "button")
        if button:
            _msg(button, "setTitle:", _ns_string(snap.title), restype=None, argtypes=(_ptr,))
            _msg(
                button,
                "setToolTip:",
                _ns_string(snap.status_line),
                restype=None,
                argtypes=(_ptr,),
            )
        last_refresh[0] = time.monotonic()
        return snap

    def rebuild_menu() -> None:
        snap = update_status_bar()
        specs = build_menu_items(snap)
        _msg(menu, "removeAllItems", restype=None)
        with state_lock:
            current_actions.clear()
            for spec in specs:
                if spec.separator:
                    sep = _msg(_class("NSMenuItem"), "separatorItem")
                    _msg(menu, "addItem:", sep, restype=None, argtypes=(_ptr,))
                    continue
                item = _msg(
                    _msg(_class("NSMenuItem"), "alloc"),
                    "initWithTitle:action:keyEquivalent:",
                    _ns_string(spec.label),
                    _sel("veilMenuAction:") if spec.enabled and spec.action is not None else None,
                    _ns_string(""),
                    argtypes=(_ptr, _ptr, _ptr),
                )
                _msg(item, "setEnabled:", spec.enabled, restype=None, argtypes=(ctypes.c_bool,))
                if spec.enabled and spec.action is not None:
                    tag = len(current_actions)
                    current_actions.append(spec.action)
                    _msg(item, "setTag:", tag, restype=None, argtypes=(ctypes.c_long,))
                    _msg(item, "setTarget:", delegate_instance, restype=None, argtypes=(_ptr,))
                _msg(menu, "addItem:", item, restype=None, argtypes=(_ptr,))

    def on_menu_needs_update(_self: int, _cmd: int, _menu_ptr: int) -> None:
        cb = _DISPATCH.get("menu")
        if cb is not None:
            cb()

    def on_action(_self: int, _cmd: int, sender: int) -> None:
        cb = _DISPATCH.get("action")
        if cb is not None:
            cb(sender)

    def on_tick(_self: int, _cmd: int, _timer: int) -> None:
        cb = _DISPATCH.get("tick")
        if cb is not None:
            cb()

    def handle_action(sender: int) -> None:
        tag = int(_msg(sender, "tag", restype=ctypes.c_long))
        with state_lock:
            if not 0 <= tag < len(current_actions):
                return
            action = current_actions[tag]
        if action is MenuAction.QUIT:
            _msg(app, "terminate:", None, restype=None, argtypes=(_ptr,))
            return

        def worker() -> None:
            perform_action(action)
            dirty.set()

        threading.Thread(target=worker, daemon=True).start()

    def handle_tick() -> None:
        if dirty.is_set() or (time.monotonic() - last_refresh[0]) >= poll_seconds:
            dirty.clear()
            update_status_bar()

    _DISPATCH["menu"] = rebuild_menu
    _DISPATCH["action"] = handle_action
    _DISPATCH["tick"] = handle_tick

    delegate_cls_name = b"VeilMenuBarDelegate"
    delegate_cls = objc.objc_getClass(delegate_cls_name)
    if not delegate_cls:
        ns_object = _class("NSObject")
        delegate_cls = objc.objc_allocateClassPair(ns_object, delegate_cls_name, 0)
        cb_action = ctypes.CFUNCTYPE(None, _ptr, _ptr, _ptr)(on_action)
        cb_menu = ctypes.CFUNCTYPE(None, _ptr, _ptr, _ptr)(on_menu_needs_update)
        cb_tick = ctypes.CFUNCTYPE(None, _ptr, _ptr, _ptr)(on_tick)
        objc.class_addMethod(delegate_cls, _sel("veilMenuAction:"), cb_action, b"v@:@")
        objc.class_addMethod(delegate_cls, _sel("menuNeedsUpdate:"), cb_menu, b"v@:@")
        objc.class_addMethod(delegate_cls, _sel("veilTick:"), cb_tick, b"v@:@")
        objc.objc_registerClassPair(delegate_cls)
        _KEEP_ALIVE.extend((cb_action, cb_menu, cb_tick))

    delegate_instance = _msg(_msg(delegate_cls, "alloc"), "init")
    _KEEP_ALIVE.append(delegate_instance)
    _msg(menu, "setDelegate:", delegate_instance, restype=None, argtypes=(_ptr,))

    update_status_bar()
    _msg(
        _class("NSTimer"),
        "scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:",
        _TICK_SECONDS,
        delegate_instance,
        _sel("veilTick:"),
        None,
        True,
        argtypes=(ctypes.c_double, _ptr, _ptr, _ptr, ctypes.c_bool),
    )
    _msg(app, "run", restype=None)


_KEEP_ALIVE: list[Any] = []
_DISPATCH: dict[str, Callable[..., None]] = {}
