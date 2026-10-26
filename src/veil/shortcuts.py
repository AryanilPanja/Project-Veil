"""`veil install-shortcuts` (M3.3, spec §4.1): the clipboard and kill-switch hotkeys on KDE
Plasma 6, the way System Settings adds a custom command shortcut (plasma-desktop `kcm_keys`):

1. a `net.local.veil-<name>.desktop` file in `$XDG_DATA_HOME/applications` with
   `X-KDE-GlobalAccel-CommandShortcut=true` (so System Settings lists it under Commands);
2. `kbuildsycoca6`, so the shortcut service can find it by its file name;
3. over D-Bus (`org.kde.kglobalaccel`, `/kglobalaccel`, `org.kde.KGlobalAccel`): `doRegister`
   to make the service read the file, then `setForeignShortcutKeys` on its `_launch` action, then
   `shortcutKeys` to check. The service saves it in `kglobalshortcutsrc` itself.

A key that is already taken by something else is left alone (reported, not stolen). A shortcut
that couldn't be set gets its desktop file removed again, so "file present" means "installed"
(the OFF notifications mention Meta+Alt+K only then). `--remove` undoes everything.

D-Bus goes through jeepney (no command lines), never auto-starts a service, and never touches
the clipboard or the persona.
"""

import contextlib
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Protocol

from veil import fsutil, paths

SERVICE = "org.kde.kglobalaccel"
OBJECT_PATH = "/kglobalaccel"
INTERFACE = "org.kde.KGlobalAccel"
LAUNCH = "_launch"
TIMEOUT_SECONDS = 3.0

# Qt key combination (QKeyCombination::toCombined): modifier bits | key code.
MODIFIERS = {"Shift": 0x02000000, "Ctrl": 0x04000000, "Alt": 0x08000000, "Meta": 0x10000000}
MODIFIER_ORDER = ("Meta", "Ctrl", "Alt", "Shift")  # how KDE writes them


@dataclass(frozen=True)
class Shortcut:
    name: str  # file name part: net.local.veil-<name>.desktop
    title: str  # what System Settings shows
    keys: str  # "Meta+Alt+V"
    args: tuple[str, ...]  # veil's arguments

    @property
    def component(self) -> str:
        return f"net.local.veil-{self.name}.desktop"


SHORTCUTS = (
    Shortcut("sanitize", "veil: sanitize the clipboard", "Meta+Alt+V", ("clip", "sanitize")),
    Shortcut(
        "from-selection",
        "veil: sanitize the selection into the clipboard",
        "Meta+Alt+C",
        ("clip", "from-selection"),
    ),
    # Meta+Alt+R is Spectacle's screen recording on Plasma 6 (owner's install, 2026-10-25).
    Shortcut(
        "restore", "veil: restore real details in the clipboard", "Meta+Alt+E", ("clip", "restore")
    ),
    # veil ON = every copy sanitized; OFF = normal (ADR-0031). OFF asks for one click.
    Shortcut(
        "toggle",
        "veil: ON (sanitize every copy) / OFF",
        "Meta+Alt+K",
        ("toggle", "--from-hotkey"),
    ),
    # Sanitize, then paste (ADR-0030): the paste chord follows Ctrl+V / Ctrl+Shift+V.
    Shortcut("paste", "veil: sanitize, then paste", "Alt+V", ("clip", "paste")),
    Shortcut(
        "paste-terminal",
        "veil: sanitize, then paste in a terminal",
        "Alt+Shift+V",
        ("clip", "paste", "--terminal"),
    ),
)
TOGGLE = next(s for s in SHORTCUTS if s.name == "toggle")

# Shortcut files earlier builds may have left behind (paste mode, withdrawn by ADR-0031): the
# installer and --remove clean them up.
LEGACY_COMPONENTS = (
    "net.local.veil-paste-mode.desktop",
    "net.local.veil-mode-paste.desktop",
    "net.local.veil-mode-paste-terminal.desktop",
)
KEYS_FIELD = "X-Veil-Keys"  # the key actually installed (after any --key override)


def with_keys(overrides: dict[str, str]) -> tuple[Shortcut, ...]:
    """SHORTCUTS with `--key name=Keys` overrides applied. Raises ValueError on an unknown name,
    an unsupported key, or two shortcuts on one key."""
    names = {s.name for s in SHORTCUTS}
    unknown = sorted(set(overrides) - names)
    if unknown:
        raise ValueError(
            f"unknown shortcut name(s): {', '.join(unknown)} (known: {', '.join(sorted(names))})"
        )
    chosen = tuple(
        replace(s, keys=normalize_keys(overrides.get(s.name, s.keys))) for s in SHORTCUTS
    )
    codes = [key_code(s.keys) for s in chosen]
    if len(set(codes)) != len(codes):
        raise ValueError("two shortcuts can't share one key")
    return chosen


def normalize_keys(keys: str) -> str:
    """ "meta+alt+e" → "Meta+Alt+E" (checked by key_code)."""
    parts = [p.strip() for p in keys.split("+")]
    *mods, key = parts
    canonical = {m.lower(): m for m in MODIFIERS}
    try:
        mods = [canonical[m.lower()] for m in mods]
    except KeyError:
        raise ValueError(f"modifiers must be among {', '.join(MODIFIERS)}") from None
    if len(set(mods)) != len(mods):
        raise ValueError("a modifier is repeated")
    mods.sort(key=MODIFIER_ORDER.index)
    normalized = "+".join([*mods, key.upper()])
    key_code(normalized)
    return normalized


def key_code(keys: str) -> int:
    """ "Meta+Alt+V" → the Qt key combination int. Letters and digits only (all veil needs)."""
    *mods, key = keys.split("+")
    if len(key) != 1 or not (key.isascii() and key.isalnum()):
        raise ValueError("only a letter or digit key is supported")
    code = ord(key.upper())
    for mod in mods:
        code |= MODIFIERS[mod]
    return code


# ── desktop files ─────────────────────────────────────────────────────────────

_RESERVED = re.compile(r"[\s\"'\\><~|&;$*?#()`]")


def exec_value(argv: Sequence[str]) -> str:
    """argv as a desktop-entry Exec value (Desktop Entry spec, "The Exec key")."""
    parts = []
    for arg in argv:
        if any(ord(c) < 0x20 or c == "\x7f" for c in arg):
            raise ValueError("control characters can't go into a desktop file")
        if not arg or _RESERVED.search(arg):
            arg = '"' + re.sub(r'(["`$\\])', r"\\\1", arg) + '"'
        parts.append(arg)
    # The string-value escape applies on top (a literal backslash becomes \\), then % → %%.
    return " ".join(parts).replace("\\", "\\\\").replace("%", "%%")


def desktop_entry(shortcut: Shortcut, command: Sequence[str]) -> str:
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={shortcut.title}\n"
        f"Exec={exec_value([*command, *shortcut.args])}\n"
        "Icon=security-high\n"
        "NoDisplay=true\n"
        "StartupNotify=false\n"
        "X-KDE-GlobalAccel-CommandShortcut=true\n"
        f"{KEYS_FIELD}={shortcut.keys}\n"
    )


def veil_command() -> list[str]:
    """How a hotkey starts veil: this interpreter, `-m veil` (works for any install path)."""
    return [sys.executable, "-m", "veil"]


def applications_dir() -> Path:
    return paths.data_dir().parent / "applications"  # $XDG_DATA_HOME/applications


def installed(shortcut: Shortcut = TOGGLE) -> bool:
    return (applications_dir() / shortcut.component).is_file()


def installed_keys(shortcut: Shortcut = TOGGLE) -> str | None:
    """The key this shortcut was installed with (its desktop file says), or None."""
    try:
        text = (applications_dir() / shortcut.component).read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith(f"{KEYS_FIELD}="):
            value = line.split("=", 1)[1].strip()
            try:
                return normalize_keys(value)
            except (ValueError, KeyError):
                return None
    return None


# ── the shortcut service ──────────────────────────────────────────────────────


class ShortcutBus(Protocol):
    def running(self) -> bool: ...

    def available(self, code: int, component: str) -> bool: ...

    def register(self, shortcut: Shortcut) -> None: ...

    def set_keys(self, shortcut: Shortcut, codes: list[int]) -> None: ...

    def keys(self, shortcut: Shortcut) -> list[int]: ...

    def forget(self, shortcut: Shortcut) -> None: ...

    def drop_legacy(self, shortcut: Shortcut) -> None: ...

    def block(self, blocked: bool) -> None: ...


class ShortcutError(Exception):
    """A D-Bus failure (its error name only)."""


class JeepneyShortcuts:
    def __init__(self, address: str = "SESSION", *, timeout: float = TIMEOUT_SECONDS) -> None:
        self._address, self._timeout = address, timeout
        self._connection = None

    def running(self) -> bool:
        from jeepney import message_bus

        return bool(self._call(message_bus.NameHasOwner(SERVICE))[0])

    def available(self, code: int, component: str) -> bool:
        return bool(self._method("isGlobalShortcutAvailable", "is", (code, component))[0])

    def register(self, shortcut: Shortcut) -> None:
        # As System Settings does (globalaccelmodel.cpp addApplication): a dummy action makes
        # the service build the component from the desktop file, which creates its _launch
        # action; the dummy is then unregistered.
        self._method("doRegister", "as", (_action_id(shortcut.component, "", shortcut.title, ""),))
        self._method("unregister", "ss", (shortcut.component, ""))

    def set_keys(self, shortcut: Shortcut, codes: list[int]) -> None:
        self._method(
            "setForeignShortcutKeys", "asa(ai)", (_action(shortcut), [([c],) for c in codes])
        )

    def keys(self, shortcut: Shortcut) -> list[int]:
        sequences = self._method("shortcutKeys", "as", (_action(shortcut),))[0]
        # An unset sequence comes back as [0] (or [0, 0, 0, 0]): not a key.
        return [sequence[0][0] for sequence in sequences if sequence[0] and sequence[0][0]]

    def forget(self, shortcut: Shortcut) -> None:
        self.set_keys(shortcut, [])

    def block(self, blocked: bool) -> None:
        """Pause (or resume) every global shortcut: veil's own pasted Ctrl+V must not trigger
        paste mode's Ctrl+V shortcut again. Not saved anywhere; a session-wide flag."""
        self._method("blockGlobalShortcuts", "b", (blocked,))

    def drop_legacy(self, shortcut: Shortcut) -> None:
        """Remove the action that veil before 2026-10-25 created by mistake (named after the
        title, with the key, but not runnable): it would keep the key from `_launch`."""
        self._method("unregister", "ss", (shortcut.component, shortcut.title))

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _method(self, name: str, signature: str, body: tuple) -> tuple:
        from jeepney import DBusAddress, new_method_call

        address = DBusAddress(OBJECT_PATH, bus_name=SERVICE, interface=INTERFACE)
        return self._call(new_method_call(address, name, signature, body))

    def _call(self, message) -> tuple:
        from jeepney import HeaderFields, MessageType
        from jeepney.low_level import MessageFlag

        message.header.flags |= MessageFlag.no_auto_start
        if self._connection is None:
            from jeepney.io.blocking import open_dbus_connection

            self._connection = open_dbus_connection(self._address, auth_timeout=self._timeout)
        reply = self._connection.send_and_get_reply(message, timeout=self._timeout)
        if reply.header.message_type is MessageType.error:
            raise ShortcutError(reply.header.fields.get(HeaderFields.error_name, "unknown"))
        return reply.body


def _action(shortcut: Shortcut) -> list[str]:
    """The `_launch` action: the one the service runs the desktop file for."""
    return _action_id(shortcut.component, LAUNCH, shortcut.title, shortcut.title)


def _action_id(component: str, action: str, component_title: str, action_title: str) -> list[str]:
    # KGlobalAccel::actionIdFields: ComponentUnique = 0, ActionUnique = 1,
    # ComponentFriendly = 2, ActionFriendly = 3 (kglobalaccel.h). Getting this order wrong
    # creates an ordinary, never-run action named after the title (the M3.3 owner check).
    return [component, action, component_title, action_title]


# ── install / remove ──────────────────────────────────────────────────────────


class Result(Enum):
    INSTALLED = "installed"
    TAKEN = "key already in use"
    FAILED = "failed"
    REMOVED = "removed"


@dataclass(frozen=True)
class Report:
    shortcut: Shortcut
    result: Result


Rebuild = Callable[[], bool]  # refresh KDE's service cache (kbuildsycoca6); True on success


def install(
    bus: ShortcutBus,
    rebuild: Rebuild,
    command: Sequence[str] | None = None,
    chosen: Sequence[Shortcut] = SHORTCUTS,
) -> list[Report]:
    """Write the desktop files, register each shortcut, keep only the ones that worked."""
    command = veil_command() if command is None else list(command)
    folder = applications_dir()
    folder.mkdir(parents=True, exist_ok=True)  # a shared, existing folder: modes left alone
    _remove_legacy(bus, folder)
    for shortcut in chosen:
        _write(folder / shortcut.component, desktop_entry(shortcut, command))
    rebuild()
    reports = [Report(s, _install_one(bus, s)) for s in chosen]
    removed = [r for r in reports if r.result is not Result.INSTALLED]
    for report in removed:
        (folder / report.shortcut.component).unlink(missing_ok=True)
    if removed:
        rebuild()
    return reports


def _install_one(bus: ShortcutBus, shortcut: Shortcut) -> Result:
    code = key_code(shortcut.keys)
    try:
        with contextlib.suppress(Exception):  # nothing to clean up on a fresh install
            bus.drop_legacy(shortcut)
        # Our own _launch holding the key isn't "taken" (re-running the installer).
        if code not in bus.keys(shortcut) and not bus.available(code, shortcut.component):
            return Result.TAKEN
        bus.register(shortcut)
        bus.set_keys(shortcut, [code])
        return Result.INSTALLED if bus.keys(shortcut) == [code] else Result.FAILED
    except Exception:  # noqa: BLE001 - reported per shortcut; the others still get their turn
        return Result.FAILED


def remove(
    bus: ShortcutBus | None,
    rebuild: Rebuild,
    chosen: Sequence[Shortcut] = SHORTCUTS,
) -> list[Report]:
    folder = applications_dir()
    _remove_legacy(bus, folder)
    for shortcut in chosen:
        if bus is not None:
            # Nothing registered, or no service: fine either way.
            with contextlib.suppress(Exception):
                bus.forget(shortcut)
            with contextlib.suppress(Exception):
                bus.drop_legacy(shortcut)
        (folder / shortcut.component).unlink(missing_ok=True)
    rebuild()
    return [Report(shortcut, Result.REMOVED) for shortcut in chosen]


def _remove_legacy(bus: ShortcutBus | None, folder: Path) -> None:
    """Unregister and delete the shortcuts of withdrawn features (LEGACY_COMPONENTS)."""
    for component in LEGACY_COMPONENTS:
        name = component.removeprefix("net.local.veil-").removesuffix(".desktop")
        legacy = Shortcut(name, name, "V", ())
        if bus is not None:
            with contextlib.suppress(Exception):
                bus.forget(legacy)
        (folder / component).unlink(missing_ok=True)


@dataclass(frozen=True)
class Status:
    shortcut: Shortcut
    file_keys: str | None  # the key its desktop file records, or None (no file)
    live_keys: list[str]  # what the shortcut service has on its _launch action

    @property
    def ok(self) -> bool:
        return self.file_keys is not None and self.live_keys == [self.file_keys]


def status(bus: ShortcutBus | None) -> list[Status]:
    """Read-only: what is installed, per shortcut (`veil install-shortcuts --status`)."""
    result = []
    for shortcut in SHORTCUTS:
        live: list[str] = []
        if bus is not None:
            with contextlib.suppress(Exception):
                live = [key_name(code) for code in bus.keys(shortcut)]
        result.append(Status(shortcut, installed_keys(shortcut), live))
    return result


def key_name(code: int) -> str:
    """The inverse of key_code: 0x18000056 → "Meta+Alt+V"."""
    mods = [m for m in MODIFIER_ORDER if code & MODIFIERS[m]]
    key = code & ~sum(MODIFIERS.values())
    return "+".join([*mods, chr(key) if 0x20 < key < 0x7F else f"0x{key:x}"])


def _write(path: Path, text: str) -> None:
    fsutil.atomic_write(path, text.encode("utf-8"), what="a shortcut desktop file")
    path.chmod(0o644)  # KDE's own desktop files are 0644; nothing secret here


def kbuildsycoca(which: Callable[[str], str | None] = shutil.which) -> Rebuild:
    path = which("kbuildsycoca6")

    def rebuild() -> bool:
        if path is None:
            return False
        try:
            return (
                subprocess.run(  # noqa: S603 - fixed argv
                    [path],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=60,
                    check=False,
                ).returncode
                == 0
            )
        except (OSError, subprocess.SubprocessError):
            return False

    return rebuild


def manual_steps(
    command: Sequence[str] | None = None, chosen: Sequence[Shortcut] = SHORTCUTS
) -> list[str]:
    """The fallback (spec §4.1): System Settings → Keyboard → Shortcuts → Add New → Command."""
    command = veil_command() if command is None else list(command)
    lines = ["System Settings → Keyboard → Shortcuts → Add New → Command or Script, then:"]
    for shortcut in chosen:
        lines.append(f"  {shortcut.keys}  {exec_value([*command, *shortcut.args])}")
    return lines
