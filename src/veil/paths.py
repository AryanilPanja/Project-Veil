"""Where veil keeps things, and whether those places are safe (ADR-0025).

- config_dir():  $XDG_CONFIG_HOME/veil or ~/.config/veil       (encrypted persona, key, state)
- data_dir():    $XDG_DATA_HOME/veil   or ~/.local/share/veil  (encrypted store, later)
- runtime_dir(): $XDG_RUNTIME_DIR/veil or /run/user/<uid>/veil (the ONLY place plaintext may be
                 written, e.g. during `veil persona edit`). The base must be owned by us, mode 0700
                 and on tmpfs (memory). There is no fallback to /tmp, /dev/shm or disk.
- swap_status(): whether active swap could write memory to disk unencrypted.

Readers of /proc and /sys are injectable so tests never depend on the host.
"""

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from veil.errors import UnsafeEnvironment

APP = "veil"
MEMORY_FILESYSTEMS = frozenset({"tmpfs", "ramfs"})

TextReader = Callable[[str], str]


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8", errors="replace")


def config_dir() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config") / APP


def data_dir() -> Path:
    return _xdg("XDG_DATA_HOME", ".local/share") / APP


def _xdg(variable: str, fallback: str) -> Path:
    value = os.environ.get(variable, "").strip()
    # The XDG spec says relative values must be ignored.
    if value and Path(value).is_absolute():
        return Path(value)
    return Path.home() / fallback


# ── Runtime dir (tmpfs only) ──────────────────────────────────────────────────


def runtime_base(read: TextReader = _read_text) -> Path:
    """The validated base runtime directory (not yet the veil subdirectory)."""
    value = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    base = Path(value) if value and Path(value).is_absolute() else Path(f"/run/user/{os.getuid()}")
    try:
        info = base.lstat()
    except FileNotFoundError:
        raise UnsafeEnvironment(
            "no runtime directory (XDG_RUNTIME_DIR); refusing to write plaintext anywhere else"
        ) from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise UnsafeEnvironment("the runtime directory is not a real directory")
    if info.st_uid != os.getuid():
        raise UnsafeEnvironment("the runtime directory is not owned by you")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise UnsafeEnvironment("the runtime directory is accessible to other users")
    # Resolve symlinked parents first: the mount table holds real paths, and a lexical match
    # would let `<tmpfs>/link-to-disk/dir` pass as memory (sweep 2026-10-26).
    fstype = filesystem_of(Path(os.path.realpath(base)), read("/proc/self/mountinfo"))
    if fstype not in MEMORY_FILESYSTEMS:
        raise UnsafeEnvironment(
            "the runtime directory is not in memory (tmpfs); refusing to write plaintext there"
        )
    return base


def runtime_dir(read: TextReader = _read_text) -> Path:
    return runtime_base(read) / APP


# ── /proc/self/mountinfo ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class Mount:
    mount_point: str
    fstype: str


def parse_mountinfo(text: str) -> list[Mount]:
    """Parse /proc/self/mountinfo: `id parent maj:min root mount_point opts ... - fstype source`."""
    mounts: list[Mount] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 7 or "-" not in parts:
            continue
        separator = parts.index("-")
        if separator + 1 >= len(parts):
            continue
        mounts.append(Mount(_unescape(parts[4]), parts[separator + 1]))
    return mounts


def filesystem_of(path: Path, mountinfo: str) -> str:
    """Filesystem type of the mount that contains `path` (longest mount-point prefix wins)."""
    target = os.path.normpath(str(path))
    best_fstype, best_len = "unknown", -1
    # Later lines win ties: a mount stacked on the same point hides the earlier one.
    for mount in parse_mountinfo(mountinfo):
        point = os.path.normpath(mount.mount_point)
        inside = point == "/" or target == point or target.startswith(point + "/")
        if inside and len(point) >= best_len:
            best_fstype, best_len = mount.fstype, len(point)
    return best_fstype


_OCTAL = frozenset("01234567")


def _unescape(field: str) -> str:
    """mountinfo escapes space, tab, newline and backslash as octal (\\040 …)."""
    out: list[str] = []
    i = 0
    while i < len(field):
        if field[i] == "\\" and set(field[i + 1 : i + 4]) <= _OCTAL and i + 3 < len(field):
            out.append(chr(int(field[i + 1 : i + 4], 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


# ── Swap ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SwapStatus:
    active: int  # active swap areas
    unprotected: int  # areas that are neither zram nor dm-crypt (memory may reach disk in clear)

    @property
    def at_risk(self) -> bool:
        return self.unprotected > 0


def swap_status(read: TextReader = _read_text) -> SwapStatus:
    try:
        text = read("/proc/swaps")
    except OSError:
        return SwapStatus(active=0, unprotected=0)
    active = unprotected = 0
    for line in text.splitlines()[1:]:  # first line is the header
        parts = line.split()
        if not parts:
            continue
        active += 1
        if not _swap_is_protected(_unescape(parts[0]), read):
            unprotected += 1
    return SwapStatus(active, unprotected)


def _swap_is_protected(device: str, read: TextReader) -> bool:
    name = Path(device).name
    if name.startswith("zram"):
        return True  # compressed RAM, never written to disk
    if name.startswith("dm-"):
        try:
            return read(f"/sys/block/{name}/dm/uuid").startswith("CRYPT-")
        except OSError:
            return False
    if device.startswith("/dev/mapper/"):
        try:
            real = Path(device).resolve().name
            return read(f"/sys/block/{real}/dm/uuid").startswith("CRYPT-")
        except OSError:
            return False
    return False  # plain partitions and swap files: assume unencrypted
