"""macOS: a private RAM disk as veil's runtime directory (ADR-0025 on macOS).

Linux keeps plaintext only on tmpfs. macOS has no tmpfs, so veil makes a small RAM disk and
mounts it inside the per-user temporary directory:

- 16 MiB, `ram://` backed (memory only), HFS+, mounted `nobrowse,noexec,nosuid,nodev`
  (no Finder or Desktop icon) at `<DARWIN_USER_TEMP_DIR>/veil-runtime`. That parent is 0700,
  so other users cannot reach it.
- Made on first use and kept until logout or `eject()`. Every call checks that the mount
  point is a RAM-backed image before returning it; otherwise it refuses.
- No root needed. Tools are run by absolute path, with fixed arguments and no user text.
- Swap needs no check: macOS always encrypts swap.
"""

import contextlib
import os
import plistlib
import re
import stat
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from veil.errors import UnsafeEnvironment

SIZE_SECTORS = 32768  # 512-byte sectors: 16 MiB, plenty for a persona file and its drafts
VOLUME_NAME = "veil-runtime"
MOUNT_OPTIONS = "nobrowse,noexec,nosuid,nodev"
TIMEOUT_SECONDS = 20.0

DISKUTIL = "/usr/sbin/diskutil"
HDIUTIL = "/usr/bin/hdiutil"
NEWFS_HFS = "/sbin/newfs_hfs"
MOUNT = "/sbin/mount"

Runner = Callable[[Sequence[str]], str]

_CS_DARWIN_USER_TEMP_DIR = 65537  # <unistd.h>; Python's os.confstr_names lacks it


def _run(argv: Sequence[str]) -> str:
    try:
        done = subprocess.run(  # noqa: S603 - absolute tool paths, fixed arguments
            list(argv), capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        raise UnsafeEnvironment(f"could not run {Path(argv[0]).name}") from None
    if done.returncode != 0:
        raise UnsafeEnvironment(f"{Path(argv[0]).name} failed (exit {done.returncode})")
    return done.stdout


def user_temp_dir() -> Path:
    """The per-user temporary directory from the OS (not $TMPDIR, which anyone can set)."""
    try:
        value = os.confstr(_CS_DARWIN_USER_TEMP_DIR)
    except (OSError, ValueError, AttributeError):
        value = None
    if not value:
        raise UnsafeEnvironment("no per-user temporary directory; refusing to write plaintext")
    return Path(os.path.realpath(value))


def mount_point() -> Path:
    return user_temp_dir() / VOLUME_NAME


def ensure(run: Runner | None = None) -> Path:
    """The mounted, verified RAM disk (created if missing)."""
    run = run or _run
    point = mount_point()
    _check_owned_dir(point.parent, "the per-user temporary directory")
    device = mounted_device(point, run)
    if device is None:
        device = _create(point, run)
    if not is_ram_backed(device, run):
        raise UnsafeEnvironment(
            "the runtime directory is not in memory (RAM disk); refusing to write plaintext there"
        )
    return point


def eject(run: Runner | None = None) -> bool:
    """Unmount and free the RAM disk. True if one was mounted."""
    run = run or _run
    device = mounted_device(mount_point(), run)
    if device is None:
        return False
    run([DISKUTIL, "eject", device])
    return True


def mounted_device(point: Path, run: Runner | None = None) -> str | None:
    """The /dev/diskN mounted exactly at `point`, or None."""
    run = run or _run
    target = os.path.realpath(point)
    for line in run([MOUNT]).splitlines():
        match = re.match(r"(/dev/disk\d+(?:s\d+)?) on (.+) \(", line)
        if match and os.path.realpath(match.group(2)) == target:
            return match.group(1)
    return None


def is_ram_backed(device: str, run: Runner | None = None) -> bool:
    """Whether `device` belongs to an attached image whose source is `ram://`."""
    run = run or _run
    try:
        info = plistlib.loads(run([HDIUTIL, "info", "-plist"]).encode())
    except (plistlib.InvalidFileException, ValueError):
        return False
    whole = re.sub(r"s\d+$", "", device)
    for image in info.get("images", []):
        if not str(image.get("image-path", "")).startswith("ram://"):
            continue
        for entity in image.get("system-entities", []):
            if entity.get("dev-entry") in (device, whole):
                return True
    return False


def _create(point: Path, run: Runner) -> str:
    with contextlib.suppress(FileExistsError):
        point.mkdir(mode=0o700)
    _check_owned_dir(point, "the RAM disk mount point")
    out = run([DISKUTIL, "image", "attach", "--noMount", f"ram://{SIZE_SECTORS}"])
    match = re.search(r"/dev/disk\d+", out)
    if not match:
        raise UnsafeEnvironment("could not create the RAM disk")
    device = match.group(0)
    try:
        run([NEWFS_HFS, "-v", VOLUME_NAME, device])
        run([DISKUTIL, "mount", "-mountOptions", MOUNT_OPTIONS, "-mountPoint", str(point), device])
    except UnsafeEnvironment:
        with contextlib.suppress(UnsafeEnvironment):
            run([DISKUTIL, "eject", device])
        raise
    with contextlib.suppress(OSError):
        point.chmod(0o700)
    return device


def _check_owned_dir(path: Path, what: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise UnsafeEnvironment(f"{what} is missing") from None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise UnsafeEnvironment(f"{what} is not a real directory")
    if info.st_uid != os.getuid():
        raise UnsafeEnvironment(f"{what} is not owned by you")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise UnsafeEnvironment(f"{what} is accessible to other users")
