"""Careful file handling for everything veil stores (ADR-0025).

- Never follow symlinks (O_NOFOLLOW / lstat) and never trust files or dirs owned by someone else.
- Directories are 0700 and files 0600; looser modes are tightened, not refused.
- atomic_write: the target is either the old file or the complete new one, never a mix. On any
  failure (disk full, I/O error, a failed verify hook, Ctrl-C) the old file is left unchanged and
  the temp file is removed.
- flock_exclusive: one veil process at a time per lock file; a held lock raises Busy.
- secure_remove: overwrite then unlink. Best effort only: SSDs, journaling and copy-on-write
  filesystems may keep old blocks, which is why plaintext only ever lives on tmpfs.

Error messages never include paths (a home directory names the user); callers pass a label such
as "the persona store" instead.
"""

import contextlib
import errno
import fcntl
import os
import stat
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path

from veil.errors import Busy, StorageError, UnsafeEnvironment

DIR_MODE = 0o700
FILE_MODE = 0o600
TEMP_SUFFIX = ".tmp"
BACKUP_SUFFIX = ".bak"
_CHUNK = 1 << 20

_NO_SPACE = frozenset({errno.ENOSPC, errno.EDQUOT, errno.EFBIG})


# ── Directories ───────────────────────────────────────────────────────────────


def ensure_private_dir(path: Path, what: str = "the directory") -> Path:
    """Create `path` (and missing parents) if needed; refuse symlinks and foreign owners."""
    try:
        path.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    except FileExistsError:
        pass  # a non-directory is in the way; reported below
    except OSError as exc:
        raise _storage_error(exc, what) from exc
    info = _lstat(path, what)
    if stat.S_ISLNK(info.st_mode):
        raise UnsafeEnvironment(f"{what} is a symbolic link; refusing to use it")
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafeEnvironment(f"{what} is not a directory")
    _check_owner(info, what)
    if stat.S_IMODE(info.st_mode) & 0o077:
        path.chmod(DIR_MODE)
    return path


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# ── Files ─────────────────────────────────────────────────────────────────────


def check_private_file(path: Path, what: str = "the file") -> os.stat_result:
    """Refuse symlinks, non-regular files and foreign owners; tighten a loose mode to 0600."""
    info = _lstat(path, what)
    if stat.S_ISLNK(info.st_mode):
        raise UnsafeEnvironment(f"{what} is a symbolic link; refusing to use it")
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeEnvironment(f"{what} is not a regular file")
    _check_owner(info, what)
    if stat.S_IMODE(info.st_mode) & 0o077:
        path.chmod(FILE_MODE)
    return info


def read_private(path: Path, max_bytes: int, what: str = "the file") -> bytes:
    """Read a private file without following symlinks, refusing anything over `max_bytes`."""
    fd = _open_nofollow(path, os.O_RDONLY, what)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeEnvironment(f"{what} is not a regular file")
        _check_owner(info, what)
        if stat.S_IMODE(info.st_mode) & 0o077:
            os.fchmod(fd, FILE_MODE)
        if info.st_size > max_bytes:
            raise StorageError(f"{what} is larger than {max_bytes} bytes; refusing to read it")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, _CHUNK):
            total += len(chunk)
            if total > max_bytes:  # the file grew while we read it
                raise StorageError(f"{what} is larger than {max_bytes} bytes; refusing to read it")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as exc:
        raise _storage_error(exc, what) from exc
    finally:
        os.close(fd)


def atomic_write(
    path: Path,
    data: bytes,
    *,
    what: str = "the file",
    verify: Callable[[Path], None] | None = None,
    backup: bool = False,
) -> None:
    """Replace `path` with `data` atomically (0600).

    Steps: temp file in the same directory → write → fsync → `verify(temp)` → optional
    `<name>.bak` of the old file → rename over the target → fsync the directory. `verify` may
    raise to abort; the old file is then untouched.
    """
    parent = path.parent
    if path.is_symlink():
        raise UnsafeEnvironment(f"{what} is a symbolic link; refusing to replace it")
    try:
        fd, temp_name = tempfile.mkstemp(dir=parent, prefix=f".{path.name}.", suffix=TEMP_SUFFIX)
    except OSError as exc:
        raise _storage_error(exc, what) from exc
    temp = Path(temp_name)
    try:
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        if verify is not None:
            verify(temp)
        if backup and path.exists():
            _make_backup(path, what)
        temp.replace(path)
        fsync_dir(parent)
    except OSError as exc:
        _discard(temp)
        raise _storage_error(exc, what) from exc
    except BaseException:
        _discard(temp)
        raise


def remove_stale_temps(path: Path) -> int:
    """Remove temp files a crashed atomic_write left next to `path`. Returns how many."""
    removed = 0
    for leftover in path.parent.glob(f".{_glob_escape(path.name)}.*{TEMP_SUFFIX}"):
        with contextlib.suppress(OSError):
            if leftover.is_file() and not leftover.is_symlink():
                secure_remove(leftover)
                removed += 1
    return removed


def secure_remove(path: Path, what: str = "the file") -> bool:
    """Overwrite a regular file with zeros, then unlink it. Symlinks are unlinked, not followed.

    Returns False when there was nothing to remove.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISREG(info.st_mode):
        try:
            fd = _open_nofollow(path, os.O_WRONLY, what)
            try:
                remaining = os.fstat(fd).st_size
                zeros = bytes(min(remaining, _CHUNK))
                while remaining > 0:
                    remaining -= os.write(fd, zeros[: min(remaining, _CHUNK)])
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError as exc:
            raise _storage_error(exc, what) from exc
    elif stat.S_ISDIR(info.st_mode):
        raise UnsafeEnvironment(f"{what} is a directory; refusing to remove it")
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise _storage_error(exc, what) from exc
    return True


# ── Locking ───────────────────────────────────────────────────────────────────


@contextlib.contextmanager
def flock_exclusive(path: Path, what: str = "veil") -> Iterator[None]:
    """Hold an exclusive, non-blocking lock on `path` (created 0600). Raises Busy if held.

    The lock file is never deleted: deleting it would let two processes lock different inodes.
    """
    fd = _open_nofollow(path, os.O_RDWR | os.O_CREAT, what)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeEnvironment(f"the lock file for {what} is not a regular file")
        _check_owner(info, f"the lock file for {what}")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Busy(f"{what} is in use by another veil process; try again later") from None
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _open_nofollow(path: Path, flags: int, what: str) -> int:
    try:
        return os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, FILE_MODE)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UnsafeEnvironment(f"{what} is a symbolic link; refusing to use it") from None
        raise _storage_error(exc, what) from exc


def _lstat(path: Path, what: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise _storage_error(exc, what) from exc


def _check_owner(info: os.stat_result, what: str) -> None:
    if info.st_uid != os.getuid():
        raise UnsafeEnvironment(f"{what} is not owned by you; refusing to use it")


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view[:_CHUNK])
        view = view[written:]


def _make_backup(path: Path, what: str) -> None:
    """`<name>.bak` = the current file. Hard link (instant, same inode) or a copy as fallback."""
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    staging = path.with_name(f".{path.name}{BACKUP_SUFFIX}{TEMP_SUFFIX}")
    _discard(staging)
    try:
        os.link(path, staging, follow_symlinks=False)
    except OSError:
        # Filesystems without hard links: copy through atomic_write's own temp machinery.
        atomic_write(backup, read_private(path, max_bytes=1 << 30, what=what), what=what)
        return
    staging.replace(backup)


def _discard(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink()


def _glob_escape(name: str) -> str:
    return "".join(f"[{c}]" if c in "*?[" else c for c in name)


def _storage_error(exc: OSError, what: str) -> StorageError | UnsafeEnvironment:
    if exc.errno in _NO_SPACE:
        return StorageError(
            f"not enough disk space to write {what}; the previous version is unchanged"
        )
    if exc.errno in (errno.EACCES, errno.EPERM):
        return UnsafeEnvironment(f"permission denied for {what}")
    if exc.errno == errno.ENOENT:
        return StorageError(f"{what} does not exist")
    return StorageError(f"could not access {what} (I/O error); the previous version is unchanged")
