"""veil's own clipboard writes, remembered for a moment (ADR-0031).

While veil is ON, the copy watcher runs after *every* clipboard change, including veil's own:
a sanitized result, a placeholder, or a restore (real text the user asked for, which must not
be sanitized straight back). Each write is remembered just before it happens, as a keyed hash
(BLAKE2b with a random key made once per login session), never the text.

The watcher *consumes* a matching entry: veil's write comes back to it once, and a later copy
of the same text is a new copy. (Sweep 2026-10-26: reusable 2-minute entries let restored real
text, copied again, go out unsanitized.) Entries live 10 seconds, at most 16, in the runtime
directory (tmpfs, 0700, agent-denied; ADR-0025), behind a lock (watcher runs can overlap).

Best effort on both sides: if the list can't be read or written, the watcher just doesn't skip,
and sanitizing already-sanitized text changes nothing (commands.py also stops the loop by not
rewriting an unchanged plain-text clipboard).
"""

import contextlib
import fcntl
import hashlib
import json
import os
import secrets
import time
from collections.abc import Iterator
from pathlib import Path

from veil import fsutil, paths

FILE = "recent-writes"
KEEP = 16
MAX_AGE = 10.0  # seconds: long enough for the watcher to see veil's write come back
MAX_BYTES = 8192

Entries = list[tuple[float, str]]


def location() -> Path:
    """The list's file (tests replace this function: never the real runtime directory)."""
    folder = fsutil.ensure_private_dir(paths.runtime_dir(), "the veil runtime directory")
    return folder / FILE


def remember(text: str, *, now: float | None = None) -> None:
    """Called just *before* veil writes `text`: the watcher can see the change before the write
    call returns. Best effort: never raises."""
    with contextlib.suppress(Exception), _locked() as path:
        try:
            key, entries = _load(path)
        except Exception:  # noqa: BLE001 - a damaged list is replaced, not kept failing
            key, entries = secrets.token_hex(32), []
        stamp = time.time() if now is None else now
        entries = [e for e in entries if stamp - e[0] < MAX_AGE][-(KEEP - 1) :]
        entries.append((stamp, _digest(key, text)))
        _store(path, key, entries)


def seen(text: str, *, now: float | None = None) -> bool:
    """Whether `text` is one of veil's recent writes, without using it up (see `consume`)."""
    try:
        key, entries = _load(location())
    except Exception:  # noqa: BLE001 - unknown means "not ours": the watcher sanitizes
        return False
    stamp = time.time() if now is None else now
    digest = _digest(key, text)
    return any(d == digest and stamp - t < MAX_AGE for t, d in entries)


def consume(text: str, *, now: float | None = None) -> bool:
    """Whether `text` is one of veil's recent writes, using that entry up."""
    try:
        with _locked() as path:
            key, entries = _load(path)
            stamp = time.time() if now is None else now
            digest = _digest(key, text)
            fresh = [(t, d) for t, d in entries if stamp - t < MAX_AGE]
            for i, (_, d) in enumerate(fresh):
                if d == digest:
                    del fresh[i]
                    _store(path, key, fresh)
                    return True
            return False
    except Exception:  # noqa: BLE001 - unknown means "not ours": the watcher sanitizes
        return False


@contextlib.contextmanager
def _locked() -> Iterator[Path]:
    """One veil process at a time reads, changes and writes the list."""
    path = location()
    fd = os.open(
        path.with_name(FILE + ".lock"), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield path
    finally:
        os.close(fd)


def _load(path: Path) -> tuple[str, Entries]:
    if not path.exists():
        return secrets.token_hex(32), []
    data = json.loads(fsutil.read_private(path, MAX_BYTES, "the recent-writes list"))
    key = data["key"]
    if not isinstance(key, str) or len(key) != 64:
        raise ValueError("bad key")
    entries = [(float(t), str(d)) for t, d in data["entries"]]
    return key, entries


def _store(path: Path, key: str, entries: Entries) -> None:
    data = {"key": key, "entries": entries}
    fsutil.atomic_write(path, json.dumps(data).encode("ascii"), what="the recent-writes list")


def _digest(key: str, text: str) -> str:
    return hashlib.blake2b(text.encode("utf-8"), key=bytes.fromhex(key), digest_size=16).hexdigest()
