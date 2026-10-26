"""veil's own clipboard writes, remembered for a moment (ADR-0031).

While veil is ON, the copy watcher runs after *every* clipboard change, including veil's own:
a sanitized result, a placeholder, or a restore (real text the user asked for, which must not
be sanitized straight back). Each write is remembered as a keyed hash (BLAKE2b with a random key
made once per login session), never the text; the watcher skips content it finds here.

Kept in the runtime directory (tmpfs, 0700, agent-denied; ADR-0025), for 2 minutes, at most
16 entries. Best effort on both sides: if the list can't be read or written, the watcher just
doesn't skip, and sanitizing already-sanitized text changes nothing (commands.py also stops the
loop by not rewriting an unchanged plain-text clipboard).
"""

import contextlib
import hashlib
import json
import secrets
import time
from pathlib import Path

from veil import fsutil, paths

FILE = "recent-writes"
KEEP = 16
MAX_AGE = 120.0  # seconds
MAX_BYTES = 8192


def location() -> Path:
    """The list's file (tests replace this function: never the real runtime directory)."""
    folder = fsutil.ensure_private_dir(paths.runtime_dir(), "the veil runtime directory")
    return folder / FILE


def remember(text: str, *, now: float | None = None) -> None:
    with contextlib.suppress(Exception):  # best effort: a write must never fail because of this
        path = location()
        try:
            key, entries = _load(path)
        except Exception:  # noqa: BLE001 - a damaged list is replaced, not kept failing
            key, entries = secrets.token_hex(32), []
        stamp = time.time() if now is None else now
        entries = [e for e in entries if stamp - e[0] < MAX_AGE][-(KEEP - 1) :]
        entries.append((stamp, _digest(key, text)))
        data = {"key": key, "entries": entries}
        fsutil.atomic_write(path, json.dumps(data).encode("ascii"), what="the recent-writes list")


def seen(text: str, *, now: float | None = None) -> bool:
    try:
        key, entries = _load(location())
    except Exception:  # noqa: BLE001 - unknown means "not ours": the watcher sanitizes
        return False
    stamp = time.time() if now is None else now
    digest = _digest(key, text)
    return any(d == digest and stamp - t < MAX_AGE for t, d in entries)


def _load(path: Path) -> tuple[str, list[tuple[float, str]]]:
    if not path.exists():
        return secrets.token_hex(32), []
    data = json.loads(fsutil.read_private(path, MAX_BYTES, "the recent-writes list"))
    key = data["key"]
    if not isinstance(key, str) or len(key) != 64:
        raise ValueError("bad key")
    entries = [(float(t), str(d)) for t, d in data["entries"]]
    return key, entries


def _digest(key: str, text: str) -> str:
    return hashlib.blake2b(text.encode("utf-8"), key=bytes.fromhex(key), digest_size=16).hexdigest()
