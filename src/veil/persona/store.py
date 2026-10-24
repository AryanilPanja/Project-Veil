"""The encrypted persona store: `<config>/persona.age` (+ `persona.age.bak`), ADR-0024/0025.

The payload is the user's YAML text with the canary inserted, encrypted to the age identity in
`recipient.txt`. Saving is atomic and verified: the new file must decrypt back to the exact
payload with the real identity before it replaces the old one, and the old one is kept as `.bak`.

The decrypted payload only ever exists in this process's memory.
"""

from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path

from veil import fsutil
from veil.crypto import age
from veil.errors import DecryptFailed, KeyUnavailable, StorageError
from veil.persona import canary
from veil.persona.yamlio import MAX_BYTES

STORE_FILE = "persona.age"
LOCK_FILE = "persona.lock"
WHAT = "the encrypted persona"
# The YAML payload is capped at MAX_BYTES; age adds a small header and 16 bytes per 64 KiB chunk.
MAX_STORE_BYTES = MAX_BYTES + 64 * 1024


@dataclass(frozen=True, repr=False)
class Payload:
    """Decrypted persona YAML. Never printed: repr shows the size only."""

    data: bytes

    def __repr__(self) -> str:
        return f"Payload({len(self.data)} bytes)"

    @property
    def canary(self) -> str | None:
        found = canary.find_all(self.data.decode("utf-8", errors="replace"))
        return found[0] if found and len(set(found)) == 1 else None


class PersonaStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    @property
    def path(self) -> Path:
        return self.directory / STORE_FILE

    @property
    def backup_path(self) -> Path:
        return self.directory / (STORE_FILE + fsutil.BACKUP_SUFFIX)

    def exists(self) -> bool:
        return self.path.exists() or self.path.is_symlink()

    def lock(self) -> AbstractContextManager[None]:
        """Exclusive lock for anything that writes the store (import, edit)."""
        fsutil.ensure_private_dir(self.directory, "the veil config directory")
        return fsutil.flock_exclusive(self.directory / LOCK_FILE, WHAT)

    def load(self, identity: age.Identity) -> Payload:
        if not self.exists():
            raise KeyUnavailable("no encrypted persona yet; run `veil persona import FILE` first")
        fsutil.check_private_file(self.path, WHAT)
        ciphertext = fsutil.read_private(self.path, MAX_STORE_BYTES, WHAT)
        payload = Payload(age.decrypt(ciphertext, identity))
        if payload.canary is None:
            raise DecryptFailed(
                "the encrypted persona has no valid canary (it was not written by veil, or it "
                "was altered)"
            )
        return payload

    def save(self, payload: Payload, identity: age.Identity, *, recipient: str) -> None:
        """Encrypt to `recipient`, verify with `identity`, then atomically replace (+ `.bak`)."""
        if identity.recipient != recipient:
            raise KeyUnavailable("the key does not match recipient.txt; refusing to write")
        if len(payload.data) > MAX_BYTES:
            raise StorageError(f"the persona is larger than {MAX_BYTES} bytes")
        if payload.canary is None:
            raise DecryptFailed("refusing to save a persona without exactly one canary")
        fsutil.ensure_private_dir(self.directory, "the veil config directory")
        ciphertext = age.encrypt(payload.data, recipient)

        def verify(temp: Path) -> None:
            written = fsutil.read_private(temp, MAX_STORE_BYTES, WHAT)
            if age.decrypt(written, identity) != payload.data:
                raise DecryptFailed("the encrypted persona did not verify after writing")

        fsutil.remove_stale_temps(self.path)
        fsutil.atomic_write(self.path, ciphertext, what=WHAT, verify=verify, backup=True)
