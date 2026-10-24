"""The minimal vault for generated fakes (M1.6): `<config>/persona.vault.age`.

Contents (JSON, encrypted to the same recipient as the persona store):
    {"version": 1, "seed": <base64, 32 bytes>, "shift_days": int | null,
     "entries": {HMAC(seed, role + NUL + canon(real)) hex: generated fake}}

No real value is ever stored, not even inside the encryption: entries are keyed by an HMAC, and
the values are fakes. The seed makes generation deterministic; storing the fakes as well means a
future change to a generator can never silently change a fake that has already been used.

Like the store, the vault is written atomically and verified by decrypting it before it replaces
the old file. The v0.2 proxy vault (ADR-0028, SQLite) will absorb this file.
"""

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from veil import fsutil
from veil.crypto import age
from veil.errors import DecryptFailed, KeyUnavailable
from veil.text.normalize import canon

VAULT_FILE = "persona.vault.age"
WHAT = "the generated-fakes vault"
MAX_VAULT_BYTES = 4 * 1024 * 1024
SEED_BYTES = 32


@dataclass
class Vault:
    seed: bytes = field(repr=False)
    entries: dict[str, str] = field(default_factory=dict, repr=False)
    shift_days: int | None = None
    dirty: bool = False

    def __repr__(self) -> str:
        return f"Vault(entries={len(self.entries)}, dirty={self.dirty})"

    @classmethod
    def new(cls) -> "Vault":
        return cls(seed=secrets.token_bytes(SEED_BYTES), dirty=True)

    def key(self, role: str, real: str) -> str:
        message = f"{role}\0{canon(real)}".encode()
        return hmac.new(self.seed, message, hashlib.sha256).hexdigest()

    def get(self, role: str, real: str) -> str | None:
        return self.entries.get(self.key(role, real))

    def put(self, role: str, real: str, fake: str) -> None:
        key = self.key(role, real)
        if self.entries.get(key) != fake:
            self.entries[key] = fake
            self.dirty = True

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "version": 1,
                "seed": base64.b64encode(self.seed).decode("ascii"),
                "shift_days": self.shift_days,
                "entries": dict(sorted(self.entries.items())),
            },
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Vault":
        try:
            doc = json.loads(data)
            seed = base64.b64decode(doc["seed"], validate=True)
            entries = {str(k): str(v) for k, v in doc["entries"].items()}
            shift = doc.get("shift_days")
            if doc.get("version") != 1 or len(seed) != SEED_BYTES:
                raise ValueError("bad vault header")
            if shift is not None and not isinstance(shift, int):
                raise ValueError("bad shift")
        except (ValueError, KeyError, TypeError, AttributeError):
            raise DecryptFailed("the generated-fakes vault is corrupt") from None
        return cls(seed=seed, entries=entries, shift_days=shift)


class VaultFile:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    @property
    def path(self) -> Path:
        return self.directory / VAULT_FILE

    def exists(self) -> bool:
        return self.path.exists() or self.path.is_symlink()

    def load(self, identity: age.Identity) -> Vault:
        """The stored vault, or a new one (with a fresh seed) if there is none yet."""
        if not self.exists():
            return Vault.new()
        data = fsutil.read_private(self.path, MAX_VAULT_BYTES, WHAT)
        return Vault.from_bytes(age.decrypt(data, identity))

    def save(self, vault: Vault, identity: age.Identity, *, recipient: str) -> None:
        if identity.recipient != recipient:
            raise KeyUnavailable("the key does not match recipient.txt; refusing to write")
        plaintext = vault.to_bytes()

        def verify(temp: Path) -> None:
            written = fsutil.read_private(temp, MAX_VAULT_BYTES, WHAT)
            if age.decrypt(written, identity) != plaintext:
                raise DecryptFailed("the generated-fakes vault did not verify after writing")

        fsutil.ensure_private_dir(self.directory, "the veil config directory")
        fsutil.atomic_write(
            self.path, age.encrypt(plaintext, recipient), what=WHAT, verify=verify, backup=True
        )
        vault.dirty = False
