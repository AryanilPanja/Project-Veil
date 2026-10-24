"""Unsaved edits, kept encrypted: `<config>/persona.draft.age` (ADR-0025 §1).

Written when an edit can't be saved (invalid persona, editor crash) and the user chooses to
keep it, or when a crashed session is found on tmpfs. It is plain YAML text encrypted to the same
recipient as the store, so a draft never exists on disk in plaintext.
`veil persona edit --resume-draft` reopens it; a successful save removes it.
"""

from pathlib import Path

from veil import fsutil
from veil.crypto import age
from veil.errors import DecryptFailed, VeilError
from veil.exitcodes import ExitCode
from veil.persona.store import MAX_STORE_BYTES

DRAFT_FILE = "persona.draft.age"
WHAT = "the encrypted draft"


class DraftStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    @property
    def path(self) -> Path:
        return self.directory / DRAFT_FILE

    def exists(self) -> bool:
        return self.path.exists() or self.path.is_symlink()

    def save(self, text: bytes, recipient: str, identity: age.Identity | None = None) -> None:
        """Encrypt `text` to `recipient`; when `identity` is given, verify before replacing."""
        ciphertext = age.encrypt(text, recipient)

        def verify(temp: Path) -> None:
            if identity is None:
                return
            written = fsutil.read_private(temp, MAX_STORE_BYTES, WHAT)
            if age.decrypt(written, identity) != text:
                raise DecryptFailed("the encrypted draft did not verify after writing")

        fsutil.ensure_private_dir(self.directory, "the veil config directory")
        fsutil.atomic_write(self.path, ciphertext, what=WHAT, verify=verify)

    def load(self, identity: age.Identity) -> bytes:
        if not self.exists():
            raise VeilError("there is no saved draft to resume", exit_code=ExitCode.USAGE)
        return age.decrypt(fsutil.read_private(self.path, MAX_STORE_BYTES, WHAT), identity)

    def remove(self) -> bool:
        return fsutil.secure_remove(self.path, WHAT)
