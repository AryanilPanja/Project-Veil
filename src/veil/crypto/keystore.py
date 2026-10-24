"""Where the age identity lives: the Secret Service keyring or a passphrase file (ADR-0025).

Files in the config dir (0700; files 0600):
- `recipient.txt`: the public key. Written once at setup; every load cross-checks against it.
- `key.age`: the identity encrypted with a passphrase (age scrypt). Passphrase mode only.

Rules:
- The keyring backend is pinned to `keyring.backends.SecretService.Keyring`. Never
  `keyring.get_keyring()` and never `PYTHON_KEYRING_BACKEND`: a swapped backend could store the
  key in plaintext.
- No automatic fallback between keyring and passphrase mode; the mode is chosen at setup.
- Never generate a key while any key or encrypted store exists (`create` refuses).
- Every keyring call runs in a worker thread with a hard timeout: KDE's ksecretd can hang or drop
  an unlock prompt, and a hotkey must never hang with it.
"""

import contextlib
import threading
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from veil import fsutil
from veil.crypto import age
from veil.errors import KeyUnavailable, VeilError
from veil.exitcodes import ExitCode

SERVICE = "project-veil"
USERNAME = "age-identity-v1"
RECIPIENT_FILE = "recipient.txt"
KEY_FILE = "key.age"
DEFAULT_TIMEOUT = 20.0
_MAX_RECIPIENT_BYTES = 1024
_MAX_KEY_FILE_BYTES = 64 * 1024

# keyring / secretstorage / jeepney exception class names meaning "locked or prompt refused".
_LOCKED = frozenset({"KeyringLocked", "LockedException", "PromptDismissedException"})


class SecretBackend(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...
    def set_password(self, service: str, username: str, password: str) -> None: ...
    def delete_password(self, service: str, username: str) -> None: ...


class KeyBackend(StrEnum):
    KEYRING = "keyring"
    FILE = "file"


def secret_service_backend() -> SecretBackend:
    """The pinned Secret Service backend (KDE ksecretd / GNOME keyring)."""
    from keyring.backends.SecretService import Keyring  # slow import: only when needed

    return Keyring()


@dataclass(frozen=True)
class KeyStatus:
    """Value-free description of the key setup, for `veil persona status`."""

    backend: KeyBackend | None
    recipient_file: bool
    key_file: bool


class KeyStore:
    def __init__(
        self,
        directory: Path,
        *,
        secrets: Callable[[], SecretBackend] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.directory = directory
        self._secrets_factory = secrets
        self._secrets: SecretBackend | None = None
        self.timeout = timeout

    @property
    def recipient_path(self) -> Path:
        return self.directory / RECIPIENT_FILE

    @property
    def key_path(self) -> Path:
        return self.directory / KEY_FILE

    # ── status ────────────────────────────────────────────────────────────

    def status(self) -> KeyStatus:
        """Which mode is set up, from files only (never touches the keyring)."""
        recipient = self.recipient_path.exists()
        key_file = self.key_path.exists()
        if key_file:
            backend: KeyBackend | None = KeyBackend.FILE
        elif recipient:
            backend = KeyBackend.KEYRING
        else:
            backend = None
        return KeyStatus(backend=backend, recipient_file=recipient, key_file=key_file)

    def recipient(self) -> str:
        """The public key from recipient.txt (all that encryption needs)."""
        if not self.recipient_path.exists() and not self.recipient_path.is_symlink():
            raise KeyUnavailable("no key has been set up yet (recipient.txt is missing)")
        raw = fsutil.read_private(self.recipient_path, _MAX_RECIPIENT_BYTES, "recipient.txt")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            text = ""
        return age.parse_recipient(text)

    # ── create ────────────────────────────────────────────────────────────

    def create(
        self, backend: KeyBackend, *, store_exists: bool, passphrase: str | None = None
    ) -> age.Identity:
        """Generate and store a new identity. Refuses if any key or encrypted store exists."""
        if store_exists:
            raise _refuse("an encrypted persona already exists")
        if self.recipient_path.exists() or self.recipient_path.is_symlink():
            raise _refuse("recipient.txt already exists")
        if self.key_path.exists() or self.key_path.is_symlink():
            raise _refuse("a passphrase key file already exists")
        if backend is KeyBackend.FILE:
            if passphrase is None:
                raise VeilError("passphrase mode needs a passphrase", exit_code=ExitCode.USAGE)
            age.check_passphrase(passphrase)
        elif passphrase is not None:
            raise VeilError("keyring mode does not take a passphrase", exit_code=ExitCode.USAGE)
        if self._keyring_has_key(required=backend is KeyBackend.KEYRING):
            raise _refuse("a key already exists in the keyring")

        fsutil.ensure_private_dir(self.directory, "the veil config directory")
        identity = age.generate_identity()
        if passphrase is None:
            self._store_in_keyring(identity)
        else:
            self._store_in_file(identity, passphrase)
        try:
            fsutil.atomic_write(
                self.recipient_path,
                (identity.recipient + "\n").encode("ascii"),
                what="recipient.txt",
            )
        except BaseException:
            self._rollback(backend)
            raise
        return identity

    def _store_in_keyring(self, identity: age.Identity) -> None:
        try:
            # A timed-out set may still land later; the next `create` then refuses
            # ("already exists in the keyring"), which is the safe direction.
            self._keyring_call(lambda s: s.set_password(SERVICE, USERNAME, identity.secret))
            stored = self._keyring_get()
        except BaseException:
            self._rollback(KeyBackend.KEYRING)
            raise
        if stored is None or stored.strip() != identity.secret:
            self._rollback(KeyBackend.KEYRING)
            raise KeyUnavailable(
                "the keyring did not store the key correctly (read-back mismatch); nothing saved"
            )

    def _store_in_file(self, identity: age.Identity, passphrase: str) -> None:
        data = age.passphrase_encrypt(identity.secret.encode("ascii"), passphrase)

        def verify(temp: Path) -> None:
            written = fsutil.read_private(temp, _MAX_KEY_FILE_BYTES, "the key file")
            if age.passphrase_decrypt(written, passphrase).decode("ascii") != identity.secret:
                raise KeyUnavailable("the key file did not verify after writing; nothing was saved")

        fsutil.atomic_write(self.key_path, data, what="the key file", verify=verify)

    def _rollback(self, backend: KeyBackend) -> None:
        """Undo a half-finished `create`. Only ever called before any store exists."""
        # Best effort: the original error is the one worth reporting.
        with contextlib.suppress(Exception):
            if backend is KeyBackend.KEYRING:
                self._keyring_call(lambda s: s.delete_password(SERVICE, USERNAME))
            else:
                fsutil.secure_remove(self.key_path, "the key file")

    # ── load ──────────────────────────────────────────────────────────────

    def load(self, ask_passphrase: Callable[[], str] | None = None) -> age.Identity:
        """Load the identity and check it matches recipient.txt."""
        expected = self.recipient()
        if self.key_path.exists() or self.key_path.is_symlink():
            if ask_passphrase is None:
                raise KeyUnavailable(
                    "the key is protected by a passphrase, and no prompt is available"
                )
            data = fsutil.read_private(self.key_path, _MAX_KEY_FILE_BYTES, "the key file")
            secret = age.passphrase_decrypt(data, ask_passphrase())
            try:
                identity = age.parse_identity(secret.decode("ascii"))
            except UnicodeDecodeError:
                raise KeyUnavailable("the stored key is not a valid age identity") from None
        else:
            stored = self._keyring_get()
            if stored is None:
                raise KeyUnavailable(
                    "the key is missing from the keyring. Restore it from your backup, or if it "
                    "is lost, the encrypted persona cannot be recovered: re-import from plaintext"
                )
            identity = age.parse_identity(stored)
        if identity.recipient != expected:
            raise KeyUnavailable(
                "the stored key does not match recipient.txt (a different key was put in place)"
            )
        return identity

    # ── keyring plumbing ──────────────────────────────────────────────────

    def _keyring_has_key(self, *, required: bool) -> bool:
        """Is there a veil key in the keyring? An unreachable keyring only matters if required."""
        try:
            return self._keyring_get() is not None
        except KeyUnavailable:
            if required:
                raise
            return False  # passphrase mode must work without a keyring (e.g. over ssh)

    def _keyring_get(self) -> str | None:
        return self._keyring_call(lambda s: s.get_password(SERVICE, USERNAME))

    def _keyring_call[T](self, fn: Callable[[SecretBackend], T]) -> T:
        """Run one keyring call in a daemon thread; give up after `self.timeout` seconds."""
        result: list[T] = []
        failure: list[BaseException] = []

        def work() -> None:
            try:
                if self._secrets is None:
                    # Looked up at call time so tests can forbid the real backend globally.
                    factory = self._secrets_factory or secret_service_backend
                    self._secrets = factory()
                result.append(fn(self._secrets))
            except BaseException as exc:  # noqa: BLE001 — re-raised (mapped) in the caller
                failure.append(exc)

        worker = threading.Thread(target=work, name="veil-keyring", daemon=True)
        worker.start()
        worker.join(self.timeout)
        if worker.is_alive():
            raise KeyUnavailable(
                f"the keyring did not answer within {self.timeout:g} s "
                "(is an unlock prompt waiting? unlock KDE Wallet and try again)"
            )
        if failure:
            raise _keyring_error(failure[0]) from None
        return result[0]


def _keyring_error(exc: BaseException) -> VeilError:
    if isinstance(exc, VeilError):
        return exc
    names = {cls.__name__ for cls in type(exc).__mro__}
    if names & _LOCKED:
        return KeyUnavailable("the keyring is locked; unlock KDE Wallet and try again")
    return KeyUnavailable(f"the keyring (Secret Service) is not available ({type(exc).__name__})")


def _refuse(reason: str) -> VeilError:
    return VeilError(
        f"refusing to create a new key: {reason}. Generating a new key would make existing "
        "encrypted data unreadable",
        exit_code=ExitCode.USAGE,
    )
