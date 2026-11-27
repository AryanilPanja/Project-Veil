"""A thin wrapper over pyrage (age X25519 + age scrypt passphrase), ADR-0025.

Every pyrage failure becomes a VeilError with a fixed message: DecryptFailed (exit 5) for
anything that touches ciphertext, KeyUnavailable (exit 4) for an unusable identity. pyrage's
own exceptions are dropped (`from None`) so their tracebacks never keep plaintext alive.

Files written with these functions are standard age files: `age -d -i key.txt persona.age`
decrypts them too, so a veil bug can never lock the owner out of their own data.
"""

from dataclasses import dataclass, field

import pyrage
from pyrage import passphrase as _passphrase
from pyrage import x25519

from veil.errors import DecryptFailed, KeyUnavailable, VeilError
from veil.exitcodes import ExitCode

AGE_MAGIC = b"age-encryption.org/v1\n"
MIN_PASSPHRASE = 8


@dataclass(frozen=True)
class Identity:
    """An age X25519 identity. The secret is never shown by repr or str."""

    secret: str = field(repr=False)
    recipient: str

    def __str__(self) -> str:
        return f"Identity(recipient={self.recipient})"


def generate_identity() -> Identity:
    identity = x25519.Identity.generate()
    return Identity(secret=str(identity), recipient=str(identity.to_public()))


def parse_identity(text: str) -> Identity:
    """Parse a stored `AGE-SECRET-KEY-1…` string. Surrounding whitespace is ignored."""
    try:
        identity = x25519.Identity.from_str(text.strip())
    except (pyrage.IdentityError, ValueError, TypeError):
        raise KeyUnavailable("the stored key is not a valid age identity") from None
    return Identity(secret=str(identity), recipient=str(identity.to_public()))


def parse_recipient(text: str) -> str:
    """Validate an `age1…` public key and return it in canonical (lower-case) form."""
    try:
        return str(x25519.Recipient.from_str(text.strip()))
    except (pyrage.RecipientError, ValueError, TypeError):
        raise DecryptFailed("the public key (recipient.txt) is not a valid age recipient") from None


def is_age(data: bytes) -> bool:
    return data.startswith(AGE_MAGIC)


def encrypt(plaintext: bytes, recipient: str) -> bytes:
    try:
        return pyrage.encrypt(plaintext, [x25519.Recipient.from_str(recipient)])
    except (pyrage.RecipientError, pyrage.EncryptError, ValueError, TypeError):
        raise DecryptFailed("could not encrypt: the public key is not usable") from None


def decrypt(ciphertext: bytes, identity: Identity) -> bytes:
    if not is_age(ciphertext):
        raise DecryptFailed("the file is not an age-encrypted file (corrupt or replaced)")
    try:
        key = x25519.Identity.from_str(identity.secret)
    except (pyrage.IdentityError, ValueError, TypeError):
        raise KeyUnavailable("the stored key is not a valid age identity") from None
    try:
        return pyrage.decrypt(ciphertext, [key])
    except (pyrage.DecryptError, ValueError, TypeError):
        raise DecryptFailed(
            "could not decrypt: wrong key, or the file is corrupt or truncated"
        ) from None


def passphrase_encrypt(plaintext: bytes, passphrase: str) -> bytes:
    check_passphrase(passphrase)
    try:
        return _passphrase.encrypt(plaintext, passphrase)
    except (pyrage.EncryptError, ValueError, TypeError):
        raise DecryptFailed("could not encrypt with the passphrase") from None


def passphrase_decrypt(ciphertext: bytes, passphrase: str) -> bytes:
    if not is_age(ciphertext):
        raise DecryptFailed("the key file is not an age-encrypted file (corrupt or replaced)")
    try:
        return _passphrase.decrypt(ciphertext, passphrase)
    except (pyrage.DecryptError, ValueError, TypeError):
        raise DecryptFailed(
            "could not decrypt the key file: wrong passphrase, or it is corrupt"
        ) from None


def check_passphrase(passphrase: str) -> None:
    if len(passphrase.strip()) < MIN_PASSPHRASE:
        raise VeilError(
            f"the passphrase must be at least {MIN_PASSPHRASE} characters", exit_code=ExitCode.USAGE
        )
