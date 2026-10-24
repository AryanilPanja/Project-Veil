import pytest

from veil.errors import (
    Aborted,
    Busy,
    DecryptFailed,
    KeyUnavailable,
    UnsafeEnvironment,
    ValidationFailed,
    VeilError,
)
from veil.exitcodes import ExitCode

SUBCLASS_CODES = [
    (ValidationFailed, ExitCode.FINDINGS),
    (KeyUnavailable, ExitCode.KEY_UNAVAILABLE),
    (DecryptFailed, ExitCode.DECRYPT_FAILED),
    (Busy, ExitCode.BUSY),
    (UnsafeEnvironment, ExitCode.UNSAFE_ENVIRONMENT),
    (Aborted, ExitCode.ABORTED),
]


@pytest.mark.parametrize(("cls", "code"), SUBCLASS_CODES)
def test_subclass_default_exit_codes(cls, code):
    error = cls("something failed")
    assert error.exit_code is code
    assert isinstance(error, VeilError)
    assert isinstance(error, Exception)


def test_base_class_defaults_to_internal():
    assert VeilError("x").exit_code is ExitCode.INTERNAL


def test_exit_code_can_be_overridden_per_instance():
    error = VeilError("x", exit_code=ExitCode.BUSY)
    assert error.exit_code is ExitCode.BUSY
    # The override must not leak to the class or other instances.
    assert VeilError.exit_code is ExitCode.INTERNAL
    assert VeilError("y").exit_code is ExitCode.INTERNAL


def test_str_is_the_safe_message():
    error = KeyUnavailable("keyring locked at field persona.key")
    assert str(error) == "keyring locked at field persona.key"
    assert error.safe_message == "keyring locked at field persona.key"


def test_repr_shows_class_and_safe_message_only():
    assert repr(Busy("lock held")) == "Busy('lock held')"


def test_chained_cause_is_not_part_of_the_message():
    secret = "Jane Doe +91-98765-43210"

    def decrypt():
        try:
            raise ValueError(secret)
        except ValueError as exc:
            raise DecryptFailed("persona store could not be decrypted") from exc

    with pytest.raises(DecryptFailed) as info:
        decrypt()
    assert secret not in str(info.value)
    assert secret not in repr(info.value)
    assert isinstance(info.value.__cause__, ValueError)


def test_message_with_braces_and_unicode_is_preserved():
    msg = "field education[0].aliases.real{1} — নাম"
    assert str(ValidationFailed(msg)) == msg


def test_errors_can_be_caught_by_base_class():
    with pytest.raises(VeilError):
        raise Aborted("cancelled")
