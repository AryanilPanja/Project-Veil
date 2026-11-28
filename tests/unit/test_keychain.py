"""macOS Keychain backend (crypto/keychain.py) and its wiring into keystore."""

import os
import secrets
import sys

import pytest

from veil.crypto import keychain, keystore

# Writes a throwaway item to the login keychain, so it runs only when asked for.
real_keychain = pytest.mark.skipif(
    sys.platform != "darwin" or os.environ.get("VEIL_TEST_KEYCHAIN") != "1",
    reason="set VEIL_TEST_KEYCHAIN=1 on macOS to touch the real login keychain",
)


def test_status_mapping():
    with pytest.raises(keychain.KeychainLocked):
        keychain._check(keychain.ERR_SEC_INTERACTION_NOT_ALLOWED)
    with pytest.raises(keychain.KeychainLocked):
        keychain._check(keychain.ERR_SEC_USER_CANCELED)
    with pytest.raises(keychain.KeychainError) as info:
        keychain._check(-1)
    assert not isinstance(info.value, keychain.KeychainLocked)
    keychain._check(keychain.ERR_SEC_SUCCESS)


def test_error_text_holds_status_only():
    assert str(keychain.KeychainError(-25300)) == "OSStatus -25300"


def test_locked_keychain_maps_to_locked_message():
    error = keystore._keyring_error(keychain.KeychainLocked(-25308))
    assert "locked" in error.safe_message


@pytest.mark.skipif(sys.platform == "darwin", reason="checks the non-macOS guard")
def test_frameworks_refuse_off_macos():
    keychain._frameworks.cache_clear()
    with pytest.raises(keychain.KeychainError):
        keychain._frameworks()


@real_keychain
def test_round_trip_in_login_keychain(monkeypatch):
    import pwd

    # conftest points HOME at a sandbox; the default keychain is found through the real home.
    monkeypatch.setenv("HOME", pwd.getpwuid(os.getuid()).pw_dir)
    backend = keychain.KeychainBackend()
    service, account = f"veil-selftest-{secrets.token_hex(4)}", "synthetic"
    try:
        assert backend.get_password(service, account) is None
        backend.set_password(service, account, "AGE-SECRET-KEY-SYNTHETIC")
        assert backend.get_password(service, account) == "AGE-SECRET-KEY-SYNTHETIC"
        backend.set_password(service, account, "replaced")
        assert backend.get_password(service, account) == "replaced"
    finally:
        backend.delete_password(service, account)
    assert backend.get_password(service, account) is None
