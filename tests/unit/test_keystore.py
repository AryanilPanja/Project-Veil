"""crypto/keystore.py: keyring and passphrase identity storage. Never touches the real keyring."""

import stat
import threading
import time

import pytest

from tests.helpers.memkeyring import (
    FailingKeyring,
    HangingKeyring,
    LockedException,
    LossyKeyring,
    MemoryKeyring,
    PromptDismissedException,
    SecretServiceNotAvailableException,
)
from veil.crypto import age, keystore
from veil.crypto.keystore import KEY_FILE, RECIPIENT_FILE, SERVICE, USERNAME, KeyBackend, KeyStore
from veil.errors import DecryptFailed, KeyUnavailable, StorageError, VeilError
from veil.exitcodes import ExitCode

PASS = "correct horse battery"


@pytest.fixture(autouse=True)
def _fast(fast_scrypt):
    """Real age scrypt costs ~1.5 s per call; see `fast_scrypt` in conftest."""


@pytest.fixture
def ring():
    return MemoryKeyring()


@pytest.fixture
def config(tmp_path):
    return tmp_path / "config" / "veil"


def make(config, backend=None, timeout=2.0):
    return KeyStore(
        config, secrets=(lambda: backend) if backend is not None else None, timeout=timeout
    )


def mode(path):
    return stat.S_IMODE(path.lstat().st_mode)


# ── create: keyring ───────────────────────────────────────────────────────────


class TestCreateKeyring:
    def test_stores_secret_under_pinned_names_and_writes_recipient(self, config, ring):
        identity = make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        assert ring.items == {(SERVICE, keystore.keyring_username(config)): identity.secret}
        assert (config / RECIPIENT_FILE).read_text() == identity.recipient + "\n"
        assert not (config / KEY_FILE).exists()

    def test_names_are_the_adr_0025_ones(self):
        assert (SERVICE, USERNAME) == ("project-veil", "age-identity-v1")

    def test_test_dirs_never_use_the_real_entry(self, config):
        assert keystore.keyring_username(config) != USERNAME

    def test_creates_private_config_dir_and_files(self, config, ring):
        make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        assert mode(config) == 0o700
        assert mode(config / RECIPIENT_FILE) == 0o600

    def test_reads_back_after_set(self, config, ring):
        make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        assert ring.calls == ["get", "set", "get"]

    def test_round_trip_create_then_load(self, config, ring):
        created = make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        loaded = make(config, ring).load()
        assert loaded == created
        assert age.decrypt(age.encrypt(b"x", loaded.recipient), loaded) == b"x"

    @pytest.mark.parametrize("stored", [None, "", "AGE-SECRET-KEY-1WRONG", "garbage"])
    def test_read_back_mismatch_fails_and_saves_nothing(self, config, stored):
        lossy = LossyKeyring(stored)
        with pytest.raises(KeyUnavailable, match="read-back mismatch"):
            make(config, lossy).create(KeyBackend.KEYRING, store_exists=False)
        assert not (config / RECIPIENT_FILE).exists()
        assert lossy.items == {}

    def test_read_back_with_trailing_whitespace_is_accepted(self, config, ring, monkeypatch):
        original = ring.set_password
        monkeypatch.setattr(ring, "set_password", lambda s, u, p: original(s, u, p + "\n"))
        identity = make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        assert make(config, ring).load() == identity

    def test_keyring_set_failure_saves_nothing(self, config):
        failing = FailingKeyring(SecretServiceNotAvailableException(), on=frozenset({"set"}))
        with pytest.raises(KeyUnavailable, match="not available"):
            make(config, failing).create(KeyBackend.KEYRING, store_exists=False)
        assert not (config / RECIPIENT_FILE).exists()

    def test_recipient_write_failure_rolls_back_keyring(self, config, ring, monkeypatch):
        def boom(*_a, **_k):
            raise StorageError("not enough disk space to write recipient.txt")

        monkeypatch.setattr(keystore.fsutil, "atomic_write", boom)
        with pytest.raises(StorageError):
            make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        assert ring.items == {}
        assert "delete" in ring.calls

    def test_rollback_failure_does_not_mask_original_error(self, config, monkeypatch):
        ring = FailingKeyring(RuntimeError("dbus"), on=frozenset({"delete"}))

        def boom(*_a, **_k):
            raise StorageError("disk full")

        monkeypatch.setattr(keystore.fsutil, "atomic_write", boom)
        with pytest.raises(StorageError, match="disk full"):
            make(config, ring).create(KeyBackend.KEYRING, store_exists=False)

    def test_keyboard_interrupt_during_recipient_write_rolls_back(self, config, ring, monkeypatch):
        def interrupt(*_a, **_k):
            raise KeyboardInterrupt

        monkeypatch.setattr(keystore.fsutil, "atomic_write", interrupt)
        with pytest.raises(KeyboardInterrupt):
            make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        assert ring.items == {}

    def test_passphrase_given_in_keyring_mode_is_a_usage_error(self, config, ring):
        with pytest.raises(VeilError) as info:
            make(config, ring).create(KeyBackend.KEYRING, store_exists=False, passphrase=PASS)
        assert info.value.exit_code == ExitCode.USAGE
        assert ring.calls == []


# ── create: refusals (never regenerate) ───────────────────────────────────────


class TestNeverRegenerate:
    @pytest.mark.parametrize("backend", list(KeyBackend))
    def test_refuses_when_store_exists(self, config, ring, backend):
        kwargs = {"passphrase": PASS} if backend is KeyBackend.FILE else {}
        with pytest.raises(VeilError, match="encrypted persona already exists") as info:
            make(config, ring).create(backend, store_exists=True, **kwargs)
        assert info.value.exit_code == ExitCode.USAGE
        assert ring.items == {}
        assert not config.exists()

    @pytest.mark.parametrize("backend", list(KeyBackend))
    def test_refuses_second_create(self, config, ring, backend):
        kwargs = {"passphrase": PASS} if backend is KeyBackend.FILE else {}
        first = make(config, ring).create(backend, store_exists=False, **kwargs)
        before = (config / RECIPIENT_FILE).read_bytes()
        with pytest.raises(VeilError, match="refusing to create a new key"):
            make(config, ring).create(backend, store_exists=False, **kwargs)
        assert (config / RECIPIENT_FILE).read_bytes() == before
        assert make(config, ring).load(lambda: PASS) == first

    def test_refuses_when_only_keyring_entry_exists(self, config, ring):
        ring.items[(SERVICE, keystore.keyring_username(config))] = age.generate_identity().secret
        with pytest.raises(VeilError, match="already exists in the keyring"):
            make(config, ring).create(KeyBackend.KEYRING, store_exists=False)

    def test_file_mode_refuses_when_keyring_entry_exists(self, config, ring):
        ring.items[(SERVICE, keystore.keyring_username(config))] = age.generate_identity().secret
        with pytest.raises(VeilError, match="already exists in the keyring"):
            make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        assert not (config / KEY_FILE).exists()

    def test_refuses_when_only_key_file_exists(self, config, ring):
        config.mkdir(parents=True)
        (config / KEY_FILE).write_bytes(b"x")
        with pytest.raises(VeilError, match="passphrase key file already exists"):
            make(config, ring).create(KeyBackend.KEYRING, store_exists=False)

    def test_refuses_when_recipient_is_a_dangling_symlink(self, config, ring, tmp_path):
        config.mkdir(parents=True)
        (config / RECIPIENT_FILE).symlink_to(tmp_path / "nowhere")
        with pytest.raises(VeilError, match=r"recipient\.txt already exists"):
            make(config, ring).create(KeyBackend.KEYRING, store_exists=False)

    def test_refusal_message_is_value_free(self, config, ring):
        secret = age.generate_identity().secret
        ring.items[(SERVICE, keystore.keyring_username(config))] = secret
        with pytest.raises(VeilError) as info:
            make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        assert secret not in str(info.value)


# ── create: passphrase file ───────────────────────────────────────────────────


class TestCreateFile:
    def test_writes_encrypted_key_file_and_recipient(self, config, ring):
        identity = make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        data = (config / KEY_FILE).read_bytes()
        assert age.is_age(data)
        assert identity.secret.encode() not in data
        assert mode(config / KEY_FILE) == 0o600
        assert (config / RECIPIENT_FILE).read_text().strip() == identity.recipient
        assert ring.items == {}

    def test_round_trip(self, config, ring):
        created = make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        assert make(config, ring).load(lambda: PASS) == created

    def test_works_without_any_keyring(self, config):
        dead = FailingKeyring(SecretServiceNotAvailableException(), on=frozenset({"get", "set"}))
        created = make(config, dead).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        assert make(config, dead).load(lambda: PASS) == created
        assert dead.calls == ["get"]  # only the "is there already a key?" probe at setup

    def test_load_never_touches_keyring(self, config, ring):
        make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        ring.calls.clear()
        make(config, ring).load(lambda: PASS)
        assert ring.calls == []

    def test_missing_passphrase_is_a_usage_error(self, config, ring):
        with pytest.raises(VeilError) as info:
            make(config, ring).create(KeyBackend.FILE, store_exists=False)
        assert info.value.exit_code == ExitCode.USAGE

    @pytest.mark.parametrize("weak", ["", "short", "       ", "1234567"])
    def test_weak_passphrase_refused_before_anything_is_written(self, config, ring, weak):
        with pytest.raises(VeilError) as info:
            make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=weak)
        assert info.value.exit_code == ExitCode.USAGE
        assert not config.exists()
        assert ring.calls == []

    def test_unicode_passphrase(self, config, ring):
        phrase = "मेरा गुप्त वाक्यांश"
        created = make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=phrase)
        assert make(config, ring).load(lambda: phrase) == created

    def test_verify_failure_saves_nothing(self, config, ring, monkeypatch):
        real = age.passphrase_decrypt
        monkeypatch.setattr(age, "passphrase_decrypt", lambda c, p: real(c, p) + b"x")
        with pytest.raises(KeyUnavailable, match="did not verify"):
            make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        assert not (config / KEY_FILE).exists()
        assert not (config / RECIPIENT_FILE).exists()

    def test_recipient_write_failure_removes_key_file(self, config, ring, monkeypatch):
        real_write = keystore.fsutil.atomic_write

        def write(path, data, **kw):
            if path.name == RECIPIENT_FILE:
                raise StorageError("not enough disk space")
            return real_write(path, data, **kw)

        monkeypatch.setattr(keystore.fsutil, "atomic_write", write)
        with pytest.raises(StorageError):
            make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        assert not (config / KEY_FILE).exists()
        assert not (config / RECIPIENT_FILE).exists()


# ── load ──────────────────────────────────────────────────────────────────────


class TestLoad:
    def test_nothing_set_up(self, config, ring):
        with pytest.raises(KeyUnavailable, match="no key has been set up") as info:
            make(config, ring).load()
        assert info.value.exit_code == ExitCode.KEY_UNAVAILABLE

    def test_keyring_entry_missing_gives_recovery_hint(self, config, ring):
        make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        ring.items.clear()
        with pytest.raises(KeyUnavailable, match=r"missing from the keyring.*backup"):
            make(config, ring).load()

    def test_keyring_entry_replaced_by_other_key_is_detected(self, config, ring):
        make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        impostor = age.generate_identity()
        ring.items[(SERVICE, keystore.keyring_username(config))] = impostor.secret
        with pytest.raises(KeyUnavailable, match=r"does not match recipient\.txt") as info:
            make(config, ring).load()
        assert impostor.secret not in str(info.value)
        assert impostor.recipient not in str(info.value)

    def test_recipient_file_replaced_is_detected(self, config, ring):
        make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        (config / RECIPIENT_FILE).write_text(age.generate_identity().recipient + "\n")
        with pytest.raises(KeyUnavailable, match="does not match"):
            make(config, ring).load()

    @pytest.mark.parametrize("content", [b"", b"\n", b"garbage\n", b"\xff\xfe", b"age1nope"])
    def test_corrupt_recipient_file(self, config, ring, content):
        make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        (config / RECIPIENT_FILE).write_bytes(content)
        with pytest.raises(DecryptFailed, match="not a valid age recipient"):
            make(config, ring).load()

    def test_oversized_recipient_file(self, config, ring):
        make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        (config / RECIPIENT_FILE).write_bytes(b"a" * 5000)
        with pytest.raises(StorageError, match="larger than"):
            make(config, ring).load()

    def test_symlinked_recipient_file_is_refused(self, config, ring, tmp_path):
        identity = make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        elsewhere = tmp_path / "elsewhere.txt"
        elsewhere.write_text(identity.recipient + "\n")
        (config / RECIPIENT_FILE).unlink()
        (config / RECIPIENT_FILE).symlink_to(elsewhere)
        with pytest.raises(VeilError, match="symbolic link") as info:
            make(config, ring).load()
        assert info.value.exit_code == ExitCode.UNSAFE_ENVIRONMENT

    def test_corrupt_keyring_entry(self, config, ring):
        make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        ring.items[(SERVICE, keystore.keyring_username(config))] = "not-a-key"
        with pytest.raises(KeyUnavailable, match="not a valid age identity") as info:
            make(config, ring).load()
        assert "not-a-key" not in str(info.value)

    def test_wrong_passphrase(self, config, ring):
        make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        with pytest.raises(DecryptFailed, match="wrong passphrase") as info:
            make(config, ring).load(lambda: "wrong horse battery")
        assert info.value.exit_code == ExitCode.DECRYPT_FAILED
        assert "horse" not in str(info.value)

    def test_passphrase_mode_without_prompt(self, config, ring):
        make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        with pytest.raises(KeyUnavailable, match="no prompt"):
            make(config, ring).load()

    def test_corrupt_key_file(self, config, ring):
        make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        (config / KEY_FILE).write_bytes(b"not age at all")
        with pytest.raises(DecryptFailed):
            make(config, ring).load(lambda: PASS)

    def test_key_file_holding_non_ascii(self, config, ring, monkeypatch):
        make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        monkeypatch.setattr(age, "passphrase_decrypt", lambda _c, _p: b"\xff\xfe")
        with pytest.raises(KeyUnavailable, match="not a valid age identity"):
            make(config, ring).load(lambda: PASS)

    def test_symlinked_key_file_is_refused(self, config, ring, tmp_path):
        make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        moved = tmp_path / "moved"
        (config / KEY_FILE).rename(moved)
        (config / KEY_FILE).symlink_to(moved)
        with pytest.raises(VeilError, match="symbolic link"):
            make(config, ring).load(lambda: PASS)

    def test_loose_recipient_mode_is_tightened(self, config, ring):
        make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        (config / RECIPIENT_FILE).chmod(0o644)
        make(config, ring).load()
        assert mode(config / RECIPIENT_FILE) == 0o600

    def test_recipient_alone_is_enough_to_encrypt(self, config, ring):
        identity = make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        ring.calls.clear()
        assert make(config, ring).recipient() == identity.recipient
        assert ring.calls == []


# ── keyring failures: locked, unavailable, hanging ────────────────────────────


class TestKeyringFailures:
    @pytest.fixture
    def set_up(self, config, ring):
        make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        return config

    @pytest.mark.parametrize("error", [LockedException(), PromptDismissedException()])
    def test_locked_or_dismissed(self, set_up, error):
        with pytest.raises(KeyUnavailable, match="locked; unlock KDE Wallet") as info:
            make(set_up, FailingKeyring(error)).load()
        assert info.value.exit_code == ExitCode.KEY_UNAVAILABLE

    def test_keyring_library_locked_error(self, set_up):
        from keyring.errors import KeyringLocked

        with pytest.raises(KeyUnavailable, match="locked"):
            make(set_up, FailingKeyring(KeyringLocked("x"))).load()

    @pytest.mark.parametrize(
        "error",
        [SecretServiceNotAvailableException("no dbus"), RuntimeError("boom"), OSError(5, "io")],
    )
    def test_unavailable(self, set_up, error):
        with pytest.raises(KeyUnavailable, match="not available") as info:
            make(set_up, FailingKeyring(error)).load()
        assert type(error).__name__ in str(info.value)

    def test_keyring_library_errors(self, set_up):
        from keyring.errors import InitError, NoKeyringError

        for error in (InitError("x"), NoKeyringError("x")):
            with pytest.raises(KeyUnavailable):
                make(set_up, FailingKeyring(error)).load()

    def test_backend_factory_failure(self, set_up):
        def factory():
            raise SecretServiceNotAvailableException("no session bus")

        with pytest.raises(KeyUnavailable, match="not available"):
            KeyStore(set_up, secrets=factory, timeout=2).load()

    def test_error_text_from_backend_is_not_copied(self, set_up):
        error = RuntimeError("Jane Doe secret detail")
        with pytest.raises(KeyUnavailable) as info:
            make(set_up, FailingKeyring(error)).load()
        assert "Jane" not in str(info.value)
        assert info.value.__cause__ is None

    def test_hanging_keyring_times_out(self, set_up):
        hanging = HangingKeyring(on="get")
        start = time.monotonic()
        try:
            with pytest.raises(KeyUnavailable, match="did not answer within") as info:
                make(set_up, hanging, timeout=0.2).load()
        finally:
            hanging.release.set()
        assert time.monotonic() - start < 5
        assert info.value.exit_code == ExitCode.KEY_UNAVAILABLE

    def test_hanging_set_during_create_times_out(self, config):
        hanging = HangingKeyring(on="set")
        try:
            with pytest.raises(KeyUnavailable, match="did not answer"):
                make(config, hanging, timeout=0.2).create(KeyBackend.KEYRING, store_exists=False)
        finally:
            hanging.release.set()
        assert not (config / RECIPIENT_FILE).exists()

    def test_worker_is_a_daemon_thread(self, set_up):
        hanging = HangingKeyring(on="get")
        try:
            with pytest.raises(KeyUnavailable):
                make(set_up, hanging, timeout=0.1).load()
            workers = [t for t in threading.enumerate() if t.name == "veil-keyring"]
            assert workers
            assert all(t.daemon for t in workers)
        finally:
            hanging.release.set()

    def test_calls_run_off_the_main_thread(self, set_up, ring):
        seen: list[str] = []
        original = ring.get_password

        def get(service, username):
            seen.append(threading.current_thread().name)
            return original(service, username)

        ring.get_password = get
        make(set_up, ring).load()
        assert seen == ["veil-keyring"]

    def test_backend_created_lazily_and_once(self, set_up, ring):
        created: list[int] = []

        def factory():
            created.append(1)
            return ring

        store = KeyStore(set_up, secrets=factory, timeout=2)
        assert created == []
        store.load()
        store.load()
        assert created == [1]


# ── status / pinning ──────────────────────────────────────────────────────────


class TestStatusAndPinning:
    def test_status_nothing(self, config):
        status = make(config).status()
        assert status == keystore.KeyStatus(backend=None, recipient_file=False, key_file=False)

    def test_status_keyring(self, config, ring):
        make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        ring.calls.clear()
        assert make(config, ring).status().backend is KeyBackend.KEYRING
        assert ring.calls == []

    def test_status_file(self, config, ring):
        make(config, ring).create(KeyBackend.FILE, store_exists=False, passphrase=PASS)
        status = make(config, ring).status()
        assert status.backend is KeyBackend.FILE
        assert status.key_file
        assert status.recipient_file

    def test_status_repr_is_value_free(self, config, ring):
        identity = make(config, ring).create(KeyBackend.KEYRING, store_exists=False)
        text = repr(make(config, ring).status())
        assert identity.recipient not in text
        assert str(config) not in text

    def test_default_backend_is_pinned_secret_service(self):
        import inspect

        source = inspect.getsource(keystore)
        assert "keyring.backends.SecretService import Keyring" in source
        assert "get_keyring" not in source.replace("`keyring.get_keyring()`", "")
        assert "PYTHON_KEYRING_BACKEND" not in source.replace("never `PYTHON_KEYRING_BACKEND`", "")

    def test_tests_cannot_reach_the_real_keyring(self, config):
        with pytest.raises(KeyUnavailable, match="AssertionError"):
            KeyStore(config, timeout=2)._keyring_get()


class TestKeyringUsername:
    def test_default_config_dir_keeps_plain_name(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        assert keystore.keyring_username(tmp_path / ".config" / "veil") == USERNAME

    def test_default_dir_via_symlinked_home(self, tmp_path, monkeypatch):
        real = tmp_path / "real-home"
        (real / ".config" / "veil").mkdir(parents=True)
        link = tmp_path / "link-home"
        link.symlink_to(real)
        monkeypatch.setenv("HOME", str(link))
        assert keystore.keyring_username(real / ".config" / "veil") == USERNAME

    def test_other_dir_gets_stable_suffix(self, tmp_path):
        a = keystore.keyring_username(tmp_path / "a")
        assert a.startswith(USERNAME + "-")
        assert len(a) == len(USERNAME) + 13
        assert keystore.keyring_username(tmp_path / "a") == a
        assert keystore.keyring_username(tmp_path / "x" / ".." / "a") == a

    def test_different_dirs_differ(self, tmp_path):
        names = {keystore.keyring_username(tmp_path / f"d{i}") for i in range(50)}
        assert len(names) == 50

    def test_unicode_dir(self, tmp_path):
        assert keystore.keyring_username(tmp_path / "व्यक्ति").startswith(USERNAME + "-")

    def test_suffix_reveals_nothing_about_the_path(self, tmp_path):
        name = keystore.keyring_username(tmp_path / "jane-doe-config")
        assert "jane" not in name

    def test_two_stores_share_a_keyring_without_colliding(self, tmp_path, ring):
        first = make(tmp_path / "one", ring).create(KeyBackend.KEYRING, store_exists=False)
        second = make(tmp_path / "two", ring).create(KeyBackend.KEYRING, store_exists=False)
        assert len(ring.items) == 2
        assert make(tmp_path / "one", ring).load() == first
        assert make(tmp_path / "two", ring).load() == second

    def test_test_store_does_not_block_the_real_first_import(self, tmp_path, ring, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        make(tmp_path / "throwaway", ring).create(KeyBackend.KEYRING, store_exists=False)
        real = make(tmp_path / "home" / ".config" / "veil", ring)
        assert real.username == USERNAME
        real.create(KeyBackend.KEYRING, store_exists=False)
        assert (SERVICE, USERNAME) in ring.items
