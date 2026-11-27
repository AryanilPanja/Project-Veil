"""persona/store.py: encrypted, verified, atomic persona storage with a .bak."""

import stat

import pytest

from veil import fsutil
from veil.crypto import age
from veil.errors import Busy, DecryptFailed, KeyUnavailable, StorageError, UnsafeEnvironment
from veil.persona import canary
from veil.persona.store import MAX_STORE_BYTES, Payload, PersonaStore
from veil.persona.yamlio import MAX_BYTES

ID = age.generate_identity()
OTHER = age.generate_identity()


def payload(body: str = "person:\n  first_name: { real: Jane, fake: Alex }\n") -> Payload:
    return Payload(canary.insert('version: "1"\n' + body, canary.generate()).encode())


@pytest.fixture
def store(tmp_path):
    return PersonaStore(tmp_path / "veil")


def mode(path):
    return stat.S_IMODE(path.lstat().st_mode)


class TestPayload:
    def test_repr_hides_contents(self):
        p = payload()
        assert "Jane" not in repr(p)
        assert "Jane" not in str(p)
        assert repr(p) == f"Payload({len(p.data)} bytes)"

    def test_canary_found(self):
        p = payload()
        assert canary.is_canary(p.canary)

    def test_no_canary(self):
        assert Payload(b'version: "1"\n').canary is None

    def test_two_different_canaries_is_not_valid(self):
        data = payload().data + f"# {canary.generate()}\n".encode()
        assert Payload(data).canary is None

    def test_non_utf8_bytes_do_not_crash(self):
        assert Payload(b"\xff\xfe").canary is None


class TestSaveLoad:
    def test_round_trip(self, store):
        p = payload()
        store.save(p, ID, recipient=ID.recipient)
        assert store.load(ID) == p

    def test_file_is_age_and_hides_plaintext(self, store):
        store.save(payload(), ID, recipient=ID.recipient)
        data = store.path.read_bytes()
        assert age.is_age(data)
        assert b"Jane" not in data
        assert b"VEIL-CANARY" not in data

    def test_private_permissions(self, store):
        store.save(payload(), ID, recipient=ID.recipient)
        assert mode(store.directory) == 0o700
        assert mode(store.path) == 0o600

    def test_exists(self, store):
        assert not store.exists()
        store.save(payload(), ID, recipient=ID.recipient)
        assert store.exists()

    def test_second_save_keeps_backup_of_first(self, store):
        first, second = payload(), payload("person: {}\n")
        store.save(first, ID, recipient=ID.recipient)
        assert not store.backup_path.exists()
        store.save(second, ID, recipient=ID.recipient)
        assert store.load(ID) == second
        assert age.decrypt(store.backup_path.read_bytes(), ID) == first.data
        assert mode(store.backup_path) == 0o600

    def test_no_temp_files_left(self, store):
        store.save(payload(), ID, recipient=ID.recipient)
        store.save(payload(), ID, recipient=ID.recipient)
        assert [p.name for p in store.directory.iterdir() if p.name.endswith(".tmp")] == []

    def test_stale_temps_from_a_crash_are_cleaned(self, store):
        store.directory.mkdir(mode=0o700)
        stale = store.directory / ".persona.age.abc123.tmp"
        stale.write_bytes(b"half-written")
        store.save(payload(), ID, recipient=ID.recipient)
        assert not stale.exists()

    def test_unicode_payload(self, store):
        p = payload("person:\n  first_name: { real: जेन, fake: अॅलेक्स }\n")
        store.save(p, ID, recipient=ID.recipient)
        assert store.load(ID) == p


class TestSaveRefusals:
    def test_identity_must_match_recipient(self, store):
        with pytest.raises(KeyUnavailable, match="does not match"):
            store.save(payload(), ID, recipient=OTHER.recipient)
        assert not store.exists()

    def test_payload_without_canary_refused(self, store):
        with pytest.raises(DecryptFailed, match="canary"):
            store.save(Payload(b'version: "1"\n'), ID, recipient=ID.recipient)
        assert not store.exists()

    def test_oversized_payload_refused(self, store):
        big = payload("never_translate:\n" + "  - x\n" * (MAX_BYTES // 6 + 10))
        assert len(big.data) > MAX_BYTES
        with pytest.raises(StorageError, match="larger than"):
            store.save(big, ID, recipient=ID.recipient)

    def test_verify_failure_keeps_old_store(self, store, monkeypatch):
        old = payload()
        store.save(old, ID, recipient=ID.recipient)
        before = store.path.read_bytes()
        real = age.decrypt
        monkeypatch.setattr(age, "decrypt", lambda c, i: real(c, i) + b"corrupted")
        with pytest.raises(DecryptFailed, match="did not verify"):
            store.save(payload(), ID, recipient=ID.recipient)
        assert store.path.read_bytes() == before

    def test_disk_full_keeps_old_store(self, store, monkeypatch):
        old = payload()
        store.save(old, ID, recipient=ID.recipient)

        def full(*_a, **_k):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(fsutil.os, "write", full)
        with pytest.raises(StorageError, match="not enough disk space"):
            store.save(payload(), ID, recipient=ID.recipient)
        monkeypatch.undo()
        assert store.load(ID) == old

    def test_symlinked_store_is_not_replaced(self, store, tmp_path):
        store.directory.mkdir(mode=0o700)
        victim = tmp_path / "victim"
        victim.write_bytes(b"keep")
        store.path.symlink_to(victim)
        with pytest.raises(UnsafeEnvironment):
            store.save(payload(), ID, recipient=ID.recipient)
        assert victim.read_bytes() == b"keep"


class TestLoadFailures:
    def test_missing_store(self, store):
        with pytest.raises(KeyUnavailable, match="no encrypted persona yet"):
            store.load(ID)

    def test_wrong_key(self, store):
        store.save(payload(), ID, recipient=ID.recipient)
        with pytest.raises(DecryptFailed, match="wrong key"):
            store.load(OTHER)

    def test_truncated(self, store):
        store.save(payload(), ID, recipient=ID.recipient)
        store.path.write_bytes(store.path.read_bytes()[:-10])
        with pytest.raises(DecryptFailed):
            store.load(ID)

    def test_replaced_with_plaintext(self, store):
        store.save(payload(), ID, recipient=ID.recipient)
        store.path.write_bytes(b'version: "1"\n')
        with pytest.raises(DecryptFailed, match="not an age-encrypted file"):
            store.load(ID)

    def test_valid_age_without_canary_is_rejected(self, store):
        store.directory.mkdir(mode=0o700)
        store.path.write_bytes(age.encrypt(b'version: "1"\n', ID.recipient))
        store.path.chmod(0o600)
        with pytest.raises(DecryptFailed, match="no valid canary"):
            store.load(ID)

    def test_oversized_file(self, store):
        store.directory.mkdir(mode=0o700)
        store.path.write_bytes(b"x" * (MAX_STORE_BYTES + 1))
        with pytest.raises(StorageError, match="larger than"):
            store.load(ID)

    def test_symlink(self, store, tmp_path):
        other = PersonaStore(tmp_path / "elsewhere")
        other.save(payload(), ID, recipient=ID.recipient)
        store.directory.mkdir(mode=0o700)
        store.path.symlink_to(other.path)
        with pytest.raises(UnsafeEnvironment, match="symbolic link"):
            store.load(ID)

    def test_loose_mode_tightened_on_load(self, store):
        store.save(payload(), ID, recipient=ID.recipient)
        store.path.chmod(0o644)
        store.load(ID)
        assert mode(store.path) == 0o600

    def test_errors_never_contain_plaintext(self, store):
        store.save(
            payload("person:\n  first_name: { real: Jane, fake: Alex }\n"),
            ID,
            recipient=ID.recipient,
        )
        with pytest.raises(DecryptFailed) as info:
            store.load(OTHER)
        assert "Jane" not in str(info.value)


class TestLock:
    def test_lock_is_exclusive(self, store):
        with store.lock(), pytest.raises(Busy), store.lock():
            pass

    def test_lock_creates_private_dir(self, store):
        with store.lock():
            assert mode(store.directory) == 0o700
