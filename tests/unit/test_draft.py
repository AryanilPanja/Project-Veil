"""persona/draft.py: unsaved edits kept encrypted, never in plaintext on disk."""

import stat

import pytest

from veil.crypto import age
from veil.errors import DecryptFailed, StorageError, UnsafeEnvironment, VeilError
from veil.exitcodes import ExitCode
from veil.persona.draft import DRAFT_FILE, DraftStore

ID = age.generate_identity()
OTHER = age.generate_identity()
TEXT = b'version: "1"\nperson:\n  first_name: { real: Jane, fake: Alex }\nnot_a_field: 1\n'


@pytest.fixture
def drafts(tmp_path):
    return DraftStore(tmp_path / "veil")


def test_round_trip_and_private_file(drafts):
    drafts.save(TEXT, ID.recipient, ID)
    assert drafts.exists()
    assert drafts.load(ID) == TEXT
    assert stat.S_IMODE(drafts.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(drafts.directory.stat().st_mode) == 0o700
    assert drafts.path.name == DRAFT_FILE


def test_ciphertext_hides_the_text(drafts):
    drafts.save(TEXT, ID.recipient)
    raw = drafts.path.read_bytes()
    assert age.is_age(raw)
    assert b"Jane" not in raw
    assert b"not_a_field" not in raw


def test_save_without_identity_skips_verification(drafts):
    drafts.save(TEXT, ID.recipient)  # recovery path: only the public key is needed
    assert drafts.load(ID) == TEXT


def test_overwrite_replaces_previous_draft(drafts):
    drafts.save(b"first", ID.recipient, ID)
    drafts.save(b"second", ID.recipient, ID)
    assert drafts.load(ID) == b"second"


def test_verify_failure_keeps_previous_draft(drafts, monkeypatch):
    drafts.save(b"first", ID.recipient, ID)
    real = age.decrypt
    monkeypatch.setattr(age, "decrypt", lambda c, i: real(c, i) + b"!")
    with pytest.raises(DecryptFailed, match="did not verify"):
        drafts.save(b"second", ID.recipient, ID)
    monkeypatch.undo()
    assert drafts.load(ID) == b"first"


def test_load_missing_is_usage_error(drafts):
    with pytest.raises(VeilError, match="no saved draft") as info:
        drafts.load(ID)
    assert info.value.exit_code == ExitCode.USAGE


def test_wrong_key(drafts):
    drafts.save(TEXT, ID.recipient)
    with pytest.raises(DecryptFailed):
        drafts.load(OTHER)


def test_corrupt_draft(drafts):
    drafts.save(TEXT, ID.recipient)
    drafts.path.write_bytes(b"garbage")
    with pytest.raises(DecryptFailed):
        drafts.load(ID)


def test_symlinked_draft_refused(drafts, tmp_path):
    drafts.directory.mkdir(mode=0o700)
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep")
    drafts.path.symlink_to(victim)
    with pytest.raises(UnsafeEnvironment):
        drafts.save(TEXT, ID.recipient)
    assert victim.read_bytes() == b"keep"


def test_remove(drafts):
    assert drafts.remove() is False
    drafts.save(TEXT, ID.recipient)
    assert drafts.remove() is True
    assert not drafts.exists()


def test_disk_full(drafts, monkeypatch):
    from veil import fsutil

    def full(*_a, **_k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(fsutil.os, "write", full)
    with pytest.raises(StorageError):
        drafts.save(TEXT, ID.recipient)
    monkeypatch.undo()
    assert not drafts.exists()


def test_unicode_text(drafts):
    text = "never_translate: [নমুনা, नमूना]\n".encode()
    drafts.save(text, ID.recipient, ID)
    assert drafts.load(ID) == text
