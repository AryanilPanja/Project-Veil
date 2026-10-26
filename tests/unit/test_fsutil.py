"""fsutil.py: private dirs/files, atomic write, symlink refusal, ENOSPC, flock, secure_remove."""

import errno
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil import fsutil
from veil.errors import Busy, StorageError, UnsafeEnvironment, VeilError
from veil.exitcodes import ExitCode

OLD = b"old contents\n"
NEW = "नया content ✓\n".encode()


def mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.endswith(fsutil.TEMP_SUFFIX))


@pytest.fixture
def target(tmp_path):
    path = tmp_path / "store.bin"
    path.write_bytes(OLD)
    path.chmod(0o600)
    return path


def fail_with(err: int):
    def boom(*_args, **_kwargs):
        raise OSError(err, os.strerror(err))

    return boom


# ── ensure_private_dir ────────────────────────────────────────────────────────


class TestEnsurePrivateDir:
    def test_creates_missing_dir_and_parents_0700(self, tmp_path):
        d = tmp_path / "a" / "b" / "veil"
        assert fsutil.ensure_private_dir(d) == d
        assert d.is_dir()
        assert mode(d) == 0o700

    def test_existing_private_dir_is_fine(self, tmp_path):
        d = tmp_path / "veil"
        d.mkdir(mode=0o700)
        fsutil.ensure_private_dir(d)
        assert mode(d) == 0o700

    @pytest.mark.parametrize("loose", [0o755, 0o750, 0o777, 0o701])
    def test_loose_mode_is_tightened(self, tmp_path, loose):
        d = tmp_path / "veil"
        d.mkdir()
        d.chmod(loose)
        fsutil.ensure_private_dir(d)
        assert mode(d) == 0o700

    def test_idempotent(self, tmp_path):
        d = tmp_path / "veil"
        for _ in range(3):
            fsutil.ensure_private_dir(d)
        assert mode(d) == 0o700

    def test_symlink_is_refused(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir(mode=0o700)
        link = tmp_path / "veil"
        link.symlink_to(real)
        with pytest.raises(UnsafeEnvironment, match="symbolic link") as info:
            fsutil.ensure_private_dir(link)
        assert info.value.exit_code == ExitCode.UNSAFE_ENVIRONMENT

    def test_dangling_symlink_is_refused(self, tmp_path):
        link = tmp_path / "veil"
        link.symlink_to(tmp_path / "nowhere")
        with pytest.raises(UnsafeEnvironment, match="symbolic link"):
            fsutil.ensure_private_dir(link)
        assert not (tmp_path / "nowhere").exists()

    def test_file_in_the_way_is_refused(self, tmp_path):
        f = tmp_path / "veil"
        f.write_bytes(b"")
        with pytest.raises(UnsafeEnvironment, match="not a directory"):
            fsutil.ensure_private_dir(f)

    def test_foreign_owner_is_refused(self, tmp_path, monkeypatch):
        d = tmp_path / "veil"
        d.mkdir(mode=0o700)
        monkeypatch.setattr(fsutil.os, "getuid", lambda: d.stat().st_uid + 1)
        with pytest.raises(UnsafeEnvironment, match="not owned by you"):
            fsutil.ensure_private_dir(d)

    def test_uses_the_label_and_never_the_path(self, tmp_path):
        f = tmp_path / "secret-name"
        f.write_bytes(b"")
        with pytest.raises(UnsafeEnvironment) as info:
            fsutil.ensure_private_dir(f, what="the config directory")
        assert "the config directory" in str(info.value)
        assert "secret-name" not in str(info.value)

    def test_mkdir_permission_error(self, tmp_path):
        locked = tmp_path / "locked"
        locked.mkdir(mode=0o500)
        try:
            with pytest.raises(VeilError):
                fsutil.ensure_private_dir(locked / "veil")
        finally:
            locked.chmod(0o700)


# ── check_private_file / read_private ─────────────────────────────────────────


class TestCheckPrivateFile:
    def test_private_file_passes(self, target):
        assert fsutil.check_private_file(target).st_size == len(OLD)

    @pytest.mark.parametrize("loose", [0o644, 0o640, 0o666, 0o604])
    def test_loose_mode_is_tightened(self, target, loose):
        target.chmod(loose)
        fsutil.check_private_file(target)
        assert mode(target) == 0o600

    def test_symlink_is_refused(self, target, tmp_path):
        link = tmp_path / "link"
        link.symlink_to(target)
        with pytest.raises(UnsafeEnvironment, match="symbolic link"):
            fsutil.check_private_file(link)

    def test_directory_is_refused(self, tmp_path):
        with pytest.raises(UnsafeEnvironment, match="not a regular file"):
            fsutil.check_private_file(tmp_path)

    def test_fifo_is_refused(self, tmp_path):
        fifo = tmp_path / "fifo"
        os.mkfifo(fifo, 0o600)
        with pytest.raises(UnsafeEnvironment, match="not a regular file"):
            fsutil.check_private_file(fifo)

    def test_missing_file(self, tmp_path):
        with pytest.raises(StorageError, match="does not exist"):
            fsutil.check_private_file(tmp_path / "missing")

    def test_foreign_owner_is_refused(self, target, monkeypatch):
        monkeypatch.setattr(fsutil.os, "getuid", lambda: target.stat().st_uid + 1)
        with pytest.raises(UnsafeEnvironment, match="not owned by you"):
            fsutil.check_private_file(target)


class TestReadPrivate:
    def test_reads_bytes(self, target):
        assert fsutil.read_private(target, max_bytes=100) == OLD

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        assert fsutil.read_private(f, max_bytes=0) == b""

    def test_exactly_at_the_limit(self, target):
        assert fsutil.read_private(target, max_bytes=len(OLD)) == OLD

    def test_one_byte_over_the_limit_is_refused(self, target):
        with pytest.raises(StorageError, match="larger than"):
            fsutil.read_private(target, max_bytes=len(OLD) - 1)

    def test_larger_than_one_chunk(self, tmp_path):
        f = tmp_path / "big"
        data = os.urandom(fsutil._CHUNK * 2 + 17)
        f.write_bytes(data)
        assert fsutil.read_private(f, max_bytes=len(data)) == data

    def test_growth_during_read_is_caught(self, target, monkeypatch):
        monkeypatch.setattr(fsutil.os, "read", lambda _fd, _n: b"x" * 64)
        with pytest.raises(StorageError, match="larger than"):
            fsutil.read_private(target, max_bytes=100)

    def test_symlink_is_refused_via_o_nofollow(self, target, tmp_path):
        link = tmp_path / "link"
        link.symlink_to(target)
        with pytest.raises(UnsafeEnvironment, match="symbolic link"):
            fsutil.read_private(link, max_bytes=100)

    def test_loose_mode_is_tightened(self, target):
        target.chmod(0o644)
        fsutil.read_private(target, max_bytes=100)
        assert mode(target) == 0o600

    def test_directory_is_refused(self, tmp_path):
        with pytest.raises(VeilError):
            fsutil.read_private(tmp_path, max_bytes=100)

    def test_missing_file(self, tmp_path):
        with pytest.raises(StorageError, match="does not exist"):
            fsutil.read_private(tmp_path / "missing", max_bytes=100)

    def test_unreadable_file(self, target):
        target.chmod(0o000)
        try:
            if os.access(target, os.R_OK):
                pytest.skip("running with CAP_DAC_OVERRIDE (root)")
            with pytest.raises(UnsafeEnvironment, match="permission denied"):
                fsutil.read_private(target, max_bytes=100)
        finally:
            target.chmod(0o600)

    def test_io_error_is_a_storage_error(self, target, monkeypatch):
        monkeypatch.setattr(fsutil.os, "read", fail_with(errno.EIO))
        with pytest.raises(StorageError, match="I/O error") as info:
            fsutil.read_private(target, max_bytes=100)
        assert info.value.exit_code == ExitCode.STORAGE


# ── atomic_write ──────────────────────────────────────────────────────────────


class TestAtomicWriteHappyPath:
    def test_replaces_contents(self, target):
        fsutil.atomic_write(target, NEW)
        assert target.read_bytes() == NEW

    def test_creates_new_file_0600(self, tmp_path):
        f = tmp_path / "new.bin"
        fsutil.atomic_write(f, NEW)
        assert f.read_bytes() == NEW
        assert mode(f) == 0o600

    def test_result_is_0600_even_if_old_file_was_loose(self, target):
        target.chmod(0o644)
        fsutil.atomic_write(target, NEW)
        assert mode(target) == 0o600

    def test_result_is_0600_with_permissive_umask(self, tmp_path):
        old = os.umask(0o000)
        try:
            fsutil.atomic_write(tmp_path / "f", NEW)
        finally:
            os.umask(old)
        assert mode(tmp_path / "f") == 0o600

    def test_replaces_inode_rather_than_writing_in_place(self, target):
        before = target.stat().st_ino
        fsutil.atomic_write(target, NEW)
        assert target.stat().st_ino != before

    def test_empty_data(self, target):
        fsutil.atomic_write(target, b"")
        assert target.read_bytes() == b""

    def test_large_data_spanning_chunks(self, tmp_path):
        data = os.urandom(fsutil._CHUNK * 3 + 5)
        fsutil.atomic_write(tmp_path / "big", data)
        assert (tmp_path / "big").read_bytes() == data

    def test_short_writes_are_completed(self, tmp_path, monkeypatch):
        real_write = os.write
        monkeypatch.setattr(fsutil.os, "write", lambda fd, buf: real_write(fd, bytes(buf[:3])))
        fsutil.atomic_write(tmp_path / "f", NEW)
        assert (tmp_path / "f").read_bytes() == NEW

    def test_no_temp_files_left(self, target):
        fsutil.atomic_write(target, NEW)
        assert leftovers(target.parent) == []

    def test_unicode_file_name(self, tmp_path):
        f = tmp_path / "व्यक्ति.age-like"
        fsutil.atomic_write(f, NEW)
        assert f.read_bytes() == NEW

    def test_directory_is_fsynced(self, target, monkeypatch):
        synced: list[Path] = []
        monkeypatch.setattr(fsutil, "fsync_dir", synced.append)
        fsutil.atomic_write(target, NEW)
        assert synced == [target.parent]

    def test_data_is_fsynced_before_rename(self, target, monkeypatch):
        events: list[str] = []
        real_fsync, real_replace = os.fsync, Path.replace
        monkeypatch.setattr(fsutil.os, "fsync", lambda fd: events.append("fsync") or real_fsync(fd))
        monkeypatch.setattr(
            Path, "replace", lambda s, t: events.append("replace") or real_replace(s, t)
        )
        fsutil.atomic_write(target, NEW)
        assert events.index("fsync") < events.index("replace")

    @given(st.binary(max_size=4096))
    def test_round_trips_any_bytes(self, data):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "f"
            fsutil.atomic_write(f, data)
            assert f.read_bytes() == data
            assert fsutil.read_private(f, max_bytes=len(data)) == data


class TestAtomicWriteVerify:
    def test_verify_sees_the_complete_temp_file(self, target):
        seen: list[tuple[bytes, int, bool]] = []

        def verify(temp: Path) -> None:
            seen.append((temp.read_bytes(), mode(temp), temp.parent == target.parent))

        fsutil.atomic_write(target, NEW, verify=verify)
        assert seen == [(NEW, 0o600, True)]

    def test_verify_runs_while_old_file_is_still_in_place(self, target):
        fsutil.atomic_write(target, NEW, verify=lambda _t: self._assert_old(target))
        assert target.read_bytes() == NEW

    @staticmethod
    def _assert_old(target: Path) -> None:
        assert target.read_bytes() == OLD

    def test_verify_failure_keeps_old_file_and_cleans_up(self, target):
        def verify(_temp: Path) -> None:
            raise VeilError("decrypt check failed", exit_code=ExitCode.DECRYPT_FAILED)

        with pytest.raises(VeilError, match="decrypt check failed"):
            fsutil.atomic_write(target, NEW, verify=verify, backup=True)
        assert target.read_bytes() == OLD
        assert leftovers(target.parent) == []
        assert not target.with_name(target.name + ".bak").exists()

    def test_unexpected_exception_in_verify_still_cleans_up(self, target):
        with pytest.raises(ZeroDivisionError):
            fsutil.atomic_write(target, NEW, verify=lambda _t: 1 / 0)
        assert target.read_bytes() == OLD
        assert leftovers(target.parent) == []

    def test_keyboard_interrupt_cleans_up(self, target):
        def verify(_temp: Path) -> None:
            raise KeyboardInterrupt

        with pytest.raises(KeyboardInterrupt):
            fsutil.atomic_write(target, NEW, verify=verify)
        assert target.read_bytes() == OLD
        assert leftovers(target.parent) == []


class TestAtomicWriteFailures:
    @pytest.mark.parametrize("err", [errno.ENOSPC, errno.EDQUOT, errno.EFBIG])
    def test_disk_full_during_write_keeps_old_file(self, target, monkeypatch, err):
        monkeypatch.setattr(fsutil.os, "write", fail_with(err))
        with pytest.raises(StorageError, match="not enough disk space") as info:
            fsutil.atomic_write(target, NEW)
        assert info.value.exit_code == ExitCode.STORAGE
        assert "previous version is unchanged" in str(info.value)
        assert target.read_bytes() == OLD
        assert leftovers(target.parent) == []

    def test_disk_full_after_partial_write(self, target, monkeypatch):
        real_write = os.write
        calls = {"n": 0}

        def write(fd, buf):
            calls["n"] += 1
            if calls["n"] > 1:
                raise OSError(errno.ENOSPC, "full")
            return real_write(fd, bytes(buf[:2]))

        monkeypatch.setattr(fsutil.os, "write", write)
        with pytest.raises(StorageError):
            fsutil.atomic_write(target, NEW)
        assert target.read_bytes() == OLD
        assert leftovers(target.parent) == []

    def test_enospc_on_fsync(self, target, monkeypatch):
        monkeypatch.setattr(fsutil.os, "fsync", fail_with(errno.ENOSPC))
        with pytest.raises(StorageError, match="not enough disk space"):
            fsutil.atomic_write(target, NEW)
        assert target.read_bytes() == OLD
        assert leftovers(target.parent) == []

    def test_eio_on_fsync(self, target, monkeypatch):
        monkeypatch.setattr(fsutil.os, "fsync", fail_with(errno.EIO))
        with pytest.raises(StorageError, match="I/O error"):
            fsutil.atomic_write(target, NEW)
        assert target.read_bytes() == OLD

    def test_cannot_create_temp_file(self, target, monkeypatch):
        monkeypatch.setattr(fsutil.tempfile, "mkstemp", fail_with(errno.ENOSPC))
        with pytest.raises(StorageError, match="not enough disk space"):
            fsutil.atomic_write(target, NEW)
        assert target.read_bytes() == OLD

    @pytest.mark.parametrize("err", [errno.EIO, errno.EXDEV, errno.EBUSY, errno.ENOSPC])
    def test_replace_failure_keeps_old_file(self, target, monkeypatch, err):
        monkeypatch.setattr(Path, "replace", fail_with(err))
        with pytest.raises(StorageError):
            fsutil.atomic_write(target, NEW)
        assert target.read_bytes() == OLD
        assert leftovers(target.parent) == []

    def test_replace_failure_with_backup_keeps_old_file(self, target, monkeypatch):
        real_replace = Path.replace

        def replace(self, other):
            if Path(other) == target:
                raise OSError(errno.EIO, "io")
            return real_replace(self, other)

        monkeypatch.setattr(Path, "replace", replace)
        with pytest.raises(StorageError):
            fsutil.atomic_write(target, NEW, backup=True)
        assert target.read_bytes() == OLD
        assert leftovers(target.parent) == []

    def test_permission_denied_on_directory(self, target):
        target.parent.chmod(0o500)
        try:
            if os.access(target.parent, os.W_OK):
                pytest.skip("running with CAP_DAC_OVERRIDE (root)")
            with pytest.raises(UnsafeEnvironment, match="permission denied"):
                fsutil.atomic_write(target, NEW)
            assert target.read_bytes() == OLD
        finally:
            target.parent.chmod(0o700)

    def test_missing_parent_directory(self, tmp_path):
        with pytest.raises(StorageError, match="does not exist"):
            fsutil.atomic_write(tmp_path / "missing" / "f", NEW)

    def test_symlink_target_is_refused_and_untouched(self, target, tmp_path):
        link = tmp_path / "link"
        link.symlink_to(target)
        with pytest.raises(UnsafeEnvironment, match="symbolic link"):
            fsutil.atomic_write(link, NEW)
        assert link.is_symlink()
        assert target.read_bytes() == OLD
        assert leftovers(tmp_path) == []

    def test_dangling_symlink_target_is_refused(self, tmp_path):
        link = tmp_path / "link"
        link.symlink_to(tmp_path / "elsewhere")
        with pytest.raises(UnsafeEnvironment):
            fsutil.atomic_write(link, NEW)
        assert not (tmp_path / "elsewhere").exists()

    def test_error_message_uses_label_not_path(self, target, monkeypatch):
        monkeypatch.setattr(fsutil.os, "write", fail_with(errno.ENOSPC))
        with pytest.raises(StorageError) as info:
            fsutil.atomic_write(target, NEW, what="the persona store")
        assert "the persona store" in str(info.value)
        assert str(target.parent) not in str(info.value)
        assert target.name not in str(info.value)

    def test_new_data_never_appears_in_error_message(self, target, monkeypatch):
        monkeypatch.setattr(fsutil.os, "write", fail_with(errno.EIO))
        with pytest.raises(StorageError) as info:
            fsutil.atomic_write(target, b"Jane Doe secret")
        assert "Jane" not in str(info.value)
        assert "Jane" not in repr(info.value)


class TestAtomicWriteBackup:
    def bak(self, target: Path) -> Path:
        return target.with_name(target.name + ".bak")

    def test_backup_holds_previous_contents(self, target):
        fsutil.atomic_write(target, NEW, backup=True)
        assert target.read_bytes() == NEW
        assert self.bak(target).read_bytes() == OLD
        assert mode(self.bak(target)) == 0o600

    def test_backup_is_replaced_on_each_write(self, target):
        fsutil.atomic_write(target, b"v2", backup=True)
        fsutil.atomic_write(target, b"v3", backup=True)
        assert target.read_bytes() == b"v3"
        assert self.bak(target).read_bytes() == b"v2"

    def test_no_backup_for_a_new_file(self, tmp_path):
        f = tmp_path / "f"
        fsutil.atomic_write(f, NEW, backup=True)
        assert not self.bak(f).exists()

    def test_backup_off_by_default(self, target):
        fsutil.atomic_write(target, NEW)
        assert not self.bak(target).exists()

    def test_hard_link_backup_is_the_old_inode(self, target):
        old_inode = target.stat().st_ino
        fsutil.atomic_write(target, NEW, backup=True)
        assert self.bak(target).stat().st_ino == old_inode
        assert self.bak(target).stat().st_nlink == 1

    def test_copy_fallback_when_hard_links_are_unsupported(self, target, monkeypatch):
        monkeypatch.setattr(fsutil.os, "link", fail_with(errno.EPERM))
        fsutil.atomic_write(target, NEW, backup=True)
        assert target.read_bytes() == NEW
        assert self.bak(target).read_bytes() == OLD
        assert mode(self.bak(target)) == 0o600
        assert leftovers(target.parent) == []

    def test_stale_backup_staging_file_is_replaced(self, target):
        staging = target.with_name(f".{target.name}.bak-staging")
        staging.write_bytes(b"stale")
        fsutil.atomic_write(target, NEW, backup=True)
        assert self.bak(target).read_bytes() == OLD
        assert not staging.exists()

    def test_symlinked_backup_path_is_not_followed(self, target, tmp_path):
        victim = tmp_path / "victim"
        victim.write_bytes(b"victim")
        self.bak(target).symlink_to(victim)
        fsutil.atomic_write(target, NEW, backup=True)
        assert victim.read_bytes() == b"victim"
        assert not self.bak(target).is_symlink()
        assert self.bak(target).read_bytes() == OLD


class TestRemoveStaleTemps:
    def test_removes_only_this_files_temps(self, target):
        mine = target.with_name(f".{target.name}.abc123.tmp")
        other = target.with_name(".other.bin.abc123.tmp")
        mine.write_bytes(b"x")
        other.write_bytes(b"x")
        assert fsutil.remove_stale_temps(target) == 1
        assert not mine.exists()
        assert other.exists()

    def test_nothing_to_remove(self, target):
        assert fsutil.remove_stale_temps(target) == 0

    def test_glob_metacharacters_in_name(self, tmp_path):
        f = tmp_path / "a[1]*?.bin"
        temp = tmp_path / ".a[1]*?.bin.xyz.tmp"
        decoy = tmp_path / ".a1zz.bin.xyz.tmp"
        temp.write_bytes(b"x")
        decoy.write_bytes(b"x")
        assert fsutil.remove_stale_temps(f) == 1
        assert decoy.exists()

    def test_symlinked_temp_is_skipped_and_target_untouched(self, target, tmp_path):
        victim = tmp_path / "victim"
        victim.write_bytes(b"victim")
        target.with_name(f".{target.name}.evil.tmp").symlink_to(victim)
        assert fsutil.remove_stale_temps(target) == 0
        assert victim.read_bytes() == b"victim"


# ── secure_remove ─────────────────────────────────────────────────────────────


class TestSecureRemove:
    def test_removes_file(self, target):
        assert fsutil.secure_remove(target) is True
        assert not target.exists()

    def test_missing_file_returns_false(self, tmp_path):
        assert fsutil.secure_remove(tmp_path / "missing") is False

    def test_contents_are_overwritten_before_unlink(self, target, monkeypatch):
        seen: list[bytes] = []
        real_unlink = Path.unlink

        def unlink(self, missing_ok=False):
            seen.append(self.read_bytes())
            real_unlink(self, missing_ok=missing_ok)

        monkeypatch.setattr(Path, "unlink", unlink)
        fsutil.secure_remove(target)
        assert seen == [bytes(len(OLD))]

    def test_other_hard_link_keeps_its_data(self, target, tmp_path):
        # Overwriting would destroy the other name's data too (the store and its .bak share an
        # inode): a hard-linked file is only unlinked (sweep 2026-10-26).
        other = tmp_path / "other"
        os.link(target, other)
        fsutil.secure_remove(target)
        assert other.read_bytes() == OLD
        assert not target.exists()

    def test_overwrite_is_visible_through_an_open_descriptor(self, target):
        fd = os.open(target, os.O_RDONLY)
        try:
            fsutil.secure_remove(target)
            assert os.pread(fd, len(OLD), 0) == bytes(len(OLD))
        finally:
            os.close(fd)

    def test_large_file(self, tmp_path):
        f = tmp_path / "big"
        f.write_bytes(os.urandom(fsutil._CHUNK + 3))
        fd = os.open(f, os.O_RDONLY)
        try:
            fsutil.secure_remove(f)
            assert os.pread(fd, fsutil._CHUNK + 3, 0) == bytes(fsutil._CHUNK + 3)
        finally:
            os.close(fd)

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        assert fsutil.secure_remove(f) is True

    def test_symlink_is_unlinked_not_followed(self, target, tmp_path):
        link = tmp_path / "link"
        link.symlink_to(target)
        assert fsutil.secure_remove(link) is True
        assert not link.is_symlink()
        assert target.read_bytes() == OLD

    def test_directory_is_refused(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        with pytest.raises(UnsafeEnvironment, match="directory"):
            fsutil.secure_remove(d)
        assert d.is_dir()

    def test_overwrite_failure_is_reported_and_file_kept(self, target, monkeypatch):
        monkeypatch.setattr(fsutil.os, "write", fail_with(errno.EIO))
        with pytest.raises(StorageError):
            fsutil.secure_remove(target)
        assert target.exists()


# ── flock_exclusive ───────────────────────────────────────────────────────────


class TestFlock:
    def test_lock_and_release(self, tmp_path):
        lock = tmp_path / "veil.lock"
        with fsutil.flock_exclusive(lock):
            assert lock.exists()
            assert mode(lock) == 0o600
        with fsutil.flock_exclusive(lock):
            pass

    def test_lock_file_is_kept_after_release(self, tmp_path):
        lock = tmp_path / "veil.lock"
        with fsutil.flock_exclusive(lock):
            pass
        assert lock.exists()

    def test_second_holder_in_same_process_gets_busy(self, tmp_path):
        lock = tmp_path / "veil.lock"
        with (
            fsutil.flock_exclusive(lock),
            pytest.raises(Busy, match="in use") as info,
            fsutil.flock_exclusive(lock),
        ):
            pass
        assert info.value.exit_code == ExitCode.BUSY

    def test_other_process_gets_busy_then_succeeds_after_release(self, tmp_path):
        lock = tmp_path / "veil.lock"
        script = textwrap.dedent(f"""
            from pathlib import Path
            from veil import fsutil
            from veil.errors import Busy
            try:
                with fsutil.flock_exclusive(Path({str(lock)!r})):
                    print("locked")
            except Busy:
                print("busy")
        """)

        def other() -> str:
            run = subprocess.run(
                [sys.executable, "-c", script], capture_output=True, text=True, check=True
            )
            return run.stdout.strip()

        with fsutil.flock_exclusive(lock):
            assert other() == "busy"
        assert other() == "locked"

    def test_released_on_exception(self, tmp_path):
        lock = tmp_path / "veil.lock"
        with pytest.raises(RuntimeError), fsutil.flock_exclusive(lock):
            raise RuntimeError
        with fsutil.flock_exclusive(lock):
            pass

    def test_symlinked_lock_is_refused(self, tmp_path):
        victim = tmp_path / "victim"
        victim.write_bytes(b"keep")
        lock = tmp_path / "veil.lock"
        lock.symlink_to(victim)
        with pytest.raises(UnsafeEnvironment, match="symbolic link"), fsutil.flock_exclusive(lock):
            pass
        assert victim.read_bytes() == b"keep"

    def test_directory_as_lock_is_refused(self, tmp_path):
        with pytest.raises(VeilError), fsutil.flock_exclusive(tmp_path):
            pass

    def test_foreign_owned_lock_is_refused(self, tmp_path, monkeypatch):
        lock = tmp_path / "veil.lock"
        lock.write_bytes(b"")
        monkeypatch.setattr(fsutil.os, "getuid", lambda: lock.stat().st_uid + 1)
        with (
            pytest.raises(UnsafeEnvironment, match="not owned by you"),
            fsutil.flock_exclusive(lock),
        ):
            pass

    def test_busy_message_uses_label(self, tmp_path):
        lock = tmp_path / "veil.lock"
        with (
            fsutil.flock_exclusive(lock, what="the persona store"),
            pytest.raises(Busy) as info,
            fsutil.flock_exclusive(lock, what="the persona store"),
        ):
            pass
        assert "the persona store" in str(info.value)
        assert str(tmp_path) not in str(info.value)


# ── error mapping ─────────────────────────────────────────────────────────────


class TestErrorMapping:
    @pytest.mark.parametrize(
        ("err", "cls", "code"),
        [
            (errno.ENOSPC, StorageError, ExitCode.STORAGE),
            (errno.EDQUOT, StorageError, ExitCode.STORAGE),
            (errno.EIO, StorageError, ExitCode.STORAGE),
            (errno.EROFS, StorageError, ExitCode.STORAGE),
            (errno.ENOENT, StorageError, ExitCode.STORAGE),
            (errno.EACCES, UnsafeEnvironment, ExitCode.UNSAFE_ENVIRONMENT),
            (errno.EPERM, UnsafeEnvironment, ExitCode.UNSAFE_ENVIRONMENT),
        ],
    )
    def test_errno_to_exit_code(self, err, cls, code):
        exc = fsutil._storage_error(OSError(err, "msg", "/home/someone/secret"), "the store")
        assert type(exc) is cls
        assert exc.exit_code == code
        assert "secret" not in str(exc)
        assert "someone" not in str(exc)

    def test_os_error_text_is_never_copied(self):
        exc = fsutil._storage_error(OSError(errno.EIO, "Jane Doe leaked"), "the store")
        assert "Jane" not in str(exc)


# ── hard links: the live store and its .bak share an inode (sweep 2026-10-26) ─


def test_stale_staging_link_never_zeroes_the_live_file(tmp_path):
    live = tmp_path / "store.bin"
    live.write_bytes(b"precious encrypted bytes")
    live.chmod(0o600)
    # What an older veil (or a crash between link and rename) left behind: a hard link of the
    # live file whose name matches the stale-temp pattern.
    os.link(live, tmp_path / ".store.bin.bak.tmp")
    fsutil.remove_stale_temps(live)
    assert live.read_bytes() == b"precious encrypted bytes"
    assert not (tmp_path / ".store.bin.bak.tmp").exists()


def test_secure_remove_only_unlinks_a_hard_linked_file(tmp_path):
    first = tmp_path / "a"
    first.write_bytes(b"data")
    os.link(first, tmp_path / "b")
    assert fsutil.secure_remove(tmp_path / "b")
    assert first.read_bytes() == b"data"
    assert fsutil.secure_remove(first)  # now the only link: overwritten, then removed
    assert not first.exists()


def test_hard_linked(tmp_path):
    first = tmp_path / "a"
    first.write_bytes(b"x")
    assert not fsutil.hard_linked(first)
    os.link(first, tmp_path / "b")
    assert fsutil.hard_linked(first)


def test_backup_staging_name_is_not_a_stale_temp(tmp_path):
    live = tmp_path / "store.bin"
    fsutil.atomic_write(live, b"v1")
    fsutil.atomic_write(live, b"v2", backup=True)
    assert (tmp_path / "store.bin.bak").read_bytes() == b"v1"
    assert not list(tmp_path.glob(".store.bin.*.tmp"))
    assert not list(tmp_path.glob(".store.bin.bak*"))


def test_failed_backup_rename_leaves_no_staging_link(tmp_path):
    live = tmp_path / "store.bin"
    fsutil.atomic_write(live, b"v1")
    (tmp_path / "store.bin.bak").mkdir()  # the rename onto it fails
    with pytest.raises(VeilError):
        fsutil.atomic_write(live, b"v2", backup=True)
    assert live.read_bytes() == b"v1"
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".")] == []


def test_failed_directory_flush_after_rename_says_so(tmp_path, monkeypatch):
    target = tmp_path / "file.bin"
    target.write_bytes(b"old")

    def broken(path):
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(fsutil, "fsync_dir", broken)
    with pytest.raises(StorageError) as info:
        fsutil.atomic_write(target, b"new")
    assert target.read_bytes() == b"new"  # the rename happened
    assert "unchanged" not in info.value.safe_message
    assert "was written" in info.value.safe_message
