"""paths.py: XDG locations, the tmpfs-only runtime dir, mountinfo parsing and swap risk.

/proc and /sys are never read from the host: every test injects its own text.
"""

import os
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil import paths
from veil.errors import UnsafeEnvironment
from veil.exitcodes import ExitCode


def mountinfo(*mounts: tuple[str, str]) -> str:
    """Build mountinfo text from (mount_point, fstype) pairs, escaping like the kernel does."""
    lines = []
    for i, (point, fstype) in enumerate(mounts, start=20):
        escaped = point.replace("\\", "\\134").replace(" ", "\\040").replace("\t", "\\011")
        lines.append(f"{i} 1 0:{i} / {escaped} rw,nosuid shared:{i} - {fstype} src rw")
    return "\n".join(lines) + "\n"


def reader(files: dict[str, str]):
    def read(path: str) -> str:
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]

    return read


# ── XDG config / data ─────────────────────────────────────────────────────────


class TestXdg:
    def test_config_dir_uses_xdg_config_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        assert paths.config_dir() == tmp_path / "veil"

    def test_data_dir_uses_xdg_data_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert paths.data_dir() == tmp_path / "veil"

    @pytest.mark.parametrize("value", ["", "   ", "relative/dir", "./x", "~/conf"])
    def test_unset_blank_or_relative_values_fall_back_to_home(self, monkeypatch, tmp_path, value):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("XDG_CONFIG_HOME", value)
        monkeypatch.setenv("XDG_DATA_HOME", value)
        assert paths.config_dir() == tmp_path / ".config" / "veil"
        assert paths.data_dir() == tmp_path / ".local" / "share" / "veil"

    def test_missing_variables_fall_back_to_home(self, monkeypatch, tmp_path):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        assert paths.config_dir() == tmp_path / ".config" / "veil"
        assert paths.data_dir() == tmp_path / ".local" / "share" / "veil"

    def test_unicode_home(self, monkeypatch, tmp_path):
        home = tmp_path / "उपयोगकर्ता"
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        assert paths.config_dir() == home / ".config" / "veil"

    def test_config_and_data_never_point_at_the_runtime_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        assert tmp_path not in paths.config_dir().parents
        assert tmp_path not in paths.data_dir().parents


# ── mountinfo ─────────────────────────────────────────────────────────────────


class TestMountinfo:
    def test_parses_mount_point_and_type(self):
        mounts = paths.parse_mountinfo(mountinfo(("/", "btrfs"), ("/run/user/1000", "tmpfs")))
        assert mounts == [paths.Mount("/", "btrfs"), paths.Mount("/run/user/1000", "tmpfs")]

    def test_optional_fields_of_any_length(self):
        line = "30 1 0:5 / /run/user/1000 rw shared:1 master:2 propagate_from:3 - tmpfs tmpfs rw\n"
        assert paths.parse_mountinfo(line) == [paths.Mount("/run/user/1000", "tmpfs")]

    def test_no_optional_fields(self):
        line = "30 1 0:5 / /run/user/1000 rw - tmpfs tmpfs rw\n"
        assert paths.parse_mountinfo(line) == [paths.Mount("/run/user/1000", "tmpfs")]

    @pytest.mark.parametrize(
        "line",
        [
            "",
            "garbage",
            "1 2 3 4 5 6",
            "30 1 0:5 / /x rw shared:1 tmpfs tmpfs rw",
            "1 2 3 4 /x 6 -",
        ],
    )
    def test_malformed_lines_are_skipped(self, line):
        assert paths.parse_mountinfo(line + "\n") == []

    def test_malformed_lines_do_not_hide_good_ones(self):
        text = "garbage\n" + mountinfo(("/run", "tmpfs")) + "1 2 3\n"
        assert paths.parse_mountinfo(text) == [paths.Mount("/run", "tmpfs")]

    @pytest.mark.parametrize(
        "point", ["/mnt/with space", "/mnt/tab\there", "/mnt/back\\slash", "/mnt/मराठी"]
    )
    def test_escaped_mount_points_are_unescaped(self, point):
        assert paths.parse_mountinfo(mountinfo((point, "ext4"))) == [paths.Mount(point, "ext4")]

    @pytest.mark.parametrize("field", ["\\", "\\0", "\\04", "\\9xx", "a\\", "\\08x"])
    def test_incomplete_or_non_octal_escapes_are_kept_literally(self, field):
        assert paths._unescape(field) == field

    @given(st.text(alphabet=st.characters(blacklist_categories=["Cs"]), min_size=1))
    def test_unescape_inverts_kernel_escaping(self, raw):
        point = "/" + raw.replace("\n", "")
        escaped = (
            point.replace("\\", "\\134")
            .replace(" ", "\\040")
            .replace("\t", "\\011")
            .replace("\n", "\\012")
        )
        assert paths._unescape(escaped) == point


class TestFilesystemOf:
    MOUNTS = mountinfo(
        ("/", "btrfs"),
        ("/home", "btrfs"),
        ("/run", "tmpfs"),
        ("/run/user/1000", "tmpfs"),
        ("/run/user/1000/doc", "fuse.portal"),
    )

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/", "btrfs"),
            ("/etc", "btrfs"),
            ("/run/user/1000", "tmpfs"),
            ("/run/user/1000/veil", "tmpfs"),
            ("/run/user/1000/doc/x", "fuse.portal"),
            ("/run/user/10000", "tmpfs"),  # under /run, NOT under /run/user/1000
            ("/run/user/1000/../1000/veil", "tmpfs"),
            ("/home/someone", "btrfs"),
            ("/homework", "btrfs"),  # prefix of a name is not a parent
        ],
    )
    def test_longest_mount_point_prefix_wins(self, path, expected):
        assert paths.filesystem_of(Path(path), self.MOUNTS) == expected

    def test_prefix_without_slash_boundary_does_not_match(self):
        text = mountinfo(("/", "ext4"), ("/run/user/1", "tmpfs"))
        assert paths.filesystem_of(Path("/run/user/1000"), text) == "ext4"

    def test_later_mount_on_the_same_point_wins(self):
        text = mountinfo(("/", "ext4"), ("/run/user/1000", "tmpfs"), ("/run/user/1000", "ext4"))
        assert paths.filesystem_of(Path("/run/user/1000/veil"), text) == "ext4"

    def test_empty_mountinfo_is_unknown(self):
        assert paths.filesystem_of(Path("/run/user/1000"), "") == "unknown"

    def test_trailing_slash_in_path(self):
        assert paths.filesystem_of(Path("/run/user/1000/"), self.MOUNTS) == "tmpfs"


# ── runtime dir ───────────────────────────────────────────────────────────────


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    base = tmp_path / "rtdir-q7"
    base.mkdir(mode=0o700)
    base.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(base))
    return base


def tmpfs_at(path: Path, fstype: str = "tmpfs"):
    return reader({"/proc/self/mountinfo": mountinfo(("/", "ext4"), (str(path), fstype))})


class TestRuntimeDir:
    def test_valid_tmpfs_dir_is_accepted(self, runtime):
        assert paths.runtime_base(tmpfs_at(runtime)) == runtime
        assert paths.runtime_dir(tmpfs_at(runtime)) == runtime / "veil"

    def test_ramfs_is_accepted(self, runtime):
        assert paths.runtime_base(tmpfs_at(runtime, "ramfs")) == runtime

    @pytest.mark.parametrize("fstype", ["ext4", "btrfs", "xfs", "overlay", "nfs", "fuse.sshfs"])
    def test_disk_backed_filesystem_is_refused(self, runtime, fstype):
        with pytest.raises(UnsafeEnvironment, match="not in memory") as info:
            paths.runtime_base(tmpfs_at(runtime, fstype))
        assert info.value.exit_code == ExitCode.UNSAFE_ENVIRONMENT

    def test_unknown_filesystem_is_refused(self, runtime):
        with pytest.raises(UnsafeEnvironment, match="not in memory"):
            paths.runtime_base(reader({"/proc/self/mountinfo": ""}))

    @pytest.mark.parametrize("mode", [0o755, 0o750, 0o701, 0o710, 0o777, 0o705])
    def test_group_or_other_access_is_refused(self, runtime, mode):
        runtime.chmod(mode)
        with pytest.raises(UnsafeEnvironment, match="other users"):
            paths.runtime_base(tmpfs_at(runtime))

    def test_mode_is_not_silently_changed(self, runtime):
        runtime.chmod(0o755)
        with pytest.raises(UnsafeEnvironment):
            paths.runtime_base(tmpfs_at(runtime))
        assert runtime.stat().st_mode & 0o777 == 0o755

    def test_symlink_is_refused(self, runtime, tmp_path, monkeypatch):
        link = tmp_path / "link"
        link.symlink_to(runtime)
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(link))
        with pytest.raises(UnsafeEnvironment, match="not a real directory"):
            paths.runtime_base(tmpfs_at(link))

    def test_symlinked_parent_onto_disk_is_refused(self, tmp_path, monkeypatch):
        # <tmpfs>/link/rt where link → a disk folder: lexically under the tmpfs mount, really on
        # disk. The mount check resolves the path first (sweep 2026-10-26).
        memory, disk = tmp_path / "memory", tmp_path / "disk"
        memory.mkdir()
        (disk / "rt").mkdir(parents=True, mode=0o700)
        (disk / "rt").chmod(0o700)
        (memory / "link").symlink_to(disk)
        runtime = memory / "link" / "rt"
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime))
        with pytest.raises(UnsafeEnvironment, match="not in memory"):
            paths.runtime_base(tmpfs_at(memory))

    def test_regular_file_is_refused(self, tmp_path, monkeypatch):
        f = tmp_path / "file"
        f.write_bytes(b"")
        f.chmod(0o600)
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(f))
        with pytest.raises(UnsafeEnvironment, match="not a real directory"):
            paths.runtime_base(tmpfs_at(f))

    def test_missing_dir_is_refused_without_fallback(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "missing"))
        with pytest.raises(UnsafeEnvironment, match="no runtime directory"):
            paths.runtime_base(tmpfs_at(tmp_path / "missing"))

    def test_foreign_owner_is_refused(self, runtime, monkeypatch):
        monkeypatch.setattr(paths.os, "getuid", lambda: runtime.stat().st_uid + 1)
        with pytest.raises(UnsafeEnvironment, match="not owned by you"):
            paths.runtime_base(tmpfs_at(runtime))

    @pytest.mark.parametrize("value", ["", "  ", "relative/run"])
    def test_unset_or_relative_variable_falls_back_to_run_user(self, monkeypatch, value):
        monkeypatch.setenv("XDG_RUNTIME_DIR", value)
        seen: list[Path] = []

        def fake_lstat(self):
            seen.append(self)
            raise FileNotFoundError

        monkeypatch.setattr(Path, "lstat", fake_lstat)
        with pytest.raises(UnsafeEnvironment):
            paths.runtime_base(reader({}))
        assert seen == [Path(f"/run/user/{os.getuid()}")]

    def test_never_falls_back_to_tmp_or_dev_shm(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "missing"))
        try:
            result = paths.runtime_base(tmpfs_at(tmp_path / "missing"))
        except UnsafeEnvironment:
            return
        pytest.fail(f"unexpected fallback to {result}")

    def test_error_messages_do_not_contain_the_path(self, runtime):
        runtime.chmod(0o755)
        with pytest.raises(UnsafeEnvironment) as info:
            paths.runtime_base(tmpfs_at(runtime))
        assert str(runtime) not in str(info.value)
        assert runtime.name not in str(info.value)


# ── swap ──────────────────────────────────────────────────────────────────────

HEADER = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"


def swaps(*devices: str) -> str:
    return HEADER + "".join(f"{d}  partition\t8388604\t0\t-2\n" for d in devices)


class TestSwap:
    def test_no_swap(self):
        status = paths.swap_status(reader({"/proc/swaps": HEADER}))
        assert status == paths.SwapStatus(active=0, unprotected=0)
        assert not status.at_risk

    def test_unreadable_proc_swaps_reports_nothing(self):
        assert paths.swap_status(reader({})) == paths.SwapStatus(0, 0)

    def test_empty_file(self):
        assert paths.swap_status(reader({"/proc/swaps": ""})) == paths.SwapStatus(0, 0)

    @pytest.mark.parametrize("device", ["/dev/nvme0n1p6", "/dev/sda2", "/swapfile", "/var/swap"])
    def test_plain_partition_or_file_is_at_risk(self, device):
        status = paths.swap_status(reader({"/proc/swaps": swaps(device)}))
        assert status == paths.SwapStatus(active=1, unprotected=1)
        assert status.at_risk

    @pytest.mark.parametrize("device", ["/dev/zram0", "/dev/zram12"])
    def test_zram_is_safe(self, device):
        status = paths.swap_status(reader({"/proc/swaps": swaps(device)}))
        assert status == paths.SwapStatus(active=1, unprotected=0)
        assert not status.at_risk

    def test_dm_crypt_is_safe(self):
        files = {"/proc/swaps": swaps("/dev/dm-1"), "/sys/block/dm-1/dm/uuid": "CRYPT-PLAIN-swap\n"}
        assert not paths.swap_status(reader(files)).at_risk

    @pytest.mark.parametrize("uuid", ["LVM-abc123", "", "crypt-lowercase", "XCRYPT-"])
    def test_non_crypt_device_mapper_is_at_risk(self, uuid):
        files = {"/proc/swaps": swaps("/dev/dm-0"), "/sys/block/dm-0/dm/uuid": uuid}
        assert paths.swap_status(reader(files)).at_risk

    def test_dm_without_sysfs_info_is_at_risk(self):
        assert paths.swap_status(reader({"/proc/swaps": swaps("/dev/dm-3")})).at_risk

    def test_unresolvable_mapper_device_is_at_risk(self):
        device = "/dev/mapper/veil-test-does-not-exist"
        assert paths.swap_status(reader({"/proc/swaps": swaps(device)})).at_risk

    def test_mixed_devices_are_counted_separately(self):
        files = {
            "/proc/swaps": swaps("/dev/zram0", "/dev/dm-2", "/dev/sda3", "/swapfile"),
            "/sys/block/dm-2/dm/uuid": "CRYPT-LUKS2-0123-swap",
        }
        assert paths.swap_status(reader(files)) == paths.SwapStatus(active=4, unprotected=2)

    def test_blank_lines_are_ignored(self):
        text = HEADER + "\n\n" + "/dev/zram0 partition 1 0 100\n\n"
        assert paths.swap_status(reader({"/proc/swaps": text})) == paths.SwapStatus(1, 0)

    def test_escaped_swapfile_name(self):
        text = HEADER + "/var/my\\040swap file 1 0 -2\n"
        assert paths.swap_status(reader({"/proc/swaps": text})) == paths.SwapStatus(1, 1)
