"""macOS RAM-disk runtime directory (ramdisk.py)."""

import os
import plistlib
import pwd
import sys
from pathlib import Path

import pytest

from veil import ramdisk
from veil.errors import UnsafeEnvironment

real = pytest.mark.skipif(
    sys.platform != "darwin" or os.environ.get("VEIL_TEST_RAMDISK") != "1",
    reason="set VEIL_TEST_RAMDISK=1 on macOS to create the real RAM disk",
)


def info_plist(path: str, dev: str) -> str:
    return plistlib.dumps(
        {"images": [{"image-path": path, "system-entities": [{"dev-entry": dev}]}]}
    ).decode()


class FakeTools:
    """Answers mount / hdiutil info / diskutil like macOS would, and records every call."""

    def __init__(self, point, *, image="ram://32768", mounted=False):
        self.point, self.image, self.mounted, self.calls = str(point), image, mounted, []

    def __call__(self, argv):
        self.calls.append(list(argv))
        if argv[0] == ramdisk.MOUNT:
            return f"/dev/disk9 on {self.point} (hfs, local)\n" if self.mounted else ""
        if argv[0] == ramdisk.HDIUTIL:
            return info_plist(self.image, "/dev/disk9")
        if argv[:3] == [ramdisk.DISKUTIL, "image", "attach"]:
            return "/dev/disk9\n"
        if argv[:2] == [ramdisk.DISKUTIL, "mount"]:
            self.mounted = True
        return ""


@pytest.fixture
def temp_dir(tmp_path, monkeypatch):
    base = tmp_path / "T"
    base.mkdir(mode=0o700)
    monkeypatch.setattr(ramdisk, "user_temp_dir", lambda: base)
    return base


def test_creates_and_verifies(temp_dir):
    tools = FakeTools(temp_dir / "veil-runtime")
    assert ramdisk.ensure(tools) == temp_dir / "veil-runtime"
    tools_run = {Path(c[0]).name if c[0] != ramdisk.DISKUTIL else c[1] for c in tools.calls}
    assert {"image", "newfs_hfs", "mount"} <= tools_run
    mount = next(c for c in tools.calls if c[:2] == [ramdisk.DISKUTIL, "mount"])
    assert ramdisk.MOUNT_OPTIONS in mount
    assert "nobrowse" in ramdisk.MOUNT_OPTIONS


def test_reuses_existing_mount(temp_dir):
    (temp_dir / "veil-runtime").mkdir(mode=0o700)
    tools = FakeTools(temp_dir / "veil-runtime", mounted=True)
    ramdisk.ensure(tools)
    assert not any(c[:3] == [ramdisk.DISKUTIL, "image", "attach"] for c in tools.calls)


def test_refuses_a_disk_backed_image(temp_dir):
    (temp_dir / "veil-runtime").mkdir(mode=0o700)
    tools = FakeTools(temp_dir / "veil-runtime", image="/Users/x/disk.dmg", mounted=True)
    with pytest.raises(UnsafeEnvironment, match="not in memory"):
        ramdisk.ensure(tools)


def test_refuses_open_temp_dir(temp_dir):
    temp_dir.chmod(0o755)
    with pytest.raises(UnsafeEnvironment, match="accessible to other users"):
        ramdisk.ensure(FakeTools(temp_dir / "veil-runtime"))


def test_failed_mount_ejects_the_new_device(temp_dir):
    tools = FakeTools(temp_dir / "veil-runtime")

    def failing(argv):
        if argv[:2] == [ramdisk.DISKUTIL, "mount"]:
            tools.calls.append(list(argv))
            raise UnsafeEnvironment("diskutil failed (exit 1)")
        return tools(argv)

    with pytest.raises(UnsafeEnvironment):
        ramdisk.ensure(failing)
    assert [ramdisk.DISKUTIL, "eject", "/dev/disk9"] in tools.calls


def test_garbage_hdiutil_output_is_not_ram():
    assert ramdisk.is_ram_backed("/dev/disk9", lambda _argv: "not a plist") is False


def test_tests_cannot_reach_the_real_tools():
    with pytest.raises(AssertionError, match="real macOS RAM disk"):
        ramdisk._run([ramdisk.MOUNT])


@real
@pytest.mark.real_ramdisk
def test_real_ramdisk_round_trip(monkeypatch):
    # conftest points HOME at a temp dir; diskutil's image framework needs the real one.
    monkeypatch.setenv("HOME", pwd.getpwuid(os.getuid()).pw_dir)
    point = ramdisk.ensure()
    probe = point / "probe.txt"
    probe.write_text("synthetic", encoding="utf-8")
    assert ramdisk.is_ram_backed(ramdisk.mounted_device(point))
    probe.unlink()
    assert ramdisk.eject() is True
    assert ramdisk.mounted_device(point) is None
