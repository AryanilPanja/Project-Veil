"""`veil install-shortcuts` (M3.3): KDE Plasma 6 hotkeys, the System Settings way.

Never the owner's real shortcuts: conftest's `shortcut_service` replaces the D-Bus client and
kbuildsycoca6 for every test; the jeepney client is tested against a fake service on a private
dbus-daemon. Desktop files go to the per-test XDG sandbox.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tests.helpers import privatebus
from tests.unit.test_killswitch import cmd
from veil import killswitch, shortcuts
from veil.clip import messages
from veil.clip.commands import Action, Outcome, Skip
from veil.exitcodes import ExitCode
from veil.killswitch import Switch, utc_now
from veil.shortcuts import (
    SHORTCUTS,
    TOGGLE,
    Result,
    applications_dir,
    desktop_entry,
    exec_value,
    install,
    installed,
    key_code,
    manual_steps,
    remove,
)
from veil.shortcuts import JeepneyShortcuts as RealJeepneyShortcuts  # bound before conftest
from veil.shortcuts import kbuildsycoca as real_kbuildsycoca

COMMAND = ["/venv/bin/python", "-m", "veil"]
META_ALT = 0x10000000 | 0x08000000


def rebuild_counter():
    calls = []
    return calls, lambda: calls.append(1) or True


# ── keys ──────────────────────────────────────────────────────────────────────


class TestKeyCode:
    @pytest.mark.parametrize(
        ("keys", "code"),
        [
            ("Meta+Alt+V", META_ALT | 0x56),
            ("Meta+Alt+K", META_ALT | 0x4B),
            ("Meta+Alt+c", META_ALT | 0x43),
            ("Ctrl+Shift+1", 0x04000000 | 0x02000000 | 0x31),
            ("V", 0x56),
        ],
    )
    def test_codes(self, keys, code):
        assert key_code(keys) == code

    @pytest.mark.parametrize("keys", ["Meta+Alt+F1", "Meta+Alt+", "Meta+Alt+é", "Hyper+V"])
    def test_unsupported(self, keys):
        with pytest.raises((ValueError, KeyError)):
            key_code(keys)

    def test_veil_keys_are_distinct(self):
        assert len({key_code(s.keys) for s in SHORTCUTS}) == len(SHORTCUTS)
        assert {s.keys for s in SHORTCUTS} == {
            "Meta+Alt+V",
            "Meta+Alt+C",
            "Meta+Alt+E",
            "Meta+Alt+K",
        }


# ── desktop files ─────────────────────────────────────────────────────────────


def parse_exec(value: str) -> list[str]:
    """The Desktop Entry spec's reading of an Exec value (string escapes, quoting, %%)."""
    unescaped = []
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value):
            unescaped.append(
                {"s": " ", "n": "\n", "t": "\t", "r": "\r"}.get(value[i + 1], value[i + 1])
            )
            i += 2
        else:
            unescaped.append(value[i])
            i += 1
    text = "".join(unescaped)
    args, current, quoted, started, i = [], [], False, False, 0
    while i < len(text):
        c = text[i]
        if quoted:
            if c == "\\" and i + 1 < len(text) and text[i + 1] in '"`$\\':
                current.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                quoted = False
            else:
                current.append(c)
        elif c == '"':
            quoted = started = True
        elif c == " ":
            if started:
                args.append("".join(current))
            current, started = [], False
        else:
            current.append(c)
            started = True
        i += 1
    if started:
        args.append("".join(current))
    return [a.replace("%%", "%") for a in args]


class TestExec:
    @pytest.mark.parametrize(
        ("argv", "value"),
        [
            (["/usr/bin/python", "-m", "veil"], "/usr/bin/python -m veil"),
            (["/a b/python"], '"/a b/python"'),
            (['say"hi'], '"say\\\\"hi"'),
            (["a\\b"], '"a\\\\\\\\b"'),  # a literal backslash: four in the file
            (["$HOME"], '"\\\\$HOME"'),
            (["50%"], "50%%"),
            ([""], '""'),
            (["--from-hotkey"], "--from-hotkey"),
        ],
    )
    def test_values(self, argv, value):
        assert exec_value(argv) == value

    @pytest.mark.parametrize("arg", ["a\nb", "a\tb", "\x00", "x\x7f"])
    def test_control_characters_refused(self, arg):
        with pytest.raises(ValueError):  # noqa: PT011
            exec_value([arg])

    @given(
        st.lists(
            st.text(st.characters(min_codepoint=0x20, blacklist_characters="\x7f")),
            min_size=1,
            max_size=5,
        )
    )
    def test_property_round_trip(self, argv):
        assert parse_exec(exec_value(argv)) == argv

    def test_entry(self):
        assert desktop_entry(TOGGLE, COMMAND) == (
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=veil: kill switch (asks before switching off)\n"
            "Exec=/venv/bin/python -m veil toggle --from-hotkey\n"
            "Icon=security-high\n"
            "NoDisplay=true\n"
            "StartupNotify=false\n"
            "X-KDE-GlobalAccel-CommandShortcut=true\n"
            "X-Veil-Keys=Meta+Alt+K\n"
        )

    def test_component_names(self):
        assert [s.component for s in SHORTCUTS] == [
            "net.local.veil-sanitize.desktop",
            "net.local.veil-from-selection.desktop",
            "net.local.veil-restore.desktop",
            "net.local.veil-toggle.desktop",
        ]

    def test_hotkey_commands(self):
        # The kill-switch hotkey always confirms by notification (ADR-0018 amendment 2).
        assert TOGGLE.args == ("toggle", "--from-hotkey")
        assert {s.args for s in SHORTCUTS} >= {("clip", "sanitize"), ("clip", "restore")}

    def test_veil_command_is_this_interpreter(self):
        import sys

        assert shortcuts.veil_command() == [sys.executable, "-m", "veil"]


# ── install / remove ──────────────────────────────────────────────────────────


class TestInstall:
    def test_all_installed(self, shortcut_service):
        calls, rebuild = rebuild_counter()
        reports = install(shortcut_service, rebuild, COMMAND)
        assert [r.result for r in reports] == [Result.INSTALLED] * 4
        for shortcut in SHORTCUTS:
            path = applications_dir() / shortcut.component
            assert path.read_text(encoding="utf-8") == desktop_entry(shortcut, COMMAND)
            assert path.stat().st_mode & 0o777 == 0o644
            assert shortcut_service.keys_by_component[shortcut.component] == [
                key_code(shortcut.keys)
            ]
        assert shortcut_service.registered == [s.component for s in SHORTCUTS]
        assert len(calls) == 1
        assert installed()

    def test_taken_key_is_left_alone(self, shortcut_service):
        shortcut_service.taken[key_code("Meta+Alt+K")] = "org.kde.spectacle.desktop"
        reports = install(shortcut_service, lambda: True, COMMAND)
        result = {r.shortcut.name: r.result for r in reports}
        assert result["toggle"] is Result.TAKEN
        assert result["sanitize"] is Result.INSTALLED
        assert not (applications_dir() / TOGGLE.component).exists()
        assert TOGGLE.component not in shortcut_service.keys_by_component
        assert not installed()

    def test_own_key_is_not_taken(self, shortcut_service):
        install(shortcut_service, lambda: True, COMMAND)
        for shortcut in SHORTCUTS:
            shortcut_service.taken[key_code(shortcut.keys)] = shortcut.component
        reports = install(shortcut_service, lambda: True, COMMAND)  # re-install
        assert all(r.result is Result.INSTALLED for r in reports)

    @pytest.mark.parametrize("step", ["available", "register", "set_keys", "keys"])
    def test_failures_are_per_shortcut(self, shortcut_service, step):
        shortcut_service.fail = {step}
        calls, rebuild = rebuild_counter()
        reports = install(shortcut_service, rebuild, COMMAND)
        assert all(r.result is Result.FAILED for r in reports)
        assert not any(applications_dir().glob("net.local.veil-*.desktop"))
        assert len(calls) == 2  # once after writing, once after removing the failures

    def test_keys_not_confirmed_is_failed(self, shortcut_service, monkeypatch):
        monkeypatch.setattr(shortcut_service, "keys", lambda shortcut: [])
        assert all(
            r.result is Result.FAILED for r in install(shortcut_service, lambda: True, COMMAND)
        )

    def test_other_desktop_files_are_untouched(self, shortcut_service):
        folder = applications_dir()
        folder.mkdir(parents=True)
        other = folder / "org.example.app.desktop"
        other.write_text("[Desktop Entry]\n")
        folder.chmod(0o755)
        install(shortcut_service, lambda: True, COMMAND)
        remove(shortcut_service, lambda: True)
        assert other.read_text() == "[Desktop Entry]\n"
        assert folder.stat().st_mode & 0o777 == 0o755  # a shared folder: modes left alone

    def test_remove(self, shortcut_service):
        install(shortcut_service, lambda: True, COMMAND)
        calls, rebuild = rebuild_counter()
        reports = remove(shortcut_service, rebuild)
        assert all(r.result is Result.REMOVED for r in reports)
        assert shortcut_service.keys_by_component == {}
        assert not any(applications_dir().glob("net.local.veil-*.desktop"))
        assert len(calls) == 1

    def test_remove_without_service_or_files(self, shortcut_service):
        shortcut_service.fail = {"forget"}
        assert all(r.result is Result.REMOVED for r in remove(shortcut_service, lambda: True))
        assert all(r.result is Result.REMOVED for r in remove(None, lambda: True))

    def test_manual_steps(self):
        lines = manual_steps(COMMAND)
        assert lines[0].startswith("System Settings → Keyboard → Shortcuts → Add New")
        assert "  Meta+Alt+K  /venv/bin/python -m veil toggle --from-hotkey" in lines


class TestKbuildsycoca:
    def test_missing(self):
        assert real_kbuildsycoca(lambda name: None)() is False

    def test_runs_the_tool(self, tmp_path):
        tool = tmp_path / "kbuildsycoca6"
        tool.write_text("#!/bin/sh\nexit 0\n")
        tool.chmod(0o700)
        assert real_kbuildsycoca(lambda name: str(tool))() is True
        tool.write_text("#!/bin/sh\nexit 3\n")
        assert real_kbuildsycoca(lambda name: str(tool))() is False

    def test_unrunnable(self, tmp_path):
        assert real_kbuildsycoca(lambda name: str(tmp_path / "gone"))() is False


# ── the hotkey in kill-switch messages ────────────────────────────────────────


class TestSwitchBack:
    def test_without_shortcut(self):
        assert killswitch.switch_back() == "Run `veil on` to switch back."
        body = messages.notification(Outcome(Action.SANITIZE, Skip.OFF)).body
        assert "Meta+Alt" not in body

    def test_with_shortcut(self, shortcut_service):
        install(shortcut_service, lambda: True, COMMAND)
        assert killswitch.switch_back() == "Run `veil on` or press Meta+Alt+K to switch back."
        now = utc_now()
        assert "Meta+Alt+K" in killswitch.off_message(Switch(True, now), now).body
        assert "Meta+Alt+K" in messages.notification(Outcome(Action.SANITIZE, Skip.OFF)).body


# ── CLI ───────────────────────────────────────────────────────────────────────


@pytest.fixture
def session_bus(monkeypatch):
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent-test-bus")


class TestCli:
    def test_print_changes_nothing(self, capsys, shortcut_service):
        code, out, _ = cmd(capsys, "install-shortcuts", "--print")
        assert code == ExitCode.OK
        assert "Meta+Alt+V" in out
        assert "clip sanitize" in out
        assert shortcut_service.registered == []
        assert not applications_dir().exists()

    @pytest.mark.usefixtures("session_bus")
    def test_install(self, capsys, shortcut_service):
        code, out, err = cmd(capsys, "install-shortcuts")
        assert code == ExitCode.OK
        assert out.count("installed") == 4
        assert err == ""
        assert installed()
        assert shortcut_service.closed == 1

    @pytest.mark.usefixtures("session_bus")
    def test_some_taken(self, capsys, shortcut_service):
        shortcut_service.taken[key_code("Meta+Alt+V")] = "org.kde.konsole.desktop"
        code, out, err = cmd(capsys, "install-shortcuts")
        assert code == ExitCode.FINDINGS
        assert "key already in use" in out
        assert "1 hotkey(s) not set up" in err

    @pytest.mark.usefixtures("session_bus")
    def test_service_not_running(self, capsys, shortcut_service):
        shortcut_service.is_running = False
        code, _, err = cmd(capsys, "install-shortcuts")
        assert code == ExitCode.UNSAFE_ENVIRONMENT
        assert "isn't running" in err
        assert "Add New → Command" in err
        assert not applications_dir().exists()

    def test_no_session_bus(self, capsys, monkeypatch, shortcut_service):
        monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
        code, _, _ = cmd(capsys, "install-shortcuts")
        assert code == ExitCode.UNSAFE_ENVIRONMENT
        assert shortcut_service.registered == []

    @pytest.mark.usefixtures("session_bus")
    def test_running_check_crash_is_not_running(self, capsys, shortcut_service):
        shortcut_service.fail = {"running"}
        assert cmd(capsys, "install-shortcuts")[0] == ExitCode.UNSAFE_ENVIRONMENT

    @pytest.mark.usefixtures("session_bus")
    def test_remove(self, capsys, shortcut_service):
        cmd(capsys, "install-shortcuts")
        code, out, _ = cmd(capsys, "install-shortcuts", "--remove")
        assert code == ExitCode.OK
        assert out == "veil: hotkeys removed\n"
        assert not installed()

    def test_remove_and_print_exclusive(self, capsys):
        with pytest.raises(SystemExit) as caught:
            cmd(capsys, "install-shortcuts", "--remove", "--print")
        assert caught.value.code == ExitCode.USAGE


# ── jeepney against a fake shortcut service on a private bus ──────────────────


class KGlobalAccel:
    """Just enough of org.kde.KGlobalAccel, recording what arrives over the wire."""

    def __init__(self) -> None:
        self.keys: dict[str, list] = {}
        self.taken: set[int] = set()

    def handlers(self):
        return {
            "isGlobalShortcutAvailable": lambda body: ("b", (body[0] not in self.taken,)),
            "doRegister": lambda body: (None, ()),
            "unregister": lambda body: ("b", (True,)),
            "setForeignShortcutKeys": self.set_keys,
            "shortcutKeys": lambda body: ("a(ai)", (self.keys.get(body[0][0], []),)),
        }

    def set_keys(self, body):
        self.keys[body[0][0]] = body[1]
        return None, ()


@pytest.fixture
def kglobalaccel(tmp_path):
    fake = KGlobalAccel()
    with (
        privatebus.private_bus(tmp_path) as address,
        privatebus.fake_service(
            address, shortcuts.SERVICE, shortcuts.INTERFACE, fake.handlers()
        ) as service,
    ):
        fake.address, fake.service = address, service
        yield fake


class TestJeepney:
    def test_install_over_dbus(self, kglobalaccel):
        bus = RealJeepneyShortcuts(kglobalaccel.address)
        try:
            assert bus.running()
            reports = install(bus, lambda: True, COMMAND)
        finally:
            bus.close()
        assert all(r.result is Result.INSTALLED for r in reports)
        assert kglobalaccel.keys["net.local.veil-toggle.desktop"] == [([META_ALT | 0x4B],)]
        members = [member for member, _ in kglobalaccel.service.calls]
        assert members[:5] == [
            "isGlobalShortcutAvailable",
            "doRegister",
            "unregister",
            "setForeignShortcutKeys",
            "shortcutKeys",
        ]
        register = next(
            body for member, body in kglobalaccel.service.calls if member == "doRegister"
        )
        assert register == (
            ["net.local.veil-sanitize.desktop", "veil: sanitize the clipboard", "", ""],
        )

    def test_action_id(self, kglobalaccel):
        bus = RealJeepneyShortcuts(kglobalaccel.address)
        try:
            bus.set_keys(TOGGLE, [1])
        finally:
            bus.close()
        member, body = kglobalaccel.service.calls[-1]
        assert member == "setForeignShortcutKeys"
        assert body[0] == [TOGGLE.component, TOGGLE.title, "_launch", TOGGLE.title]

    def test_taken_over_dbus(self, kglobalaccel):
        kglobalaccel.taken.add(key_code("Meta+Alt+E"))
        bus = RealJeepneyShortcuts(kglobalaccel.address)
        try:
            reports = install(bus, lambda: True, COMMAND)
        finally:
            bus.close()
        assert {r.shortcut.name: r.result for r in reports}["restore"] is Result.TAKEN

    def test_not_running(self, tmp_path):
        with privatebus.private_bus(tmp_path) as address:
            bus = RealJeepneyShortcuts(address)
            try:
                assert bus.running() is False
            finally:
                bus.close()

    def test_error_name_only(self, kglobalaccel):
        bus = RealJeepneyShortcuts(kglobalaccel.address)
        try:
            with pytest.raises(shortcuts.ShortcutError) as caught:
                bus._method("nope", "s", ("x",))
        finally:
            bus.close()
        assert str(caught.value) == "org.freedesktop.DBus.Error.UnknownMethod"


# ── --key overrides ───────────────────────────────────────────────────────────


class TestOverrides:
    def test_default(self):
        assert shortcuts.with_keys({}) == SHORTCUTS

    def test_override(self):
        chosen = {s.name: s.keys for s in shortcuts.with_keys({"restore": "meta+alt+x"})}
        assert chosen["restore"] == "Meta+Alt+X"
        assert chosen["sanitize"] == "Meta+Alt+V"

    @pytest.mark.parametrize(
        ("keys", "normalized"),
        [
            ("alt+meta+e", "Meta+Alt+E"),
            ("Shift+Ctrl+1", "Ctrl+Shift+1"),
            (" Meta + Alt + r ", "Meta+Alt+R"),
        ],
    )
    def test_normalize(self, keys, normalized):
        assert shortcuts.normalize_keys(keys) == normalized

    @pytest.mark.parametrize(
        "overrides",
        [
            {"nope": "Meta+Alt+X"},
            {"restore": "Meta+Alt+V"},  # clashes with sanitize
            {"restore": "Hyper+X"},
            {"restore": "Meta+Meta+X"},
            {"restore": "Meta+Alt+F5"},
            {"restore": ""},
        ],
    )
    def test_invalid(self, overrides):
        with pytest.raises((ValueError, KeyError)):
            shortcuts.with_keys(overrides)

    def test_installed_keys_follow_the_override(self, shortcut_service):
        chosen = shortcuts.with_keys({"toggle": "Meta+Alt+J"})
        install(shortcut_service, lambda: True, COMMAND, chosen)
        assert shortcuts.installed_keys(TOGGLE) == "Meta+Alt+J"
        assert killswitch.switch_back() == "Run `veil on` or press Meta+Alt+J to switch back."
        assert shortcut_service.keys_by_component[TOGGLE.component] == [key_code("Meta+Alt+J")]

    def test_installed_keys_without_file_or_field(self):
        assert shortcuts.installed_keys(TOGGLE) is None
        folder = applications_dir()
        folder.mkdir(parents=True)
        (folder / TOGGLE.component).write_text("[Desktop Entry]\nX-Veil-Keys=garbage\n")
        assert shortcuts.installed_keys(TOGGLE) is None
        assert killswitch.switch_back() == "Run `veil on` to switch back."

    @pytest.mark.usefixtures("session_bus")
    def test_cli_key(self, capsys, shortcut_service):
        code, out, _ = cmd(capsys, "install-shortcuts", "--key", "restore=Meta+Alt+X")
        assert code == ExitCode.OK
        assert "Meta+Alt+X" in out
        assert shortcut_service.keys_by_component["net.local.veil-restore.desktop"] == [
            key_code("Meta+Alt+X")
        ]

    @pytest.mark.parametrize(
        "value", ["restore", "restore=", "=Meta+Alt+X", "bogus=Meta+Alt+X", "restore=Meta+Alt+V"]
    )
    def test_cli_bad_key(self, capsys, shortcut_service, value):
        code, _, err = cmd(capsys, "install-shortcuts", "--key", value)
        assert code == ExitCode.USAGE
        assert "--key" in err
        assert shortcut_service.registered == []

    def test_print_shows_overrides(self, capsys):
        _, out, _ = cmd(capsys, "install-shortcuts", "--print", "--key", "restore=Meta+Alt+X")
        assert "  Meta+Alt+X  " in out

    @pytest.mark.usefixtures("session_bus")
    def test_taken_message_suggests_key(self, capsys, shortcut_service):
        shortcut_service.taken[key_code("Meta+Alt+E")] = "org.kde.spectacle.desktop"
        code, _, err = cmd(capsys, "install-shortcuts")
        assert code == ExitCode.FINDINGS
        assert "--key NAME=KEYS" in err
