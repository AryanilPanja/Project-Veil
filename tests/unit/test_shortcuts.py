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
            "Alt+V",
            "Alt+Shift+V",
        }

    def test_no_ctrl_v_grab(self):
        # ADR-0031: Ctrl+C / Ctrl+V stay the applications' own (the copy watcher needs no key).
        assert not any(s.keys.startswith("Ctrl+") for s in SHORTCUTS)


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
            "Name=veil: ON (sanitize every copy) / OFF\n"
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
            "net.local.veil-paste.desktop",
            "net.local.veil-paste-terminal.desktop",
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
        assert [r.result for r in reports] == [Result.INSTALLED] * len(SHORTCUTS)
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
        assert "  Alt+V       /venv/bin/python -m veil clip paste" in lines  # aligned


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


class TestToggleHint:
    def test_without_shortcut(self):
        assert killswitch.toggle_hint() == "`veil on` / `veil off` switch it."
        assert "Meta+Alt" not in killswitch.off_message().body

    def test_with_shortcut(self, shortcut_service):
        install(shortcut_service, lambda: True, COMMAND)
        assert killswitch.toggle_hint() == "Meta+Alt+K switches it."
        now = utc_now()
        assert "Meta+Alt+K" in killswitch.off_message().body
        assert "Meta+Alt+K" in killswitch.on_message(Switch(True, now), now).body


class TestLegacy:
    def test_paste_mode_files_are_cleaned_up(self, shortcut_service):
        folder = applications_dir()
        folder.mkdir(parents=True)
        for component in shortcuts.LEGACY_COMPONENTS:
            (folder / component).write_text("[Desktop Entry]\n")
        install(shortcut_service, lambda: True, COMMAND)
        assert not any((folder / c).exists() for c in shortcuts.LEGACY_COMPONENTS)

    def test_remove_cleans_up_too(self):
        folder = applications_dir()
        folder.mkdir(parents=True)
        (folder / shortcuts.LEGACY_COMPONENTS[0]).write_text("[Desktop Entry]\n")
        remove(None, lambda: True)
        assert not (folder / shortcuts.LEGACY_COMPONENTS[0]).exists()


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
        assert out.count("installed") == len(SHORTCUTS)
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
    """Just enough of org.kde.KGlobalAccel, keyed like the real one: (component, action unique
    name) from the action id [ComponentUnique, ActionUnique, ComponentFriendly, ActionFriendly]."""

    def __init__(self) -> None:
        self.keys: dict[tuple[str, str], list] = {}
        self.taken: set[int] = set()

    def handlers(self):
        return {
            "isGlobalShortcutAvailable": lambda body: ("b", (body[0] not in self.taken,)),
            "doRegister": lambda body: (None, ()),
            "unregister": self.unregister,
            "setForeignShortcutKeys": self.set_keys,
            "shortcutKeys": lambda body: ("a(ai)", (self.keys.get((body[0][0], body[0][1]), []),)),
        }

    def set_keys(self, body):
        self.keys[(body[0][0], body[0][1])] = body[1]
        return None, ()

    def unregister(self, body):
        return "b", (self.keys.pop((body[0], body[1]), None) is not None,)


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
        # The key is on the _launch action: the one KDE runs the desktop file for.
        assert kglobalaccel.keys[("net.local.veil-toggle.desktop", "_launch")] == [
            ([META_ALT | 0x4B],)
        ]
        assert all(action == "_launch" for _, action in kglobalaccel.keys)
        calls = [c for c in kglobalaccel.service.calls if "veil-sanitize" in str(c[1])]
        assert [member for member, _ in calls] == [
            "unregister",  # the legacy action, if any
            "shortcutKeys",
            "isGlobalShortcutAvailable",
            "doRegister",
            "unregister",
            "setForeignShortcutKeys",
            "shortcutKeys",
        ]

    def test_action_id_order_matches_kglobalaccel(self, kglobalaccel):
        # kglobalaccel.h: ComponentUnique = 0, ActionUnique = 1, ComponentFriendly = 2,
        # ActionFriendly = 3.
        bus = RealJeepneyShortcuts(kglobalaccel.address)
        try:
            bus.register(TOGGLE)
            bus.set_keys(TOGGLE, [1])
        finally:
            bus.close()
        member, body = kglobalaccel.service.calls[0]
        assert member == "doRegister"
        assert body == ([TOGGLE.component, "", TOGGLE.title, ""],)
        member, body = kglobalaccel.service.calls[-1]
        assert member == "setForeignShortcutKeys"
        assert body[0] == [TOGGLE.component, "_launch", TOGGLE.title, TOGGLE.title]

    def test_legacy_action_is_removed(self, kglobalaccel):
        # What the first M3.3 build left behind: the key on an action named after the title.
        legacy = (TOGGLE.component, TOGGLE.title)
        kglobalaccel.keys[legacy] = [([META_ALT | 0x4B],)]
        bus = RealJeepneyShortcuts(kglobalaccel.address)
        try:
            install(bus, lambda: True, COMMAND)
        finally:
            bus.close()
        assert legacy not in kglobalaccel.keys
        assert kglobalaccel.keys[(TOGGLE.component, "_launch")] == [([META_ALT | 0x4B],)]

    def test_reinstall_keeps_own_keys(self, kglobalaccel):
        bus = RealJeepneyShortcuts(kglobalaccel.address)
        try:
            install(bus, lambda: True, COMMAND)
            # The real service may call our own key "unavailable": it must not matter.
            kglobalaccel.taken.update(key_code(s.keys) for s in SHORTCUTS)
            reports = install(bus, lambda: True, COMMAND)
        finally:
            bus.close()
        assert all(r.result is Result.INSTALLED for r in reports)
        assert all((applications_dir() / s.component).exists() for s in SHORTCUTS)

    def test_taken_over_dbus(self, kglobalaccel):
        kglobalaccel.taken.add(key_code("Meta+Alt+E"))
        bus = RealJeepneyShortcuts(kglobalaccel.address)
        try:
            reports = install(bus, lambda: True, COMMAND)
        finally:
            bus.close()
        assert {r.shortcut.name: r.result for r in reports}["restore"] is Result.TAKEN

    def test_status_over_dbus(self, kglobalaccel):
        bus = RealJeepneyShortcuts(kglobalaccel.address)
        try:
            install(bus, lambda: True, COMMAND)
            rows = shortcuts.status(bus)
        finally:
            bus.close()
        assert all(row.ok for row in rows)
        toggle = next(row for row in rows if row.shortcut.name == "toggle")
        assert toggle.live_keys == ["Meta+Alt+K"]

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
        assert killswitch.toggle_hint() == "Meta+Alt+J switches it."
        assert shortcut_service.keys_by_component[TOGGLE.component] == [key_code("Meta+Alt+J")]

    def test_installed_keys_without_file_or_field(self):
        assert shortcuts.installed_keys(TOGGLE) is None
        folder = applications_dir()
        folder.mkdir(parents=True)
        (folder / TOGGLE.component).write_text("[Desktop Entry]\nX-Veil-Keys=garbage\n")
        assert shortcuts.installed_keys(TOGGLE) is None
        assert killswitch.toggle_hint() == "`veil on` / `veil off` switch it."

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


# ── --status and key names ────────────────────────────────────────────────────


class TestStatus:
    @pytest.mark.parametrize("keys", ["Meta+Alt+V", "Ctrl+Shift+1", "Meta+Ctrl+Alt+Shift+Z"])
    def test_key_name_round_trip(self, keys):
        assert shortcuts.key_name(key_code(keys)) == keys

    def test_nothing_installed(self, shortcut_service):
        rows = shortcuts.status(shortcut_service)
        assert [r.ok for r in rows] == [False] * len(SHORTCUTS)
        assert rows[0].file_keys is None

    def test_installed(self, shortcut_service):
        install(shortcut_service, lambda: True, COMMAND)
        assert all(r.ok for r in shortcuts.status(shortcut_service))

    def test_file_without_live_key(self, shortcut_service):
        install(shortcut_service, lambda: True, COMMAND)
        shortcut_service.keys_by_component.clear()
        rows = shortcuts.status(shortcut_service)
        assert rows[0].file_keys == "Meta+Alt+V"
        assert rows[0].live_keys == []
        assert not rows[0].ok

    def test_service_error_counts_as_no_key(self, shortcut_service):
        install(shortcut_service, lambda: True, COMMAND)
        shortcut_service.fail = {"keys"}
        assert not any(r.ok for r in shortcuts.status(shortcut_service))

    @pytest.mark.usefixtures("session_bus")
    def test_cli(self, capsys, shortcut_service):
        code, out, _ = cmd(capsys, "install-shortcuts", "--status")
        assert code == ExitCode.FINDINGS
        assert out.count("NOT WORKING") == len(SHORTCUTS)
        cmd(capsys, "install-shortcuts")
        code, out, _ = cmd(capsys, "install-shortcuts", "--status")
        assert code == ExitCode.OK
        assert out.count(" ok") == len(SHORTCUTS)

    def test_cli_without_bus(self, capsys, monkeypatch):
        monkeypatch.delenv("DBUS_SESSION_BUS_ADDRESS", raising=False)
        code, _, err = cmd(capsys, "install-shortcuts", "--status")
        assert code == ExitCode.FINDINGS
        assert "only files were checked" in err

    def test_install_drops_legacy_actions(self, shortcut_service):
        install(shortcut_service, lambda: True, COMMAND)
        assert shortcut_service.dropped == [s.component for s in SHORTCUTS]

    def test_reinstall_with_own_key_taken(self, shortcut_service):
        install(shortcut_service, lambda: True, COMMAND)
        for shortcut in SHORTCUTS:  # the service says "taken" even for our own key
            shortcut_service.taken[key_code(shortcut.keys)] = "something-else"
        reports = install(shortcut_service, lambda: True, COMMAND)
        assert all(r.result is Result.INSTALLED for r in reports)


def test_empty_sequences_are_not_keys(kglobalaccel):
    kglobalaccel.keys[(TOGGLE.component, "_launch")] = [([0],), ([0, 0, 0, 0],)]
    bus = RealJeepneyShortcuts(kglobalaccel.address)
    try:
        assert bus.keys(TOGGLE) == []
    finally:
        bus.close()


def test_help_names_every_shortcut(capsys):
    from veil import cli

    with pytest.raises(SystemExit):
        cli.main(["install-shortcuts", "--help"])
    # argparse wraps lines after a hyphen ("paste-" / "terminal"): undo that before matching
    out = " ".join(capsys.readouterr().out.split()).replace("- ", "-")
    for shortcut in SHORTCUTS:
        assert shortcut.name in out, shortcut.name
    with pytest.raises(SystemExit):
        cli.main(["--help"])
    assert "Meta+Alt+V/C/E/K" in capsys.readouterr().out  # the command list's summary
