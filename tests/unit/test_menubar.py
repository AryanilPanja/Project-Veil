"""Unit tests for the macOS menu-bar status and quick-toggle app (`veil menubar`)."""

import sys
from datetime import UTC, datetime, timedelta

import pytest

from veil import cli, killswitch, paths, shortcuts
from veil.clip import menubar
from veil.clip.menubar import MenuAction, build_menu_items, menu_snapshot, perform_action
from veil.errors import VeilError
from veil.exitcodes import ExitCode

NOW = datetime(2026, 11, 28, 12, 0, tzinfo=UTC)


def test_snapshot_and_menu_when_off(copy_watcher):
    cfg = paths.config_dir()
    snap = menu_snapshot(cfg, NOW, watcher=copy_watcher)
    assert not snap.is_on
    assert snap.title == "veil OFF"
    assert "OFF" in snap.status_line

    items = build_menu_items(snap)
    actions = [item.action for item in items if item.action is not None]
    assert MenuAction.ON in actions
    assert MenuAction.ON_30M in actions
    assert MenuAction.ON_2H in actions
    assert MenuAction.OFF not in actions
    assert MenuAction.SANITIZE in actions
    assert MenuAction.RESTORE in actions
    assert MenuAction.OPEN_SHORTCUTS in actions
    assert MenuAction.QUIT in actions


def test_snapshot_and_menu_when_on(copy_watcher, switch_timers):
    cfg = paths.config_dir()
    killswitch.switch_on(cfg, copy_watcher, switch_timers, NOW, timedelta(minutes=30))
    snap = menu_snapshot(cfg, NOW, watcher=copy_watcher)
    assert snap.is_on
    assert snap.title == "veil ON"
    assert "30 min" in snap.status_line

    items = build_menu_items(snap)
    actions = [item.action for item in items if item.action is not None]
    assert MenuAction.ON not in actions
    assert MenuAction.OFF in actions


@pytest.mark.parametrize(
    ("action", "expected_hours"),
    [
        (MenuAction.ON, None),
        (MenuAction.ON_30M, 0.5),
        (MenuAction.ON_2H, 2.0),
    ],
)
def test_perform_action_switch_on(
    copy_watcher, switch_timers, notifications, action, expected_hours
):
    cfg = paths.config_dir()
    assert perform_action(action, config=cfg, now=NOW, watcher=copy_watcher, timers=switch_timers)
    assert copy_watcher.running
    switch, _ = killswitch.read_switch(cfg)
    assert switch.on
    if expected_hours is None:
        assert switch.until is None
    else:
        assert switch.until == NOW + timedelta(hours=expected_hours)
    assert notifications[-1].summary == "veil ON"


def test_perform_action_switch_off_requires_confirmation(
    copy_watcher, switch_timers, switch_chooser, monkeypatch
):
    cfg = paths.config_dir()
    killswitch.switch_on(cfg, copy_watcher, switch_timers, NOW)

    # User didn't click Switch OFF -> stays ON.
    switch_chooser.reply = None
    assert not perform_action(
        MenuAction.OFF, config=cfg, now=NOW, watcher=copy_watcher, timers=switch_timers
    )
    assert copy_watcher.running

    # Missing chooser -> stays ON.
    monkeypatch.setattr(killswitch, "detect_chooser", lambda: None)
    assert not perform_action(
        MenuAction.OFF,
        config=cfg,
        now=NOW,
        watcher=copy_watcher,
        timers=switch_timers,
    )
    assert copy_watcher.running

    # User clicked Switch OFF -> switches OFF.
    assert perform_action(
        MenuAction.OFF,
        config=cfg,
        now=NOW,
        watcher=copy_watcher,
        timers=switch_timers,
        chooser=lambda *_a: "off",
    )
    assert not copy_watcher.running


def test_perform_action_clipboard_and_shortcuts(monkeypatch):
    seen: list[list[str]] = []
    monkeypatch.setattr(shortcuts.shutil, "which", lambda _n: None)

    assert perform_action(
        MenuAction.SANITIZE,
        run_subprocess=lambda argv: seen.append(list(argv)) or 0,
        veil_cmd=["/py", "-m", "veil"],
    )
    assert perform_action(
        MenuAction.RESTORE,
        run_subprocess=lambda argv: seen.append(list(argv)) or 0,
        veil_cmd=["/py", "-m", "veil"],
    )
    assert perform_action(
        MenuAction.OPEN_SHORTCUTS,
        run_subprocess=lambda argv: seen.append(list(argv)) or 0,
    )
    assert seen[0] == ["/py", "-m", "veil", "clip", "sanitize"]
    assert seen[1] == ["/py", "-m", "veil", "clip", "restore"]
    assert seen[2] == ["/usr/bin/open", str(shortcuts.macos_shortcuts_dir())]
    assert (shortcuts.macos_shortcuts_dir() / "veil-sanitize.shortcut").is_file()


def test_perform_action_watcher_failure_notifies_without_raising(
    copy_watcher, switch_timers, notifications
):
    copy_watcher.can_start = False
    ok = perform_action(
        MenuAction.ON,
        config=paths.config_dir(),
        now=NOW,
        watcher=copy_watcher,
        timers=switch_timers,
    )
    assert ok is False
    assert notifications[-1].summary == "veil"


def test_non_darwin_menubar_runtime_refuses(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    menubar._runtime.cache_clear()
    try:
        with pytest.raises(VeilError, match="macOS") as exc:
            menubar._runtime()
        assert exc.value.exit_code is ExitCode.UNSAFE_ENVIRONMENT
    finally:
        menubar._runtime.cache_clear()


def test_cli_dispatches_menubar(monkeypatch):
    called = []
    monkeypatch.setattr(menubar, "run", lambda: called.append(True))
    assert cli.main(["menubar"]) == ExitCode.OK
    assert called == [True]
