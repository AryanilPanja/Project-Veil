"""`veil --help` names the hotkeys of the platform it runs on."""

import pytest

from veil import cli


def _help(monkeypatch: pytest.MonkeyPatch, platform: str) -> str:
    monkeypatch.setattr(cli.sys, "platform", platform)
    return cli.build_parser().format_help()


def test_macos_help_names_control_option_and_shortcuts_app(monkeypatch: pytest.MonkeyPatch):
    text = " ".join(_help(monkeypatch, "darwin").split())
    assert "(Control+Option+K)" in text
    assert "Shortcuts.app" in text
    assert "Meta+Alt+K" not in text
    assert "KDE Plasma" not in text


def test_linux_help_names_kde_keys(monkeypatch: pytest.MonkeyPatch):
    text = " ".join(_help(monkeypatch, "linux").split())
    assert "(Meta+Alt+K)" in text
    assert "KDE Plasma: set up the hotkeys" in text
    assert "Control+Option" not in text
    assert "Shortcuts.app" not in text
