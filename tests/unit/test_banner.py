"""The terminal banner (banner.py)."""

from veil import banner


def test_plain_text_has_no_escape_codes():
    text = banner.render("1.2.3", color=False)
    assert "\x1b" not in text
    assert "v1.2.3" in text
    assert banner.ART[-1] in text


def test_color_respects_no_color_dumb_terminals_and_pipes():
    assert banner.use_color(True, {"TERM": "xterm-256color"})
    assert not banner.use_color(True, {"NO_COLOR": ""})
    assert not banner.use_color(True, {"TERM": "dumb"})
    assert not banner.use_color(False, {})


def test_fits_in_a_narrow_terminal():
    assert max(len(line) for line in banner.render("10.20.30", color=False).splitlines()) <= 60


def test_help_shows_banner_only_in_a_terminal(monkeypatch, capsys):
    from veil import cli, ui

    monkeypatch.setattr(ui, "stdout_is_tty", lambda: False)
    cli.main([])
    assert banner.ART[1] not in capsys.readouterr().out
    monkeypatch.setattr(ui, "stdout_is_tty", lambda: True)
    monkeypatch.setenv("NO_COLOR", "1")
    cli.main([])
    out = capsys.readouterr().out
    assert banner.ART[1] in out
    assert "\x1b" not in out
