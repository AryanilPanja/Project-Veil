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
