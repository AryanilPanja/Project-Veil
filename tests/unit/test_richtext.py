"""Pure-stdlib rich-text extraction tests (Feature B): HTML and RTF -> plain text."""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil.clip.richtext import RichFormat, html_to_text, rtf_to_text, to_text
from veil.errors import ClipboardError


class TestHtmlToText:
    def test_extracts_visible_text_and_drops_hidden_sections(self):
        html = (
            b"<html><head><title>Jane Doe Secret Title</title>"
            b"<style>body { color: red; /* Jane Doe */ }</style>"
            b"<script>var user = 'Jane Doe';</script></head>"
            b"<body><noscript>Enable JS for Jane Doe</noscript>"
            b"<template><p>Template Jane Doe</p></template>"
            b"<p>Hello <b>Jane Doe</b> &amp; &lt;team&gt;&#39;s &#x2014; welcome!</p>"
            b"<p>Line 1<br>Line 2<br/>Line 3</p></body></html>"
        )
        got = html_to_text(html)
        assert "Secret Title" not in got
        assert "color: red" not in got
        assert "var user" not in got
        assert "Enable JS" not in got
        assert "Template Jane Doe" not in got
        assert got == "Hello Jane Doe & <team>'s \u2014 welcome!\nLine 1\nLine 2\nLine 3"

    def test_block_elements_and_table_cells(self):
        html = (
            b"<h1>Heading</h1>"
            b"<ul><li>First</li><li>Second</li></ul>"
            b"<table><tr><th>Name</th><th>Email</th></tr>"
            b"<tr><td>Jane Doe</td><td>jane.doe@xyz.example.test</td></tr></table>"
        )
        got = html_to_text(html)
        assert got == "Heading\nFirst\nSecond\nName\tEmail\nJane Doe\tjane.doe@xyz.example.test"

    def test_pre_preserves_whitespace(self):
        html = b"<pre>  Jane Doe\n    indented  </pre>"
        assert html_to_text(html) == "  Jane Doe\n    indented  "

    def test_utf16_bom_and_nbsp(self):
        html = "<p>Jane&nbsp;Doe</p>".encode("utf-16")
        assert html_to_text(html) == "Jane\xa0Doe"

    def test_invalid_utf8_raises_clipboard_error_without_leaking_text(self):
        with pytest.raises(ClipboardError, match="not valid UTF-8") as caught:
            html_to_text(b"<p>Jane \xff Doe</p>")
        assert "Jane" not in str(caught.value)

    def test_unsupported_format_raises_clipboard_error(self):
        with pytest.raises(ClipboardError, match="unsupported rich text format"):
            to_text(b"hi", "markdown")


class TestRtfToText:
    def test_basic_paragraphs_lines_tabs_and_escapes(self):
        rtf = rb"{\rtf1\ansi Hello \{Jane\}\line \tab \\path\~end\_word\-soft\par Second line}"
        assert rtf_to_text(rtf) == "Hello {Jane}\n\t\\path\xa0end-wordsoft\nSecond line"

    def test_skips_destination_groups(self):
        rtf = (
            b"{\\rtf1\\ansi"
            b"{\\fonttbl{\\f0 Helvetica;}}"
            b"{\\colortbl;\\red0\\green0\\blue0;}"
            b"{\\stylesheet{\\s0 Normal;}}"
            b"{\\info{\\author Jane Doe Secret}{\\title Hidden}}"
            b"{\\pict\\pngblip 89504e47}"
            b"{\\header Header Jane}{\\footer Footer Jane}"
            b"{\\*\\generator LibreOffice Jane}"
            b"Visible Jane Doe}"
        )
        assert rtf_to_text(rtf) == "Visible Jane Doe"

    def test_codepage_hex_escapes(self):
        # cp1252 0xe9 = é, 0x80 = €; cp1251 0xcf = П
        rtf_1252 = rb"{\rtf1\ansi\ansicpg1252 Caf\'e9 \'8010}"
        assert rtf_to_text(rtf_1252) == "Caf\xe9 \u20ac10"
        rtf_1251 = rb"{\rtf1\ansi\ansicpg1251 \'cf\'f0\'e8\'e2\'e5\'f2}"
        assert rtf_to_text(rtf_1251) == "\u041f\u0440\u0438\u0432\u0435\u0442"
        rtf_utf8 = rb"{\rtf1\ansi\ansicpg65001 \'e0\'a6\'9c}"
        assert rtf_to_text(rtf_utf8) == "\u099c"

    def test_unicode_and_uc_fallback_skipping_and_surrogates(self):
        rtf = rb"{\rtf1\ansi \u2332? \uc2\u8212\'97\'97 \uc1\u-10179?\u-8704?}"
        assert rtf_to_text(rtf) == "\u091c \u2014 \U0001f600"

    def test_special_character_control_words(self):
        rtf = rb"{\rtf1\ansi \ldblquote Jane\emdash Doe\rdblquote  \bullet  \lquote x\rquote}"
        assert rtf_to_text(rtf) == "\u201cJane\u2014Doe\u201d \u2022 \u2018x\u2019"

    def test_to_text_dispatches_html_and_rtf(self):
        assert to_text(b"<p>Jane Doe</p>", RichFormat.HTML) == "Jane Doe"
        assert to_text(rb"{\rtf1 Jane Doe}", RichFormat.RTF) == "Jane Doe"

    @pytest.mark.parametrize(
        "bad_rtf",
        [
            b"",
            b"not rtf at all",
            b"{\\rtf1 unclosed",
            b"{\\rtf1 extra}}",
            b"{\\rtf1 ok} trailing",
            b"{\\rtf1 bad \xff byte}",
            b"{\\rtf1 nul \x00 byte}",
            b"{\\rtf1 \\'zz}",
            b"{\\rtf1 \\'a}",
            b"{\\rtf1 \\ansicpg}",
            b"{\\rtf1 \\ansicpg999999}",
            b"{\\rtf1 \\uc-1}",
            b"{\\rtf1 \\u}",
            b"{\\rtf1 \\u-10179? abc}",  # unpaired high surrogate
            b"{\\rtf1 \\u-8704?}",  # unpaired low surrogate
            b"{" * 300 + b"\\rtf1 deep" + b"}" * 300,
        ],
    )
    def test_malformed_rtf_raises_clipboard_error(self, bad_rtf):
        with pytest.raises(ClipboardError):
            rtf_to_text(bad_rtf)


class TestFuzz:
    @given(st.binary(max_size=2048))
    def test_html_fuzz_never_crashes(self, data):
        try:
            res = html_to_text(data)
        except ClipboardError:
            return
        assert isinstance(res, str)

    @given(st.binary(max_size=2048))
    def test_rtf_fuzz_never_crashes(self, data):
        try:
            res = rtf_to_text(data)
        except ClipboardError:
            return
        assert isinstance(res, str)
