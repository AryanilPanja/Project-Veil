"""tests/manual/site-matrix: the offline M4 test page, its slot template and the synthetic slots.

The page's script runs under node (skipped without node); the static checks run everywhere.
"""

import json
import re
import shutil
import subprocess
import unicodedata
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

ROOT = Path(__file__).resolve().parents[2]
MATRIX = ROOT / "tests" / "manual" / "site-matrix"
PAGE = MATRIX / "matrix.html"
TEMPLATE = MATRIX / "matrix-slots.template.txt"
SYNTHETIC = MATRIX / "matrix-slots.synthetic.txt"
FIXTURE = ROOT / "tests" / "fixtures" / "synthetic_jane.yaml"

HTML = PAGE.read_text(encoding="utf-8")
SCRIPT = re.search(r"<script>(.*?)</script>", HTML, re.S).group(1)

HARNESS = """
const fs = require("fs");
const readline = require("readline");
const vm = require("vm");
const ctx = { module: { exports: {} } };
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(process.argv[2], "utf8"), ctx);
const M = ctx.module.exports;
const call = ([name, args]) => {
  try {
    const value = typeof M[name] === "function" ? M[name](...args) : M[name];
    return { value: value === undefined ? null : value };
  } catch (e) {
    return { error: String(e) };
  }
};
// One JSON batch per line in, one JSON result list per line out.
readline.createInterface({ input: process.stdin }).on("line", (line) => {
  process.stdout.write(JSON.stringify(JSON.parse(line).map(call)) + "\\n");
});
"""


def slot_lines(path: Path) -> list[tuple[str, str]]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            key, _, value = line.partition("=")
            out.append((key.strip(), value.strip()))
    return out


SYN = dict(slot_lines(SYNTHETIC))


@pytest.fixture(scope="module")
def js(tmp_path_factory):
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    folder = tmp_path_factory.mktemp("matrix")
    (folder / "page.js").write_text(SCRIPT, encoding="utf-8")
    (folder / "harness.js").write_text(HARNESS, encoding="utf-8")
    proc = subprocess.Popen(
        [node, str(folder / "harness.js"), str(folder / "page.js")],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )

    def batch(*calls):
        line = json.dumps([[name, list(args)] for name, *args in calls])
        proc.stdin.write(line + "\n")
        proc.stdin.flush()
        reply = proc.stdout.readline()
        assert reply, "node exited"
        results = json.loads(reply)
        for result in results:
            assert "error" not in result, result
        return [r["value"] for r in results]

    def one(name, *args):
        return batch((name, *args))[0]

    one.batch = batch
    yield one
    proc.stdin.close()
    proc.wait(timeout=10)
    proc.stdout.close()


# ── Static: offline, no storage, no hidden characters ─────────────────────────


class TestStatic:
    def test_csp_blocks_all_network(self):
        csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', HTML).group(1)
        for directive in (
            "default-src 'none'",
            "connect-src 'none'",
            "img-src 'none'",
            "font-src 'none'",
            "frame-src 'none'",
            "object-src 'none'",
            "form-action 'none'",
            "base-uri 'none'",
        ):
            assert directive in csp
        assert "http" not in csp

    @pytest.mark.parametrize(
        "pattern",
        [
            r"<script[^>]+src", r"<link\b", r"<iframe", r"<form\b", r"@import", r"url\(",
            r"\bfetch\(", r"XMLHttpRequest", r"WebSocket", r"EventSource", r"sendBeacon",
            r"localStorage", r"sessionStorage", r"indexedDB", r"document\.cookie",
            r"navigator\.clipboard", r"window\.open", r"\beval\(", r"new Function",
            r"postMessage", r"execCommand",
        ],
    )  # fmt: skip
    def test_no_network_storage_or_clipboard_api(self, pattern):
        assert not re.search(pattern, HTML)

    def test_no_invisible_characters(self):
        # Escapes such as \\uFEFF must stay escapes in the source (a Write can turn them literal).
        bad = [hex(ord(c)) for c in HTML if unicodedata.category(c) in ("Cf", "Co", "Cs")]
        assert bad == []

    def test_external_urls_only_in_link_markup(self):
        # The only URLs are the rich source's link targets, built from slot values.
        urls = re.findall(r"https?://[^\s\"'`$]*", HTML)
        assert set(urls) == {"https://github.com/", "https://"}


# ── The slot files ─────────────────────────────────────────────────────────────


class TestSlotFiles:
    def test_template_has_no_values(self):
        # The committed template must never carry data.
        assert all(value == "" for _, value in slot_lines(TEMPLATE))

    def test_template_keys_match_the_page(self, js):
        assert [k for k, _ in slot_lines(TEMPLATE)] == js("SLOT_KEYS")

    def test_synthetic_keys_match_the_page(self, js):
        assert [k for k, _ in slot_lines(SYNTHETIC)] == js("SLOT_KEYS")

    def test_synthetic_fills_every_slot(self):
        assert all(SYN.values())

    def test_synthetic_values_come_from_the_synthetic_persona(self):
        fixture = FIXTURE.read_text(encoding="utf-8")
        reformatted = {"phone_other_format", "date_of_birth_other_format"}
        for key, value in SYN.items():
            if key not in reformatted:
                assert value in fixture, key
        assert re.sub(r"\D", "", SYN["phone"]).endswith(SYN["phone_other_format"])
        assert "2001" in SYN["date_of_birth_other_format"]

    def test_filled_copy_is_git_ignored(self):
        lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        assert "matrix-slots.txt" in lines
        # a basename pattern: it doesn't touch the template or the synthetic copy
        assert TEMPLATE.name != "matrix-slots.txt"
        assert SYNTHETIC.name != "matrix-slots.txt"

    def test_every_slot_is_used_and_every_placeholder_is_a_slot(self, js):
        keys = set(js("SLOT_KEYS"))
        templates = js("templates")
        used = {k for t in templates for k in js.batch(("needs", t))[0]}
        assert used == keys


# ── parseSlots ─────────────────────────────────────────────────────────────────


class TestParse:
    def test_basic(self, js):
        r = js("parseSlots", "# c\n\nfirst_name = Jane\n  email=jane@x.test  \n")
        assert r == {"slots": {"first_name": "Jane", "email": "jane@x.test"}, "problems": []}

    @pytest.mark.parametrize("newline", ["\r\n", "\r", "\n"])
    def test_line_endings(self, js, newline):
        r = js("parseSlots", newline.join(["first_name = Jane", "last_name = Doe", ""]))
        assert r["slots"] == {"first_name": "Jane", "last_name": "Doe"}

    def test_bom(self, js):
        assert js("parseSlots", "\ufefffirst_name = Jane")["slots"] == {"first_name": "Jane"}

    def test_first_equals_splits(self, js):
        r = js("parseSlots", "website = a.test/?q=1=2")
        assert r["slots"] == {"website": "a.test/?q=1=2"}

    def test_empty_value_is_skipped(self, js):
        assert js("parseSlots", "first_name =\nlast_name =   \n") == {"slots": {}, "problems": []}

    def test_nfd_value_becomes_nfc(self, js):
        nfd = unicodedata.normalize("NFD", "জো")
        assert nfd != "জো"
        assert js("parseSlots", f"name_bengali = {nfd}")["slots"] == {"name_bengali": "জো"}

    @pytest.mark.parametrize(
        ("text", "problem"),
        [
            ("Jane Doe", 'line 1: no "="'),
            ("First Name = Jane", "line 1: bad key"),
            ("1st = Jane", "line 1: bad key"),
            ("= Jane", "line 1: bad key"),
            ("favourite = Jane", "line 1: unknown slot favourite"),
            ("first_name = A\nfirst_name = B", "line 2: first_name given twice"),
        ],
    )
    def test_problems(self, js, text, problem):
        assert js("parseSlots", text)["problems"] == [problem]

    def test_duplicate_keeps_the_first(self, js):
        assert js("parseSlots", "first_name = A\nfirst_name = B")["slots"] == {"first_name": "A"}

    def test_problems_never_echo_values(self, js):
        marker = "Zq9MarkerValue"
        text = "\n".join(
            [
                f"{marker}",
                f"{marker} = x",
                f"bad key = {marker}",
                f"unknown_key = {marker}",
                f"first_name = {marker}",
                f"first_name = {marker}2",
            ]
        )
        problems = js("parseSlots", text)["problems"]
        assert len(problems) == 5
        assert not any(marker in p for p in problems)

    def test_line_numbers_count_comments_and_blanks(self, js):
        assert js("parseSlots", "# a\n\n# b\noops")["problems"] == ['line 4: no "="']


# ── The sources ────────────────────────────────────────────────────────────────

BUILDERS = ["plainText", "richHtml", "indicText", "sensitiveText", "dumpText"]


class TestSources:
    def test_nothing_loaded_means_empty_sources(self, js):
        assert js.batch(*[(b, {}) for b in BUILDERS]) == [""] * len(BUILDERS)

    def test_no_placeholder_is_left(self, js):
        for out in js.batch(*[(b, SYN) for b in BUILDERS]):
            assert not re.search(r"\{[a-z_0-9]+\}", out)

    def test_every_value_reaches_some_source(self, js):
        outs = js.batch(*[(b, SYN) for b in BUILDERS])
        everything = "\n".join(outs)
        for key, value in SYN.items():
            assert value in everything, key

    def test_only_loaded_values_appear(self, js):
        one = {"email": SYN["email"]}
        assert js("plainText", one) == f"Please reply to {SYN['email']}."
        outs = js.batch(*[(b, one) for b in BUILDERS])
        everything = "\n".join(outs)
        for key, value in SYN.items():
            if key != "email" and value not in SYN["email"]:
                assert value not in everything, key

    def test_sentence_needs_all_its_slots(self, js):
        # "I run jobs on {cluster} as {cluster_user}." is left out without cluster_user.
        out = js("plainText", {"cluster": "orion"})
        assert out == ""

    def test_plain_paragraphs_per_section(self, js):
        out = js("plainText", SYN)
        assert out.count("\n\n") == 3
        assert out.startswith("Hi, I'm Jane Doe.")

    def test_rich_markup(self, js):
        out = js("richHtml", SYN)
        assert "<strong>Jane Doe</strong>" in out
        assert f'<a href="mailto:{SYN["email"]}">' in out
        assert '<a href="https://github.com/jane-doe-dev">' in out
        assert '<a href="https://janedoe.example.test/">' in out
        assert "<code>/home/janed</code>" in out
        assert "<table>" in out
        assert "<h3>About me</h3>" in out

    def test_rich_escapes_values(self, js):
        evil = '<img src=x onerror=alert(1)>"&'
        out = js("richHtml", {"full_name": evil, "email": 'a"b@x.test', "website": evil})
        assert "<img" not in out
        assert "&lt;img src=x onerror=alert(1)&gt;&quot;&amp;" in out
        assert 'mailto:a%22b@x.test"' in out
        assert '<a href="https://%3Cimg' in out

    def test_rich_link_targets_cannot_switch_scheme(self, js):
        out = js("richHtml", {"website": "javascript:alert(1)", "github": "../../evil"})
        assert 'href="https://javascript:alert(1)/"' in out
        assert 'href="https://github.com/..%2F..%2Fevil"' in out
        assert 'href="javascript' not in out

    def test_indic(self, js):
        out = js("indicText", SYN).splitlines()
        assert "আমার নাম জেন।" in out
        assert "मेरा नाम जेन है।" in out
        assert "என் பெயர் ஜேன்." in out
        assert "Jane Doe / জেন / जेन" in out

    def test_indic_adds_a_decomposed_line_when_it_differs(self, js):
        assert len(js("indicText", {"name_bengali": "জেন"}).splitlines()) == 2
        lines = js("indicText", {"name_bengali": "জো"}).splitlines()
        assert len(lines) == 3
        assert lines[2] == unicodedata.normalize("NFD", lines[0]) != lines[0]

    def test_sensitive(self, js):
        out = js("sensitiveText", {"sensitive_term": "asthma"})
        assert out.count("asthma") == 2

    def test_dump_is_at_least_50_kb(self, js):
        out = js("dumpText", SYN)
        assert len(out.encode()) >= 51200 == js("DUMP_MIN_BYTES")
        assert len(out.encode()) < 51200 + 2048
        for key in ("home_dir", "email", "full_name", "cluster", "slurm_account", "linux_user"):
            assert SYN[key] in out
        assert "Author: Jane Doe <jane.doe@xyz.example.test>" in out

    def test_dump_is_deterministic(self, js):
        a, b = js.batch(("dumpText", SYN), ("dumpText", SYN))
        assert a == b

    def test_dump_commit_hashes(self, js):
        hashes = re.findall(r"^commit (\S+)$", js("dumpText", SYN), re.M)
        assert len(hashes) >= 30
        assert all(re.fullmatch(r"[0-9a-f]{40}", h) for h in hashes)
        assert len(set(hashes)) == len(hashes)

    def test_dump_with_some_slots(self, js):
        out = js("dumpText", {"home_dir": "/home/janed"}, 2000)
        assert out
        assert len(out.encode()) >= 2000
        assert "@" not in out  # the prompt lines need linux_user and hostname
        assert "cd /home/janed/projects/repo-1" not in out
        assert "fix: path handling under /home/janed/projects/repo-1" in out

    def test_dump_without_its_slots_is_empty(self, js):
        assert js("dumpText", {"first_name": "Jane", "phone": "+91 1"}) == ""

    def test_dump_counts_utf8_bytes(self, js):
        out = js("dumpText", {"full_name": "জেন দো", "email": "j@x.test"}, 5000)
        assert len(out.encode()) >= 5000
        assert len(out.encode()) - 5000 < 400  # a block, not a block per character

    @settings(max_examples=5, deadline=None)
    @given(st.lists(st.text(max_size=40), min_size=1, max_size=200))
    def test_utf8_bytes_matches_python(self, js, texts):
        got = js.batch(*[("utf8Bytes", t) for t in texts])
        assert got == [len(t.encode()) for t in texts]


# ── findLeaks and verdict ─────────────────────────────────────────────────────


class TestLeaks:
    def test_full_text_finds_its_values(self, js):
        found = js("findLeaks", js("plainText", SYN), SYN)
        assert "full_name" in found
        assert "email" in found
        assert "home_dir" in found

    def test_fake_text_finds_nothing(self, js):
        fake = "Hi, I'm Alex Smith. Reply to alex.smith@abc.example.test. Files: /home/alexs."
        assert js("findLeaks", fake, SYN) == []

    @pytest.mark.parametrize(
        ("text", "key", "found"),
        [
            ("Jane", "first_name", True),
            ("JANE wrote", "first_name", True),
            ("Jane's draft", "first_name", True),
            ("(Jane)", "first_name", True),
            ("Janet", "first_name", False),
            ("xJane", "first_name", False),
            ("Jane_", "first_name", False),
            ("Jane2", "first_name", False),
            ("/home/janed/projects", "home_dir", True),
            ("/home/janedoe", "home_dir", False),
            ("/home/janedoe", "linux_user", False),
            ("mailto:jane.doe@xyz.example.test", "email", True),
            ("xjane.doe@xyz.example.test", "email", False),
            ("Prof. Mary Major", "advisor", True),
            ("ProfX Mary Major", "advisor", False),
            ("আমার নাম জেন।", "name_bengali", True),
            ("জেনের বই", "name_bengali", True),  # a glued case ending (board Q17)
            ("অজেন", "name_bengali", False),
            ("मेरा नाम जेन है।", "name_devanagari", True),
            ("+91-90000-00001", "phone", True),
            ("(900) 000-0001", "phone", True),
            ("0091 9000000001", "phone", True),
            ("90000 00002", "phone", False),
            ("call 9000000001", "phone_other_format", True),
            ("", "first_name", False),
        ],
    )
    def test_cases(self, js, text, key, found):
        assert (key in js("findLeaks", text, SYN)) is found

    def test_nfd_text_matches_nfc_value(self, js):
        text = unicodedata.normalize("NFD", "নাম জো।")
        assert js("findLeaks", text, {"name_bengali": "জো"}) == ["name_bengali"]

    def test_short_phone_needs_an_exact_match(self, js):
        slots = {"phone": "12-345"}
        assert js("findLeaks", "12345", slots) == []
        assert js("findLeaks", "call 12-345 now", slots) == ["phone"]

    def test_regex_characters_in_values(self, js):
        slots = {"full_name": "a+b(c)[d]*?", "website": "x.test"}
        assert js("findLeaks", "see a+b(c)[d]*? and xytest", slots) == ["full_name"]

    def test_order_follows_the_slot_list(self, js):
        found = js("findLeaks", "/home/janed Jane", SYN)
        keys = js("SLOT_KEYS")
        assert found == sorted(found, key=keys.index)

    @settings(max_examples=5, deadline=None)
    @given(
        st.lists(
            st.tuples(
                st.sampled_from(sorted(SYN)),
                st.text(alphabet=" .,;:!?()[]<>\"'\n\t-/", max_size=6),
                st.text(alphabet=" .,;:!?()[]<>\"'\n\t", max_size=6),
            ),
            min_size=1,
            max_size=60,
        )
    )
    def test_a_value_between_separators_is_always_found(self, js, cases):
        results = js.batch(*[("findLeaks", f"{a}{SYN[k]}{b}", SYN) for k, a, b in cases])
        for (key, _, _), found in zip(cases, results, strict=True):
            assert key in found

    @pytest.mark.parametrize(
        ("found", "expect", "ok"),
        [
            ([], "sanitized", True),
            (["email"], "sanitized", False),
            ([], "restored", False),
            (["email"], "restored", True),
        ],
    )
    def test_verdict(self, js, found, expect, ok):
        assert js("verdict", found, expect)["ok"] is ok

    def test_verdict_names_keys_not_values(self, js):
        found = js("findLeaks", "Jane Doe at /home/janed", SYN)
        text = js("verdict", found, "sanitized")["text"]
        assert text.startswith("LEAK: ")
        assert "full_name" in text
        assert not any(v in text for v in SYN.values() if len(v) > 3)
