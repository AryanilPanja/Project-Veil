import contextlib
from pathlib import Path

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from veil.errors import PersonaFormatError, ValidationFailed
from veil.exitcodes import ExitCode
from veil.persona.yamlio import MAX_BYTES, load_yaml

ROOT = Path(__file__).resolve().parents[2]
BOM = chr(0xFEFF)
SECRET = "Jane Doe 9876543210"


def _error(text: str | bytes) -> PersonaFormatError:
    with pytest.raises(PersonaFormatError) as info:
        load_yaml(text)
    return info.value


# ── The template and normal documents ─────────────────────────────────────────


def test_template_loads():
    data = load_yaml((ROOT / "persona.example.yaml").read_bytes())
    assert data["version"] == "1"  # stays text; the schema checks it
    assert data["numbers"]["date_shift_days"] == "0"
    assert data["education"][0]["degree"]["enabled"] is False
    assert data["sensitive"]["default_policy"] == "ASK"
    assert data["never_reverse"] == []


def test_nested_flow_and_block_structures():
    doc = (
        "people:\n  - { real: Jane, fake: Alex, relation: friend }\n  - real: Ravi\n    fake: Om\n"
    )
    assert load_yaml(doc) == {
        "people": [
            {"real": "Jane", "fake": "Alex", "relation": "friend"},
            {"real": "Ravi", "fake": "Om"},
        ]
    }


def test_comments_are_ignored():
    assert load_yaml("# top\na: b  # trailing\n# end\n") == {"a": "b"}


def test_unicode_values_are_preserved():
    doc = "bn: রাম\nhi: आदित्य\nmix: 'Jane (জেন)'\n"
    assert load_yaml(doc) == {"bn": "রাম", "hi": "आदित्य", "mix": "Jane (জেন)"}


# ── Scalars stay text (YAML 1.1 traps) ───────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0123", "0123"),  # roll number: YAML 1.1 would read octal 83
        ("123", "123"),
        ("-7", "-7"),
        ("1.50", "1.50"),
        ("1e3", "1e3"),
        ("0x1F", "0x1F"),
        (".inf", ".inf"),
        (".nan", ".nan"),
        ("2001-03-14", "2001-03-14"),  # date of birth: would become a date
        ("2001-03-14 10:00:00", "2001-03-14 10:00:00"),
        ("+91 98765 43210", "+91 98765 43210"),
        ("12:30", "12:30"),  # sexagesimal in YAML 1.1
        ("yes", "yes"),
        ("no", "no"),  # would become False
        ("on", "on"),
        ("off", "off"),
        ("y", "y"),
        ("n", "n"),
        ("Yes", "Yes"),
        ("NO", "NO"),
        ("=", "="),  # the YAML "value" key
        ("<<", "<<"),
    ],
)
def test_plain_scalars_stay_text(raw, expected):
    assert load_yaml(f"v: {raw}\n") == {"v": expected}


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("true", True),
        ("True", True),
        ("TRUE", True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
    ],
)
def test_true_and_false_are_booleans(raw, expected):
    assert load_yaml(f"v: {raw}\n")["v"] is expected


@pytest.mark.parametrize("raw", ["~", "null", "Null", "NULL", ""])
def test_null_forms(raw):
    assert load_yaml(f"v: {raw}\n") == {"v": None}


@pytest.mark.parametrize("raw", ['"true"', "'false'", '"null"', '"0123"', "'2001-03-14'"])
def test_quoted_scalars_are_always_text(raw):
    assert load_yaml(f"v: {raw}\n") == {"v": raw[1:-1]}


def test_explicit_str_tag_is_allowed():
    assert load_yaml("v: !!str 0123\n") == {"v": "0123"}


# ── Duplicate keys (E002) ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("doc", "line", "column"),
    [
        ("a: 1\nb: 2\na: 3\n", 3, 1),
        ("person:\n  first: x\n  first: y\n", 3, 3),
        ("people:\n  - { real: a, real: b }\n", 2, 16),
        ('a: 1\n"a": 2\n', 2, 1),  # quoting does not make it a different key
    ],
)
def test_duplicate_keys_are_rejected_with_position(doc, line, column):
    error = _error(doc)
    assert error.code == "E002"
    assert (error.line, error.column) == (line, column)
    assert str(error) == f"E002 duplicate key at line {line}, column {column}"


def test_duplicate_key_message_has_no_values():
    error = _error(f"real: {SECRET}\nreal: {SECRET}\n")
    assert "Jane" not in str(error)
    assert "real" not in str(error)


# ── Refused constructs (E001) ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "doc",
    [
        "a: &x 1\nb: 2\n",  # anchor
        "a: &x [1, 2]\nb: *x\n",  # alias
        "base: &b {x: 1}\nchild:\n  <<: *b\n",  # merge key via alias
        "a: &x\n  k: v\n",  # anchor on a mapping
    ],
)
def test_anchors_and_aliases_are_rejected(doc):
    error = _error(doc)
    assert error.code == "E001"
    assert "anchors and aliases" in str(error)


def test_billion_laughs_is_rejected_quickly():
    doc = 'a: &a ["x","x","x","x","x","x","x","x","x"]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n'
    assert _error(doc).code == "E001"


@pytest.mark.parametrize(
    "doc",
    [
        "a: !!python/object/apply:os.system ['echo pwned']\n",
        "a: !!python/name:os.system\n",
        "a: !!python/object:builtins.dict {}\n",
        "a: !custom thing\n",
    ],
)
def test_unsafe_or_unknown_tags_are_rejected(doc):
    error = _error(doc)
    assert error.code == "E001"
    assert "unsupported value or tag" in str(error)
    assert "python" not in str(error)
    assert "os.system" not in str(error)


@pytest.mark.parametrize(
    "doc",
    [
        "~: x\n",
        "null: x\n",
        "true: x\n",
        "? [a, b]\n: x\n",
        "? {k: v}\n: x\n",
    ],
)
def test_non_text_keys_are_rejected(doc):
    error = _error(doc)
    assert error.code == "E001"
    assert "keys must be text" in str(error)


def test_numeric_looking_keys_are_text():
    assert load_yaml("2021: x\n0123: y\n") == {"2021": "x", "0123": "y"}


# ── Document shape (E003) and multiple documents ──────────────────────────────


@pytest.mark.parametrize("doc", ["", "   \n", "# only a comment\n", "---\n", "~\n"])
def test_empty_documents(doc):
    error = _error(doc)
    assert error.code == "E003"
    assert "empty" in str(error)


@pytest.mark.parametrize("doc", ["- a\n- b\n", "just text\n", "123\n", "true\n"])
def test_top_level_must_be_a_mapping(doc):
    error = _error(doc)
    assert error.code == "E003"
    assert "top level must be a mapping" in str(error)


def test_multiple_documents_are_rejected():
    error = _error("a: 1\n---\nb: 2\n")
    assert error.code == "E001"
    assert "more than one YAML document" in str(error)
    assert error.line == 2


# ── Syntax errors: position only, never source text ──────────────────────────


@pytest.mark.parametrize(
    ("doc", "line"),
    [
        (f'a: ok\nreal: "{SECRET}\nb: c\n', 4),  # unclosed quote: reported where the scan ends
        (f"a:\n  b: {SECRET}\n c: {SECRET}\n", 3),  # bad indentation
        (f"a:\n\tb: {SECRET}\n", 2),  # tab indentation
        (f"a: {{real: {SECRET}\n", 2),  # unclosed flow mapping
        (f"a: [{SECRET}, x\n", 2),  # unclosed flow sequence
        (f"real: {SECRET}: nested\n", 1),  # mapping value where not allowed
    ],
)
def test_syntax_errors_report_position_without_source_text(doc, line):
    error = _error(doc)
    assert error.code == "E001"
    assert error.line == line
    assert error.column is not None
    message = str(error)
    for fragment in ("Jane", "9876543210", "real", "nested"):
        assert fragment not in message


def test_control_character_is_rejected_without_echo():
    error = _error(f"a: {SECRET}\x07\n")
    assert error.code == "E001"
    assert "invalid character" in str(error)
    assert "Jane" not in str(error)


# ── Encoding and size ─────────────────────────────────────────────────────────


def test_bytes_are_decoded_as_utf8():
    assert load_yaml("bn: রাম\n".encode()) == {"bn": "রাম"}


def test_leading_bom_is_ignored_for_bytes_and_text():
    assert load_yaml((BOM + "a: b\n").encode()) == {"a": "b"}
    assert load_yaml(BOM + "a: b\n") == {"a": "b"}


def test_invalid_utf8_reports_byte_offset_only():
    error = _error(b"a: Jane\xff\xfeDoe\n")
    assert error.code == "E001"
    assert "not valid UTF-8 (byte offset 7)" in str(error)
    assert "Jane" not in str(error)


def test_oversized_bytes_are_rejected_before_parsing():
    error = _error(b"a: " + b"x" * MAX_BYTES)
    assert error.code == "E001"
    assert "larger than" in str(error)


def test_oversized_text_is_rejected():
    assert "larger than" in str(_error("a: " + "x" * MAX_BYTES))


def test_exactly_max_bytes_is_allowed():
    doc = "a: " + "x" * (MAX_BYTES - len("a: \n")) + "\n"
    assert len(doc.encode()) == MAX_BYTES
    assert load_yaml(doc)["a"].startswith("xxx")


# ── The error type ────────────────────────────────────────────────────────────


def test_error_is_a_validation_failure_with_exit_code_1():
    error = _error("a: 1\na: 2\n")
    assert isinstance(error, ValidationFailed)
    assert error.exit_code is ExitCode.FINDINGS


def test_error_without_position():
    error = PersonaFormatError("E003", "the file is empty; expected a mapping")
    assert str(error) == "E003 the file is empty; expected a mapping"
    assert error.line is None
    assert error.column is None


@pytest.mark.parametrize("doc", [f'real: "{SECRET}\n', "a: 1\na: 2\n", "a: !!int 5\n"])
def test_pyyaml_exception_is_not_chained(doc):
    """PyYAML errors quote source lines and their marks hold the whole document."""
    error = _error(doc)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert "Jane" not in str(error)


@pytest.mark.parametrize(
    "doc",
    [
        "a: !!int 5\n",
        "a: !!float 1.5\n",
        "a: !!timestamp 2001-03-14\n",
        "a: !!binary aGVsbG8=\n",
        "a: !!set {x, y}\n",
        "a: !!omap [x: 1]\n",
        "a: !!pairs [x: 1]\n",
        "a: !!bool yes\n",  # explicit bool must still be true/false
        "a: !!null nothing\n",
        "a: !!merge x\n",
        "a: !!value x\n",
    ],
)
def test_explicit_non_text_tags_are_rejected(doc):
    error = _error(doc)
    assert error.code == "E001"
    assert "unsupported value or tag" in str(error)


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        ("a: !!bool true\n", True),
        ("a: !!null ~\n", None),
        ("a: !!seq [x]\n", ["x"]),
        ("a: !!map {x: y}\n", {"x": "y"}),
    ],
)
def test_explicit_core_tags_with_valid_values_are_allowed(doc, expected):
    assert load_yaml(doc)["a"] == expected


# ── Properties ────────────────────────────────────────────────────────────────

# Printable text only: PyYAML itself does not round-trip raw line-break characters such as NEL
# (U+0085) or control characters (its reader rejects them), so they are out of scope here and
# covered by the "never crashes" properties below.
printable = st.characters(
    blacklist_categories=("Cc", "Cs", "Zl", "Zp"), blacklist_characters=chr(0x85)
)
text_values = st.text(alphabet=printable, max_size=40)


@given(
    st.dictionaries(st.text(alphabet=printable, min_size=1, max_size=20), text_values, max_size=8)
)
def test_round_trip_of_text_mappings(mapping):
    """Anything safe_dump writes as text comes back as exactly the same text."""
    if not mapping:
        return
    assert load_yaml(yaml.safe_dump(mapping, allow_unicode=True)) == mapping


@given(st.text(max_size=200))
def test_never_raises_anything_but_persona_format_error(text):
    try:
        result = load_yaml(text)
    except PersonaFormatError:
        return
    assert isinstance(result, dict)


@given(st.binary(max_size=200))
def test_arbitrary_bytes_never_crash(data):
    with contextlib.suppress(PersonaFormatError):
        load_yaml(data)


TOKEN = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", min_size=8, max_size=16
)


@given(
    TOKEN,
    st.sampled_from(['real: "{t}\n', "a:\n  b: {t}\n c: {t}\n", "a: [{t}\n", "{t}: x\n{t}: y\n"]),
)
def test_error_messages_never_contain_document_text(token, template):
    error = _error(template.format(t=token))
    assert token not in str(error)
