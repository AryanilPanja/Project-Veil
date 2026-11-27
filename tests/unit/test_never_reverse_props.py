"""T3 / #34: Hypothesis properties for the never_reverse count (engine/).

Built from a synthetic persona in-test. Counts only: no property returns or prints a phrase.
"""

import unicodedata
from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st

from veil.engine import residue
from veil.engine.lexicon import build_lexicon
from veil.engine.matcher import Engine
from veil.persona.entities import flatten
from veil.persona.schema import parse_persona
from veil.persona.yamlio import load_yaml
from veil.text.containment import find_bounded

PERSONA = """version: "1"
person:
  first_name: { real: Jane, fake: Alex }
  last_name: { real: Doe, fake: Smith }
  full_name: { real: Jane Doe, fake: Alex Smith }
never_reverse:
  - Alex Smith
"""


@pytest.fixture(scope="module")
def lex():
    return Engine(build_lexicon(flatten(parse_persona(load_yaml(PERSONA))))).lexicon


@given(text=st.text(max_size=80))
def test_same_text_creates_nothing(lex, text):
    assert residue.never_reverse_hits(lex, text, text) == 0


@given(original=st.text(max_size=60), output=st.text(max_size=60))
def test_count_is_non_negative_and_bounded_by_output(lex, original, output):
    count = residue.never_reverse_hits(lex, original, output)
    available = sum(len(find_bounded(phrase, output)) for phrase in lex.never_reverse)
    assert 0 <= count <= available


@given(original=st.text(max_size=60), output=st.text(max_size=60))
def test_no_entries_means_zero(lex, original, output):
    empty = replace(lex, never_reverse=frozenset())
    assert residue.never_reverse_hits(empty, original, output) == 0


FRAGMENTS = st.sampled_from(
    [
        "Alex Smith",
        "Alex",
        "Smith",
        "জেন",
        "অ্যালেক্স",
        "जेन",
        "é",
        chr(0x0301),  # a lone combining mark
        chr(0x200B),  # zero-width space
        "",
        " ",
        "x_y",
        "9",
        "\n",
    ]
)


@given(parts=st.lists(FRAGMENTS, max_size=12))
def test_never_raises_on_arbitrary_text(lex, parts):
    text = "".join(parts)
    for form in (text, unicodedata.normalize("NFD", text), text.upper(), ""):
        count = residue.never_reverse_hits(lex, form, form + " Alex Smith")
        assert count >= 0
        assert count <= 1 + sum(len(find_bounded(p, form)) for p in lex.never_reverse)
