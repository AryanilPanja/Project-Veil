import pytest

from veil.text.boundary import CharClass, char_class, is_bounded, script
from veil.text.containment import contains_bounded


@pytest.mark.parametrize(
    ("ch", "expected"),
    [
        ("a", CharClass.LETTER),
        ("Z", CharClass.LETTER),
        ("ক", CharClass.LETTER),  # Bengali letter
        ("\u09be", CharClass.LETTER),  # Bengali vowel sign AA (Mc) counts as a letter
        ("\u093c", CharClass.LETTER),  # Devanagari nukta (Mn)
        ("é", CharClass.LETTER),
        ("7", CharClass.DIGIT),
        ("৭", CharClass.DIGIT),  # Bengali digit
        ("½", CharClass.DIGIT),  # vulgar fraction: Unicode category No (a number)
        ("_", CharClass.OTHER),
        ("/", CharClass.OTHER),
        (".", CharClass.OTHER),
        (" ", CharClass.OTHER),
        ("@", CharClass.OTHER),
        ("-", CharClass.OTHER),
    ],
)
def test_char_class(ch, expected):
    assert char_class(ch) is expected


@pytest.mark.parametrize(
    ("ch", "expected"),
    [("a", "LATIN"), ("ক", "BENGALI"), ("\u09be", "BENGALI"), ("क", "DEVANAGARI"), ("α", "GREEK")],
)
def test_script(ch, expected):
    assert script(ch) == expected


def test_script_of_unnamed_character():
    assert script("") == "UNKNOWN"  # private use area has no name


# (needle, haystack, bounded?): the examples in ADR-0026 and the spec, plus edge cases.
CASES = [
    # Latin names
    ("jane", "jane", True),
    ("jane", "hi jane!", True),
    ("jane", "jane04", True),  # letter next to digit
    ("jane", "jane_resume.pdf", True),  # underscore is "other"
    ("jane", "/home/jane/", True),
    ("jane", "janeResume", True),  # lower→Upper transition
    ("jane", "myJane", True),  # lower→Upper on the left
    ("jane", "janet", False),
    ("jane", "xjane", False),
    ("jane", "JANEresume", False),  # Upper→lower is not a boundary
    ("tim", "timeout", False),
    ("doe", "JaneDoe", True),
    ("jane doe", "Jane   Doe signed", True),  # whitespace collapsed
    ("jane", "ja\u200bne", True),  # invisible char inside the haystack
    ("jane", "ＪＡＮＥ", True),  # full-width haystack
    # Digits
    ("2021", "2021", True),
    ("2021", "20217", False),  # digit next to digit is never a boundary
    ("2021", "12021", False),
    ("2021", "x2021", True),
    ("2021", "2021x", True),
    ("2021", "roll-2021-07", True),
    # Edge characters that are "other"
    (".ac.in", "example.ac.in", True),
    ("ac.in", "example.ac.in", True),
    ("@example.test", "jane@example.test", True),
    # Indic scripts
    ("রাম", "রাম", True),
    ("রাম", "রামকৃষ্ণ", False),  # inside a longer Bengali word
    ("রাম", "রামা", False),  # followed by a vowel sign (combining mark = letter)
    ("রাম", "রাম ও শ্যাম", True),
    ("রাম", "abcরাম", True),  # Latin next to Bengali: script change
    ("आदित्य", "आदित्यjane", True),
    ("आदित्य", "श्रीआदित्य", False),
    # Other scripts, so behaviour is not tuned to one language
    ("ராம்", "ராம்", True),  # Tamil
    ("ராம்", "ராம்குமார்", False),  # inside a longer Tamil word
    ("علي", "hello علي", True),  # Arabic
    ("علي", "عليم", False),
    ("علي", "abcعلي", True),  # Latin next to Arabic: script change
    # Combining marks and modifier letters belong to their base letter (no false boundary)
    ("jaq", "jaq" + chr(0x0301), False),  # q + combining acute: no precomposed form
    ("hawai", "Hawai" + chr(0x02BB) + "i", False),  # okina is a modifier letter (Lm)
    ("q" + chr(0x0301), "q" + chr(0x0301) + " x", True),
    # Deliberate over-match (lower→Upper inside a surname); safe direction for privacy
    ("donald", "McDonald", True),
    ("shawn", "DeShawn", True),
    # Casefold expansion must not split characters
    ("ss", "ß", True),
    ("strasse", "Straße", True),
    ("s", "ß", False),
    # Degenerate
    ("", "anything", False),
    ("   ", "anything", False),
    ("longer than hay", "short", False),
]


@pytest.mark.parametrize(("needle", "haystack", "expected"), CASES)
def test_contains_bounded_cases(needle, haystack, expected):
    assert contains_bounded(needle, haystack) is expected


@pytest.mark.parametrize(
    ("start", "end"),
    [(-1, 2), (0, 0), (3, 2), (0, 99)],
)
def test_is_bounded_rejects_invalid_spans(start, end):
    assert is_bounded("jane", start, end) is False


def test_is_bounded_whole_text():
    assert is_bounded("jane", 0, 4) is True
