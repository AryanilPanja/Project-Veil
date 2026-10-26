"""engine/generate.py (M1.6): shape-preserving, checksum-valid, deterministic fakes."""

import re
from datetime import date

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from veil.engine import generate as g

SEED = b"\x01" * 32
OTHER_SEED = b"\x02" * 32


def shape(text: str) -> str:
    return re.sub(r"[a-z]", "a", re.sub(r"[A-Z]", "A", re.sub(r"\d", "9", text)))


class TestStream:
    def test_deterministic(self):
        a, b = g.Stream(SEED, "x"), g.Stream(SEED, "x")
        assert [a.digit() for _ in range(50)] == [b.digit() for _ in range(50)]

    def test_label_and_seed_matter(self):
        base = [g.Stream(SEED, "x").digit() for _ in range(1)]
        runs = {
            "".join(g.Stream(s, lab).digit() for _ in range(20))
            for s in (SEED, OTHER_SEED)
            for lab in ("x", "y")
        }
        assert len(runs) == 4
        assert base

    def test_unbiased_enough(self):
        stream = g.Stream(SEED, "dist")
        counts = [0] * 10
        for _ in range(5000):
            counts[int(stream.digit())] += 1
        assert min(counts) > 400

    @pytest.mark.parametrize("n", [1, 2, 10, 26, 255, 256, 257, 336, 1000, 70000])
    def test_below_any_range(self, n):
        stream = g.Stream(SEED, f"below{n}")
        values = [stream.below(n) for _ in range(300)]
        assert all(0 <= v < n for v in values)

    def test_below_rejects_non_positive(self):
        with pytest.raises(ValueError, match="positive"):
            g.Stream(SEED, "x").below(0)

    def test_digit_low_bound_and_letters(self):
        stream = g.Stream(SEED, "z")
        assert all(stream.digit(2) not in "01" for _ in range(200))
        assert all(stream.letter(True).isupper() for _ in range(50))
        assert all(stream.letter(False).islower() for _ in range(50))


class TestChecksums:
    @pytest.mark.parametrize("valid", ["234123412346", "496858245152"])
    def test_verhoeff_known_values(self, valid):
        assert g.verhoeff_valid(valid)
        assert g.verhoeff_check_digit(valid[:-1]) == valid[-1]

    def test_verhoeff_detects_single_digit_errors(self):
        number = "234123412346"
        for i in range(len(number)):
            wrong = number[:i] + str((int(number[i]) + 1) % 10) + number[i + 1 :]
            assert not g.verhoeff_valid(wrong)

    @pytest.mark.parametrize("valid", ["4111111111111111", "5500005555555559", "79927398713"])
    def test_luhn_known_values(self, valid):
        assert g.luhn_valid(valid)

    @pytest.mark.parametrize(
        "orcid", ["0000-0002-1825-0097", "0000-0001-5109-3700", "0000-0002-1694-233X"]
    )
    def test_orcid_documented_examples(self, orcid):
        digits = orcid.replace("-", "")
        assert g.orcid_check_digit(digits[:15]) == digits[15]


class TestGenerators:
    def test_phone_keeps_country_code_series_and_layout(self):
        fake = g.generate("phone", "+91 90000 00001", SEED, 0)
        assert fake.startswith("+91 9")
        assert shape(fake) == shape("+91 90000 00001")
        assert fake != "+91 90000 00001"

    @pytest.mark.parametrize(
        "real", ["9000000001", "09000000001", "90000-00001", "+1 (415) 555-0100"]
    )
    def test_phone_layouts(self, real):
        fake = g.generate("phone", real, SEED, 0)
        assert shape(fake) == shape(real)
        digits_r, digits_f = re.sub(r"\D", "", real), re.sub(r"\D", "", fake)
        _, national = g.split_phone(real)
        keep = len(digits_r) - len(national) + 1
        assert digits_f[:keep] == digits_r[:keep]

    @pytest.mark.parametrize("real", ["2341 2341 2346", "234123412346", "2341-2341-2346"])
    def test_aadhaar(self, real):
        fake = g.generate("aadhaar", real, SEED, 0)
        assert shape(fake) == shape(real)
        digits = re.sub(r"\D", "", fake)
        assert digits[0] in "23456789"
        assert g.verhoeff_valid(digits)

    @pytest.mark.parametrize("real", ["4111 1111 1111 1111", "5500005555555559", "1234"])
    def test_card(self, real):
        fake = g.generate("card", real, SEED, 0)
        assert shape(fake) == shape(real)
        digits = re.sub(r"\D", "", fake)
        if len(digits) >= 12:
            assert g.luhn_valid(digits)
            assert digits[0] == re.sub(r"\D", "", real)[0]

    def test_pan(self):
        fake = g.generate("pan", "ABCPD1234E", SEED, 0, surname_initial="T")
        assert re.fullmatch(r"[A-Z]{3}PT\d{4}[A-Z]", fake)

    def test_pan_lowercase_and_malformed(self):
        assert g.generate("pan", "abcpd1234e", SEED, 0, surname_initial="t")[4] == "t"
        assert shape(g.generate("pan", "AB12", SEED, 0)) == shape("AB12")

    def test_ifsc(self):
        fake = g.generate("ifsc", "SBIN0001234", SEED, 0)
        assert fake.startswith("SBIN0")
        assert shape(fake) == shape("SBIN0001234")

    def test_orcid_generator(self):
        fake = g.generate("orcid", "0000-0002-1825-0097", SEED, 0)
        assert fake.startswith("0000-000")
        digits = fake.replace("-", "")
        assert g.orcid_check_digit(digits[:15]) == digits[15]

    def test_roll_number_keeps_year(self):
        fake = g.generate("roll_number", "2024701001", SEED, 0)
        assert fake.startswith("2024")
        assert len(fake) == 10
        assert fake.isdigit()

    @pytest.mark.parametrize(
        "real", ["E-1001", "K1234567", "EPIC/123/456", "MH12 2019 0001234", "a1-B2"]
    )
    def test_generic_shape_and_prefix(self, real):
        fake = g.generate("passport", real, SEED, 0)
        assert shape(fake) == shape(real)
        prefix = g.LETTER_PREFIX.match(real)
        if prefix and any(c.isdigit() for c in real):
            assert fake.startswith(prefix.group())

    def test_no_new_leading_zero(self):
        for attempt in range(100):
            assert not g.generate("employee_id", "71234", SEED, attempt).startswith("0")

    def test_non_ascii_digits_and_letters_are_kept(self):
        real = "आईडी-१२३"  # Devanagari letters and digits: left as they are
        assert g.generate("passport", real, SEED, 0) == real

    def test_deterministic_and_attempt_dependent(self):
        a = g.generate("passport", "K1234567", SEED, 0)
        assert g.generate("passport", "K1234567", SEED, 0) == a
        assert g.generate("passport", "K1234567", SEED, 1) != a
        assert g.generate("passport", "K1234567", OTHER_SEED, 0) != a


class TestDates:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("14/03/2001", (date(2001, 3, 14), "dmy", "/")),
            ("4-3-2001", (date(2001, 3, 4), "dmy", "-")),
            ("2001-03-14", (date(2001, 3, 14), "ymd", "-")),
            ("14.03.2001", (date(2001, 3, 14), "dmy", ".")),
        ],
    )
    def test_parse(self, text, expected):
        assert g.parse_date(text) == expected

    @pytest.mark.parametrize("text", ["31/02/2001", "14/03/01", "March 14", "", "14/03-2001"])
    def test_unparseable(self, text):
        assert g.parse_date(text) is None

    def test_shift_keeps_format(self):
        assert g.shift_date("14/03/2001", -37) == "05/02/2001"
        assert g.shift_date("2001-03-14", 1) == "2001-03-15"
        assert g.shift_date("4/3/2001", 1) == "5/3/2001"
        assert g.shift_date("28/02/2004", 1) == "29/02/2004"  # leap year
        assert g.shift_date("31/12/2001", 1) == "01/01/2002"

    def test_random_shift_is_stable_and_bounded(self):
        assert g.random_shift(SEED) == g.random_shift(SEED)
        shifts = {g.random_shift(bytes([i]) * 32) for i in range(50)}
        assert all(30 <= abs(s) <= 365 for s in shifts)
        assert any(s < 0 for s in shifts)
        assert any(s > 0 for s in shifts)


class TestVariants:
    def test_phone_variants_are_aligned(self):
        pairs = list(g.variants_for("phone", "+91 90000 00001", "+91 98246 38262"))
        assert ("9000000001", "9824638262") in pairs
        assert ("+919000000001", "+919824638262") in pairs
        assert ("90000 00001", "98246 38262") in pairs

    def test_date_variants(self):
        pairs = dict(g.variants_for("date_of_birth", "14/03/2001", "05/02/2001"))
        assert pairs["2001-03-14"] == "2001-02-05"
        assert pairs["14 March 2001"] == "5 February 2001"
        assert pairs["March 14, 2001"] == "February 5, 2001"
        assert pairs["14 Mar 2001"] == "5 Feb 2001"

    # Sweep 2026-10-26: common ways people write a phone or a date that used to pass through.
    @pytest.mark.parametrize(
        ("real", "fake"),
        [
            ("919000000001", "919824638262"),
            ("00919000000001", "00919824638262"),
            ("+91 900 000 0001", "+91 982 463 8262"),
            ("+91-90000-00001", "+91-98246-38262"),
            ("900.000.0001", "982.463.8262"),
            ("90000.00001", "98246.38262"),
            ("(900) 000-0001", "(982) 463-8262"),
            ("91 90000 00001", "91 98246 38262"),
            ("09000000001", "09824638262"),
        ],
    )
    def test_more_phone_variants(self, real, fake):
        pairs = dict(g.variants_for("phone", "+91 90000 00001", "+91 98246 38262"))
        assert pairs[real] == fake

    def test_phone_variants_have_unique_reals_and_fakes(self):
        pairs = list(g.variants_for("phone", "+91 90000 00001", "+91 98246 38262"))
        assert len({r for r, _ in pairs}) == len(pairs)
        assert len({f for _, f in pairs}) == len(pairs)
        assert all(len(re.sub(r"\D", "", r)) == len(re.sub(r"\D", "", f)) for r, f in pairs)

    def test_phone_without_country_code(self):
        pairs = dict(g.variants_for("phone", "90000 00001", "98246 38262"))
        assert pairs["900-000-0001"] == "982-463-8262"
        assert not any(r.startswith(("+", "00")) for r in pairs)

    def test_phone_of_other_length_gets_no_grouping(self):
        pairs = dict(g.variants_for("phone", "+44 2079460000", "+44 2079461111"))
        assert pairs["2079460000"] == "2079461111"
        assert "20794 60000" in pairs
        assert "(207) 946-0000" in pairs
        # Too short to split off a country code: only the bare digits.
        assert list(g.variants_for("phone", "+1 555123", "+1 555987")) == [("1555123", "1555987")]

    def test_phone_lengths_differ_gives_nothing(self):
        assert list(g.variants_for("phone", "+91 90000 00001", "+91 9824638")) == []

    @pytest.mark.parametrize(
        ("real", "fake"),
        [
            ("14/3/2001", "5/2/2001"),
            ("14-3-2001", "5-2-2001"),
            ("14.3.2001", "5.2.2001"),
            ("2001-3-14", "2001-2-5"),
            ("14032001", "05022001"),
            ("20010314", "20010205"),
            ("14th March 2001", "5th February 2001"),
            ("14th of March 2001", "5th of February 2001"),
            ("March 14th, 2001", "February 5th, 2001"),
            ("March 14 2001", "February 5 2001"),
            ("Mar 14, 2001", "Feb 5, 2001"),
            ("14-Mar-2001", "5-Feb-2001"),
            ("14 March, 2001", "5 February, 2001"),
        ],
    )
    def test_more_date_variants(self, real, fake):
        pairs = dict(g.variants_for("date_of_birth", "14/03/2001", "05/02/2001"))
        assert pairs[real] == fake

    def test_month_first_only_when_unambiguous(self):
        # 05/02 could be read either way: no month-first forms for that pair.
        pairs = dict(g.variants_for("date_of_birth", "14/03/2001", "05/02/2001"))
        assert "03/14/2001" not in pairs
        pairs = dict(g.variants_for("date_of_birth", "14/03/2001", "23/02/2001"))
        assert pairs["03/14/2001"] == "02/23/2001"
        assert pairs["3/14/2001"] == "2/23/2001"

    @pytest.mark.parametrize(
        ("n", "word"),
        [(1, "1st"), (2, "2nd"), (3, "3rd"), (4, "4th"), (11, "11th"), (12, "12th"),
         (13, "13th"), (21, "21st"), (22, "22nd"), (23, "23rd"), (31, "31st")],
    )  # fmt: skip
    def test_ordinal(self, n, word):
        assert g._ordinal(n) == word

    @pytest.mark.parametrize(
        ("real", "fake"),
        [("01/01/2001", "25/12/2000"), ("12/11/1999", "05/02/2001"), ("31/12/1999", "29/02/2000")],
    )
    def test_date_variants_never_repeat_a_form(self, real, fake):
        # Where one side has no short form (25/12 padded or not), the second pair is dropped
        # rather than mapping one real or one fake to two counterparts.
        pairs = list(g.variants_for("date_of_birth", real, fake))
        assert len({r for r, _ in pairs}) == len(pairs)
        assert len({f for _, f in pairs}) == len(pairs)

    def test_card_variants(self):
        pairs = dict(g.variants_for("card", "4111 1111 1111 1111", "4539 1488 0343 6467"))
        assert pairs["4111111111111111"] == "4539148803436467"
        assert pairs["4111-1111-1111-1111"] == "4539-1488-0343-6467"

    def test_other_roles_have_none(self):
        assert list(g.variants_for("passport", "K1234567", "K7654321")) == []


@settings(max_examples=300)
@given(st.text(alphabet="0123456789ABCXYZabcxyz-/. ", min_size=1, max_size=16), st.integers(0, 20))
def test_property_generic_shape(real, attempt):
    fake = g.generate("voter_id", real, SEED, attempt)
    assert shape(fake) == shape(real)
    assert g.generate("voter_id", real, SEED, attempt) == fake


@settings(max_examples=200)
@given(st.text(alphabet="0123456789", min_size=11, max_size=11), st.integers(0, 10))
def test_property_aadhaar_always_valid(body, attempt):
    real = body + g.verhoeff_check_digit(body)
    fake = g.generate("aadhaar", real, SEED, attempt)
    assert g.verhoeff_valid(fake)
    assert fake[0] in "23456789"
