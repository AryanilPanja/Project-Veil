"""crypto/age.py: pyrage wrapper. Round trips, every failure mapped to a value-free VeilError."""

import pyrage
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pyrage import x25519

from veil.crypto import age
from veil.errors import DecryptFailed, KeyUnavailable, VeilError
from veil.exitcodes import ExitCode

SECRET_TEXT = b"Jane Doe, roll 2021101001, jane.doe@uni.example"

# One identity for the module: generation is cheap, but fixed keys make failures reproducible.
ID = age.generate_identity()
OTHER = age.generate_identity()
FIXED_CT = age.encrypt(SECRET_TEXT, ID.recipient)


class TestIdentity:
    def test_generate_gives_matching_pair(self):
        identity = age.generate_identity()
        assert identity.secret.startswith("AGE-SECRET-KEY-1")
        assert identity.recipient.startswith("age1")
        assert age.parse_identity(identity.secret).recipient == identity.recipient

    def test_generated_identities_differ(self):
        assert len({age.generate_identity().secret for _ in range(20)}) == 20

    def test_repr_and_str_hide_the_secret(self):
        assert ID.secret not in repr(ID)
        assert ID.secret not in str(ID)
        assert ID.recipient in repr(ID)

    def test_secret_not_in_format_or_fstring(self):
        assert ID.secret not in f"{ID}"
        assert ID.secret not in f"{ID!r}"

    @pytest.mark.parametrize("wrap", ["  {}  ", "{}\n", "\n{}\r\n", "\t{}"])
    def test_parse_ignores_surrounding_whitespace(self, wrap):
        assert age.parse_identity(wrap.format(ID.secret)) == ID

    def test_parse_accepts_lower_case(self):
        assert age.parse_identity(ID.secret.lower()).recipient == ID.recipient

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "   ",
            "AGE-SECRET-KEY-1",
            "not a key",
            "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "AGE-SECRET-KEY-1" + "Q" * 58,
            "जेन",
        ],
    )
    def test_parse_rejects_garbage_as_key_unavailable(self, text):
        with pytest.raises(KeyUnavailable) as info:
            age.parse_identity(text)
        assert info.value.exit_code == ExitCode.KEY_UNAVAILABLE
        assert info.value.__cause__ is None
        assert info.value.__suppress_context__

    def test_truncated_secret_is_rejected(self):
        with pytest.raises(KeyUnavailable):
            age.parse_identity(ID.secret[:-3])

    def test_error_never_echoes_the_input(self):
        bogus = "AGE-SECRET-KEY-1JANEDOEXYZ"
        with pytest.raises(KeyUnavailable) as info:
            age.parse_identity(bogus)
        assert "JANEDOE" not in str(info.value)


class TestRecipient:
    def test_parse_valid(self):
        assert age.parse_recipient(ID.recipient) == ID.recipient

    def test_parse_normalises_case_and_whitespace(self):
        assert age.parse_recipient("  " + ID.recipient.upper() + "\n") == ID.recipient

    @pytest.mark.parametrize("text", ["", "age1", "age1nope", ID.secret, "ssh-ed25519 AAAA", "x"])
    def test_parse_rejects_garbage(self, text):
        with pytest.raises(DecryptFailed) as info:
            age.parse_recipient(text)
        assert info.value.exit_code == ExitCode.DECRYPT_FAILED

    def test_secret_key_is_not_accepted_as_recipient_and_not_echoed(self):
        with pytest.raises(DecryptFailed) as info:
            age.parse_recipient(ID.secret)
        assert ID.secret not in str(info.value)


class TestX25519:
    def test_round_trip(self):
        assert age.decrypt(age.encrypt(SECRET_TEXT, ID.recipient), ID) == SECRET_TEXT

    def test_ciphertext_is_standard_age_and_hides_plaintext(self):
        ct = age.encrypt(SECRET_TEXT, ID.recipient)
        assert age.is_age(ct)
        assert b"Jane" not in ct
        assert b"2021101001" not in ct

    def test_interoperates_with_plain_pyrage(self):
        ct = age.encrypt(SECRET_TEXT, ID.recipient)
        assert pyrage.decrypt(ct, [x25519.Identity.from_str(ID.secret)]) == SECRET_TEXT
        ct2 = pyrage.encrypt(SECRET_TEXT, [x25519.Recipient.from_str(ID.recipient)])
        assert age.decrypt(ct2, ID) == SECRET_TEXT

    def test_encryption_is_randomised(self):
        assert age.encrypt(b"x", ID.recipient) != age.encrypt(b"x", ID.recipient)

    @pytest.mark.parametrize(
        "data",
        [b"", b"\x00", "मराठी নাম தமிழ் ✓".encode(), bytes(range(256)), b"x" * (1 << 20)],
    )
    def test_round_trip_edge_payloads(self, data):
        assert age.decrypt(age.encrypt(data, ID.recipient), ID) == data

    @settings(max_examples=50)
    @given(st.binary(max_size=2048))
    def test_round_trip_property(self, data):
        assert age.decrypt(age.encrypt(data, ID.recipient), ID) == data

    def test_wrong_key(self):
        with pytest.raises(DecryptFailed, match="wrong key") as info:
            age.decrypt(age.encrypt(SECRET_TEXT, ID.recipient), OTHER)
        assert info.value.exit_code == ExitCode.DECRYPT_FAILED

    def test_not_age_at_all(self):
        with pytest.raises(DecryptFailed, match="not an age-encrypted file"):
            age.decrypt(SECRET_TEXT, ID)

    def test_empty_input(self):
        with pytest.raises(DecryptFailed):
            age.decrypt(b"", ID)

    def test_header_only(self):
        with pytest.raises(DecryptFailed):
            age.decrypt(age.AGE_MAGIC, ID)

    @pytest.mark.parametrize("cut", [1, 16, 100])
    def test_truncated(self, cut):
        ct = age.encrypt(SECRET_TEXT, ID.recipient)
        with pytest.raises(DecryptFailed):
            age.decrypt(ct[:-cut], ID)

    def test_extra_trailing_bytes(self):
        ct = age.encrypt(SECRET_TEXT, ID.recipient)
        with pytest.raises(DecryptFailed):
            age.decrypt(ct + b"\x00", ID)

    @settings(max_examples=60)
    @given(st.data())
    def test_any_single_bit_flip_is_detected(self, data):
        ct = bytearray(FIXED_CT)  # fixed, so every example draws from the same length
        pos = data.draw(st.integers(len(age.AGE_MAGIC), len(ct) - 1))
        ct[pos] ^= 1 << data.draw(st.integers(0, 7))
        with pytest.raises(DecryptFailed):
            age.decrypt(bytes(ct), ID)

    def test_invalid_identity_object(self):
        broken = age.Identity(secret="AGE-SECRET-KEY-1BROKEN", recipient=ID.recipient)  # noqa: S106
        with pytest.raises(KeyUnavailable):
            age.decrypt(age.encrypt(b"x", ID.recipient), broken)

    def test_encrypt_to_invalid_recipient(self):
        with pytest.raises(DecryptFailed, match="not usable"):
            age.encrypt(b"x", "age1nope")

    def test_errors_never_contain_plaintext_and_drop_pyrage_cause(self):
        with pytest.raises(DecryptFailed) as info:
            age.decrypt(age.encrypt(SECRET_TEXT, ID.recipient), OTHER)
        assert "Jane" not in str(info.value)
        assert info.value.__cause__ is None
        assert info.value.__suppress_context__


@pytest.mark.slow_scrypt
class TestPassphrase:
    """Real age scrypt (~1.5 s per call), so only a few cases. Keystore tests use a fast fake."""

    def test_round_trip_and_wrong_passphrase(self):
        ct = age.passphrase_encrypt(SECRET_TEXT, "correct horse battery")
        assert age.is_age(ct)
        assert b"Jane" not in ct
        assert age.passphrase_decrypt(ct, "correct horse battery") == SECRET_TEXT
        with pytest.raises(DecryptFailed, match="wrong passphrase") as info:
            age.passphrase_decrypt(ct, "wrong horse battery")
        assert "horse" not in str(info.value)

    def test_unicode_passphrase(self):
        ct = age.passphrase_encrypt(b"k", "पासवर्ड सुरक्षित है")
        assert age.passphrase_decrypt(ct, "पासवर्ड सुरक्षित है") == b"k"

    def test_x25519_file_is_not_a_passphrase_file(self):
        with pytest.raises(DecryptFailed):
            age.passphrase_decrypt(age.encrypt(b"k", ID.recipient), "whatever123")


class TestPassphraseChecks:
    @pytest.mark.parametrize("weak", ["", "       ", "short", "1234567", "  abc   "])
    def test_too_short_is_a_usage_error(self, weak):
        with pytest.raises(VeilError) as info:
            age.passphrase_encrypt(b"x", weak)
        assert info.value.exit_code == ExitCode.USAGE
        assert weak.strip() == "" or weak.strip() not in str(info.value)

    def test_exactly_min_length_passes_check(self):
        age.check_passphrase("x" * age.MIN_PASSPHRASE)

    def test_decrypt_rejects_non_age_input_without_scrypt(self):
        with pytest.raises(DecryptFailed, match="not an age-encrypted file"):
            age.passphrase_decrypt(b"plain text", "whatever123")
