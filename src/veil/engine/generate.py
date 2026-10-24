"""Shape-preserving fakes for FPE/SHIFT fields left empty (spec v0.2 §5.6, M1.6).

Every random choice comes from a deterministic stream: HMAC-SHA256(seed, role, canon(real),
attempt). With the same vault seed the same real value always gets the same fake; without the
seed nobody can recompute it. Generators by role:

    phone          country code and first national digit kept (+91 9…), rest random
    aadhaar        12 digits, first 2-9, Verhoeff check digit
    card           same length and first digit, Luhn check digit (4-digit "last four" stays 4)
    pan            AAAAA9999A; 4th letter (holder type) kept, 5th = fake surname initial
    ifsc           bank code (first 4 letters) and the 0 kept, branch random
    orcid          0000-000X prefix kept, mod 11-2 check digit
    roll_number    a leading 19xx/20xx year kept
    anything else  digits → digits (no new leading zero), letters → letters (case kept),
                   separators kept, a short letter prefix ("E-", "K") kept
    date (SHIFT)   moved by `date_shift_days` (or a stored random shift when that is 0)

`variants_for` gives the other ways people write the same value (phone without spaces or with
the country code, dates in other formats), index-aligned real ↔ fake, so they all translate.
"""

import hashlib
import hmac
import re
import string
from collections.abc import Iterator
from datetime import date, timedelta

YEAR_PREFIX = re.compile(r"^(19|20)\d\d")
LETTER_PREFIX = re.compile(r"^[A-Za-z]{1,3}(?=[^A-Za-z]|$)")
DATE_FORMATS = (  # (regex, parser order) for the declared value
    (re.compile(r"^(\d{1,2})([/.-])(\d{1,2})\2(\d{4})$"), "dmy"),
    (re.compile(r"^(\d{4})([/.-])(\d{1,2})\2(\d{1,2})$"), "ymd"),
)
MONTHS = (
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
)  # fmt: skip


class Stream:
    """Deterministic random digits/letters from HMAC(seed, label, counter)."""

    def __init__(self, seed: bytes, label: str) -> None:
        self._seed = seed
        self._label = label.encode("utf-8")
        self._counter = 0
        self._pool = b""

    def _byte(self) -> int:
        if not self._pool:
            self._pool = hmac.new(
                self._seed, self._label + self._counter.to_bytes(8, "big"), hashlib.sha256
            ).digest()
            self._counter += 1
        value, self._pool = self._pool[0], self._pool[1:]
        return value

    def below(self, n: int) -> int:
        """Uniform in [0, n): enough bytes to cover n, rejection sampling (no modulo bias)."""
        if n < 1:
            raise ValueError("n must be positive")
        width = 1
        while 256**width < n:
            width += 1
        space = 256**width
        limit = space - space % n
        while True:
            value = 0
            for _ in range(width):
                value = value * 256 + self._byte()
            if value < limit:
                return value % n

    def digit(self, low: int = 0) -> str:
        return str(low + self.below(10 - low))

    def letter(self, upper: bool) -> str:
        return (string.ascii_uppercase if upper else string.ascii_lowercase)[self.below(26)]


def generate(role: str, real: str, seed: bytes, attempt: int, *, surname_initial: str = "") -> str:
    """One candidate fake for `real` (the caller retries with attempt+1 on collisions)."""
    stream = Stream(seed, f"gen\0{role}\0{real}\0{attempt}")
    match role:
        case "phone":
            return _phone(real, stream)
        case "aadhaar":
            return _aadhaar(real, stream)
        case "card":
            return _card(real, stream)
        case "pan":
            return _pan(real, stream, surname_initial)
        case "ifsc":
            return _ifsc(real, stream)
        case "orcid":
            return _orcid(real, stream)
        case "roll_number":
            year = YEAR_PREFIX.match(real)
            keep = year.end() if year else 0
            return real[:keep] + _shape(real[keep:], stream, keep_prefix=False)
        case _:
            return _shape(real, stream, keep_prefix=True)


# ── generic shape ─────────────────────────────────────────────────────────────


def _shape(text: str, stream: Stream, *, keep_prefix: bool) -> str:
    prefix = LETTER_PREFIX.match(text) if keep_prefix else None
    keep = prefix.end() if prefix and any(c.isdigit() for c in text) else 0
    out = [text[:keep]]
    first_digit = True
    for ch in text[keep:]:
        if ch.isdigit() and ch.isascii():
            out.append(stream.digit(1 if first_digit and ch != "0" else 0))
            first_digit = False
        elif ch.isascii() and ch.isalpha():
            out.append(stream.letter(ch.isupper()))
        else:
            out.append(ch)
            if not ch.isalnum():
                first_digit = True
    return "".join(out)


def _digits_into(template: str, digits: str) -> str:
    """Put `digits` into the digit positions of `template` (keeps its separators)."""
    it = iter(digits)
    return "".join(next(it) if c.isdigit() else c for c in template)


# ── phone ─────────────────────────────────────────────────────────────────────


def _phone(real: str, stream: Stream) -> str:
    digits = re.sub(r"\D", "", real)
    _, national = split_phone(real)
    if not national:
        return _shape(real, stream, keep_prefix=False)
    keep = len(digits) - len(national) + 1  # country code or trunk 0, plus the first digit
    return _digits_into(real, digits[:keep] + "".join(stream.digit() for _ in digits[keep:]))


def split_phone(real: str) -> tuple[str, str]:
    """(country code digits, national digits). "+91 90000 00001" → ("91", "9000000001")."""
    digits = re.sub(r"\D", "", real)
    stripped = real.strip()
    if stripped.startswith("+"):
        head = re.match(r"\+\s*(\d{1,3})", stripped)
        if head and len(digits) > len(head.group(1)) + 6:
            return head.group(1), digits[len(head.group(1)) :]
    if digits.startswith("0") and len(digits) == 11:
        return "", digits[1:]
    return "", digits


# ── checksummed IDs ───────────────────────────────────────────────────────────

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5), (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7), (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3), (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)  # fmt: skip
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4), (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7), (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)  # fmt: skip
_VERHOEFF_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_check_digit(digits: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return str(_VERHOEFF_INV[c])


def verhoeff_valid(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def luhn_check_digit(digits: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            d -= 9 if d > 9 else 0
        total += d
    return str((10 - total % 10) % 10)


def luhn_valid(digits: str) -> bool:
    return luhn_check_digit(digits[:-1]) == digits[-1]


def orcid_check_digit(digits15: str) -> str:
    total = 0
    for ch in digits15:
        total = (total + int(ch)) * 2
    result = (12 - total % 11) % 11
    return "X" if result == 10 else str(result)


def _aadhaar(real: str, stream: Stream) -> str:
    digits = re.sub(r"\D", "", real)
    if len(digits) != 12:
        return _shape(real, stream, keep_prefix=False)
    body = stream.digit(2) + "".join(stream.digit() for _ in range(10))
    return _digits_into(real, body + verhoeff_check_digit(body))


def _card(real: str, stream: Stream) -> str:
    digits = re.sub(r"\D", "", real)
    if len(digits) < 12:  # "last four" and other fragments: plain shape
        return _shape(real, stream, keep_prefix=False)
    body = digits[0] + "".join(stream.digit() for _ in digits[1:-1])
    return _digits_into(real, body + luhn_check_digit(body))


def _pan(real: str, stream: Stream, surname_initial: str) -> str:
    if not re.fullmatch(r"[A-Za-z]{5}\d{4}[A-Za-z]", real.strip()):
        return _shape(real, stream, keep_prefix=False)
    upper = real.strip().isupper()
    initial = (surname_initial[:1] or stream.letter(True)).upper()
    chars = [
        stream.letter(True),
        stream.letter(True),
        stream.letter(True),
        real.strip()[3].upper(),  # holder type (P = person) stays
        initial if initial in string.ascii_uppercase else stream.letter(True),
        *(stream.digit() for _ in range(4)),
        stream.letter(True),
    ]
    out = "".join(chars)
    return out if upper else out.lower()


def _ifsc(real: str, stream: Stream) -> str:
    value = real.strip()
    if not re.fullmatch(r"[A-Za-z]{4}0[A-Za-z0-9]{6}", value):
        return _shape(real, stream, keep_prefix=False)
    branch = "".join(
        stream.digit() if c.isdigit() else stream.letter(c.isupper()) for c in value[5:]
    )
    return value[:5] + branch


def _orcid(real: str, stream: Stream) -> str:
    digits = re.sub(r"[^0-9Xx]", "", real)
    if len(digits) != 16:
        return _shape(real, stream, keep_prefix=False)
    body = digits[:7] + "".join(stream.digit() for _ in range(8))
    full = body + orcid_check_digit(body)
    it = iter(full)
    return "".join(next(it) if c.isalnum() else c for c in real)


# ── dates (SHIFT) ─────────────────────────────────────────────────────────────


def parse_date(text: str) -> tuple[date, str, str] | None:
    """(date, order "dmy"/"ymd", separator) for DD/MM/YYYY-like or YYYY-MM-DD-like text."""
    value = text.strip()
    for pattern, order in DATE_FORMATS:
        m = pattern.match(value)
        if not m:
            continue
        a, sep, b, c = m.group(1), m.group(2), m.group(3), m.group(4)
        try:
            if order == "dmy":
                return date(int(c), int(b), int(a)), order, sep
            return date(int(a), int(b), int(c)), order, sep
        except ValueError:
            return None
    return None


def shift_date(text: str, days: int) -> str | None:
    parsed = parse_date(text)
    if parsed is None:
        return None
    day, order, sep = parsed
    moved = day + timedelta(days=days)
    return format_date(moved, order, sep, padded=text.strip()[:2].isdigit() or order == "ymd")


def format_date(day: date, order: str, sep: str, *, padded: bool = True) -> str:
    d = f"{day.day:02d}" if padded else str(day.day)
    m = f"{day.month:02d}" if padded else str(day.month)
    return f"{d}{sep}{m}{sep}{day.year}" if order == "dmy" else f"{day.year}{sep}{m}{sep}{d}"


def random_shift(seed: bytes) -> int:
    """A stable shift (±30…365 days) for SHIFT dates when date_shift_days is 0."""
    stream = Stream(seed, "date-shift")
    magnitude = 30 + stream.below(336)
    return magnitude if stream.below(2) else -magnitude


# ── variants: other ways to write the same value ──────────────────────────────


def variants_for(role: str, real: str, fake: str) -> Iterator[tuple[str, str]]:
    """(real, fake) pairs of alternative spellings, index-aligned, besides the declared one."""
    if role == "phone":
        yield from _phone_variants(real, fake)
    elif role in ("aadhaar", "card"):
        rd, fd = re.sub(r"\D", "", real), re.sub(r"\D", "", fake)
        yield rd, fd
        if len(rd) % 4 == 0:
            yield _groups(rd, 4, " "), _groups(fd, 4, " ")
            yield _groups(rd, 4, "-"), _groups(fd, 4, "-")
    elif role == "date_of_birth":
        yield from _date_variants(real, fake)


def _phone_variants(real: str, fake: str) -> Iterator[tuple[str, str]]:
    rc, rn = split_phone(real)
    fc, fn = split_phone(fake)
    if not rn or len(rn) != len(fn):
        return
    yield rn, fn
    if rc:
        yield f"+{rc}{rn}", f"+{fc}{fn}"
        yield f"+{rc} {rn}", f"+{fc} {fn}"
        yield f"+{rc}-{rn}", f"+{fc}-{fn}"
        yield f"0{rn}", f"0{fn}"
    if len(rn) == 10:
        yield f"{rn[:5]} {rn[5:]}", f"{fn[:5]} {fn[5:]}"
        yield f"{rn[:5]}-{rn[5:]}", f"{fn[:5]}-{fn[5:]}"
        yield f"{rn[:3]}-{rn[3:6]}-{rn[6:]}", f"{fn[:3]}-{fn[3:6]}-{fn[6:]}"


def _date_variants(real: str, fake: str) -> Iterator[tuple[str, str]]:
    r, f = parse_date(real), parse_date(fake)
    if r is None or f is None:
        return
    rd, fd = r[0], f[0]
    for order, sep in (("dmy", "/"), ("dmy", "-"), ("dmy", "."), ("ymd", "-"), ("ymd", "/")):
        yield format_date(rd, order, sep), format_date(fd, order, sep)
    for render in (_long_dmy, _long_mdy, _short_dmy):
        yield render(rd), render(fd)


def _long_dmy(d: date) -> str:
    return f"{d.day} {MONTHS[d.month - 1]} {d.year}"


def _long_mdy(d: date) -> str:
    return f"{MONTHS[d.month - 1]} {d.day}, {d.year}"


def _short_dmy(d: date) -> str:
    return f"{d.day} {MONTHS[d.month - 1][:3]} {d.year}"


def _groups(digits: str, size: int, sep: str) -> str:
    return sep.join(digits[i : i + size] for i in range(0, len(digits), size))
