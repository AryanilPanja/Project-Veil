"""The persona canary: a random marker that exists only inside the encrypted persona (ADR-0025 §10).

`VEIL-CANARY-` + 26 base32 characters (128 random bits). The proxy, hooks and pre-commit look for
the generic pattern without needing the key: if a canary ever appears in outbound text, the
persona file itself is leaking, and the request is blocked.

`insert` puts it in two places of the YAML payload, so a truncated or partial copy still carries
one: a `veil_canary:` key right after the top-level `version:` line, and a trailing comment.
Comments and layout of the user's file are otherwise preserved byte for byte.
"""

import base64
import re
import secrets

from veil.errors import ValidationFailed

PREFIX = "VEIL-CANARY-"
PATTERN = re.compile(r"VEIL-CANARY-[A-Z2-7]{26}")
_FULL = re.compile(rf"\A{PATTERN.pattern}\Z")
_VERSION_LINE = re.compile(r"^version[ \t]*:[^\r\n]*", re.MULTILINE)
_CANARY_KEY_LINE = re.compile(r"^veil_canary[ \t]*:[^\r\n]*(?:\r?\n|\Z)", re.MULTILINE)
_CANARY_COMMENT_LINE = re.compile(
    r"^# veil_canary: VEIL-CANARY-[A-Z2-7]{26}[ \t]*(?:\r?\n|\Z)", re.MULTILINE
)
_BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"


def generate() -> str:
    token = base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
    return PREFIX + token


def is_canary(text: str) -> bool:
    return bool(_FULL.match(text))


def find_all(text: str) -> list[str]:
    return PATTERN.findall(text)


def remove(yaml_text: str) -> str:
    """Strip the canary lines `insert` adds (for showing the persona in an editor)."""
    text = _CANARY_KEY_LINE.sub("", yaml_text.removeprefix(_BOM))
    return _CANARY_COMMENT_LINE.sub("", text)


def insert(yaml_text: str, canary: str) -> str:
    """Return `yaml_text` with `canary` added (any previous canary lines are replaced)."""
    if not is_canary(canary):
        raise ValueError("not a veil canary")
    newline = "\r\n" if "\r\n" in yaml_text else "\n"
    text = remove(yaml_text)
    version = _VERSION_LINE.search(text)
    if version is None:
        raise ValidationFailed(
            "E004 the persona needs a top-level `version:` line (block style) to import"
        )
    line_end = version.end()
    text = f'{text[:line_end]}{newline}veil_canary: "{canary}"{text[line_end:]}'
    if not text.endswith(("\n", "\r\n")):
        text += newline
    return f"{text}# veil_canary: {canary}{newline}"
