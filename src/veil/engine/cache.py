"""Encrypted compiled-lexicon cache: `<config>/persona.cache.age` (ADR-0029).

Everything after "decrypt the persona" (YAML parse, schema, validation, variants, derived
identifiers, generated fakes, lexicon) is a pure function of three inputs: the persona payload,
the generated-fakes vault, and veil's own code. So the finished lexicon is cached, encrypted to
the same recipient as the persona (same data, same protection), under a key that hashes all
three. Any change to any of them is a cache miss, and the normal path (with full validation)
runs and rewrites the cache.

The cache is strictly optional: missing, unreadable, corrupt, or written for another key, it is
ignored, never an error. It never holds anything the persona doesn't already hold.

Loading it needs only `forms.py` and `model.py`: no YAML, no pydantic (that is the point).
"""

import hashlib
import json
from functools import cache
from pathlib import Path

from veil import fsutil
from veil.crypto import age
from veil.engine.forms import Form, Lexicon, Variant
from veil.persona.model import Entity, EntityKind
from veil.persona.policy import Policy

CACHE_FILE = "persona.cache.age"
FORMAT = 2  # 2: sensitive terms + ask timeout (M2.4)
WHAT = "the lexicon cache"
MAX_CACHE_BYTES = 64 * 1024 * 1024
_CODE_DIRS = ("engine", "text", "persona")


@cache
def code_fingerprint() -> str:
    """Hash of the engine/text/persona sources: a code change invalidates every cache."""
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    for directory in _CODE_DIRS:
        for path in sorted((root / directory).glob("*.py")):
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def cache_key(payload: bytes, vault: bytes) -> str:
    digest = hashlib.sha256()
    for part in (
        str(FORMAT).encode(),
        code_fingerprint().encode(),
        hashlib.sha256(payload).digest(),
        hashlib.sha256(vault).digest(),
    ):
        digest.update(len(part).to_bytes(4, "big") + part)
    return digest.hexdigest()


# ── (de)serialization ─────────────────────────────────────────────────────────


def encode(lexicon: Lexicon, key: str) -> bytes:
    entity_ids: dict[int, int] = {}
    entities: list[dict[str, object]] = []

    def entity_ref(entity: Entity) -> int:
        ref = entity_ids.get(id(entity))
        if ref is None:
            ref = entity_ids[id(entity)] = len(entities)
            entities.append(
                {
                    "id": entity.id,
                    "sources": list(entity.sources),
                    "kind": entity.kind.value,
                    "role": entity.role,
                    "policy": entity.policy.value,
                    "reversible": entity.reversible,
                    "contexts": list(entity.contexts),
                    "allow_short": entity.allow_short,
                    "meta": [list(pair) for pair in entity.meta],
                }
            )
        return ref

    def forms(items: tuple[Form, ...]) -> list[list[object]]:
        return [
            [
                entity_ref(f.entity),
                f.variant.real,
                f.variant.fake,
                [list(pair) for pair in f.variant.spellings],
                f.variant.origin,
            ]
            for f in items
        ]

    doc = {
        "format": FORMAT,
        "key": key,
        "forward": forms(lexicon.forward),
        "reverse": forms(lexicon.reverse),
        "never_translate": sorted(lexicon.never_translate),
        "never_reverse": sorted(lexicon.never_reverse),
        "sensitive": forms(lexicon.sensitive),
        "ask_timeout_seconds": lexicon.ask_timeout_seconds,
    }
    doc["entities"] = entities
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def decode(data: bytes, key: str) -> Lexicon | None:
    """The cached lexicon, or None if it is for another key, another format, or malformed."""
    try:
        doc = json.loads(data)
        if doc.get("format") != FORMAT or doc.get("key") != key:
            return None
        entities = [_entity(e) for e in doc["entities"]]

        def forms(rows: list[list[object]]) -> tuple[Form, ...]:
            return tuple(
                Form(
                    Variant(
                        real=str(real),
                        fake=str(fake),
                        spellings=tuple((str(a), str(b)) for a, b in spellings),
                        origin=str(origin),
                    ),
                    entities[int(ref)],
                )
                for ref, real, fake, spellings, origin in rows
            )

        return Lexicon(
            forward=forms(doc["forward"]),
            reverse=forms(doc["reverse"]),
            never_translate=frozenset(str(t) for t in doc["never_translate"]),
            never_reverse=frozenset(str(t) for t in doc["never_reverse"]),
            sensitive=forms(doc["sensitive"]),
            ask_timeout_seconds=int(doc["ask_timeout_seconds"]),
        )
    except (ValueError, KeyError, TypeError, IndexError, AttributeError):
        return None


def _entity(e: dict) -> Entity:
    return Entity(
        id=str(e["id"]),
        sources=tuple(str(s) for s in e["sources"]),
        kind=EntityKind(e["kind"]),
        role=str(e["role"]),
        real_forms=(),  # the engine never needs them; the variants carry the forms
        fake_forms=(),
        policy=Policy(e["policy"]),
        needs_generation=False,
        reversible=bool(e["reversible"]),
        contexts=tuple(str(c) for c in e["contexts"]),
        allow_short=bool(e["allow_short"]),
        meta=tuple((str(k), str(v)) for k, v in e["meta"]),
    )


# ── the file ──────────────────────────────────────────────────────────────────


class CacheFile:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    @property
    def path(self) -> Path:
        return self.directory / CACHE_FILE

    def load(self, identity: age.Identity, key: str) -> Lexicon | None:
        """The cached lexicon for `key`, or None (missing, unreadable, corrupt, stale)."""
        if not self.path.exists() or self.path.is_symlink():
            return None
        try:
            data = fsutil.read_private(self.path, MAX_CACHE_BYTES, WHAT)
            return decode(age.decrypt(data, identity), key)
        except Exception:  # noqa: BLE001 - the cache is optional: any problem means "rebuild"
            return None

    def save(self, lexicon: Lexicon, key: str, *, recipient: str) -> bool:
        """Best effort: returns False instead of raising (the cache is only an optimization)."""
        try:
            fsutil.ensure_private_dir(self.directory, "the veil config directory")
            data = age.encrypt(encode(lexicon, key), recipient)
            fsutil.atomic_write(self.path, data, what=WHAT)
        except Exception:  # noqa: BLE001 - a full disk must not break translation
            return False
        return True

    def remove(self) -> bool:
        try:
            return fsutil.secure_remove(self.path, WHAT)
        except Exception:  # noqa: BLE001
            return False
