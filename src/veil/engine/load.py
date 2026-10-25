"""Load the engine from the encrypted store (M1.7, M1.8). Fails closed at every step.

    key → decrypt persona.age (canary checked) → decrypt the vault
        ├─ warm: persona.cache.age holds the lexicon for exactly these inputs → Engine
        └─ cold: parse → validate (any error: refuse) → flatten → generated fakes
                 (vault saved under the store lock *before* any output) → lexicon
                 (refuses on bijection errors) → Engine, and the cache is rewritten

The warm path imports neither YAML nor pydantic (ADR-0029): those imports live inside
`_build`. A cache is only ever used for the exact persona payload, vault and veil code it was
built from, so it can't hide a change that validation would have caught.

Vault saving: the first run creates a vault with a fresh random seed. If it couldn't be saved,
the next run would draw a different seed and produce different fakes for the same values,
which would link outputs to the same person in a way the persona is meant to prevent. So the
save happens before anything is printed, and an unsaved vault means no translation. Two
concurrent first runs are serialized by the lock: the second reloads whatever the first saved
and refills from it, so both use the same seed.
"""

from collections.abc import Callable

from veil.crypto import age
from veil.crypto.keystore import KeyStore
from veil.engine.cache import CacheFile, cache_key
from veil.engine.forms import Lexicon
from veil.engine.matcher import Engine
from veil.engine.vault import Vault, VaultFile
from veil.errors import ValidationFailed
from veil.persona.store import PersonaStore
from veil.timing import STAGES


def load_engine(
    keystore: KeyStore, store: PersonaStore, *, ask_passphrase: Callable[[], str] | None = None
) -> Engine:
    STAGES.mark("start+imports")
    identity = keystore.load(ask_passphrase)
    STAGES.mark("key")
    payload = store.load(identity)
    vault_file = VaultFile(store.directory)
    vault = vault_file.load(identity)
    STAGES.mark("decrypt")

    cache = CacheFile(store.directory)
    if not vault.dirty:  # a vault that still needs saving can't be the one a cache was built on
        cached = cache.load(identity, cache_key(payload.data, vault.to_bytes()))
        if cached is not None:
            STAGES.mark("cache")
            engine = Engine(cached)
            STAGES.mark("index")
            return engine

    lexicon, vault = _build(payload.data, keystore, store, identity, vault_file, vault)
    STAGES.mark("build")
    cache.save(lexicon, cache_key(payload.data, vault.to_bytes()), recipient=identity.recipient)
    engine = Engine(lexicon)
    STAGES.mark("index")
    return engine


def _build(
    data: bytes,
    keystore: KeyStore,
    store: PersonaStore,
    identity: age.Identity,
    vault_file: VaultFile,
    vault: Vault,
) -> tuple[Lexicon, Vault]:
    """The cold path: everything that needs the persona schema (imported only here)."""
    from veil.engine.fill import fill_generated
    from veil.engine.lexicon import build_lexicon
    from veil.errors import PersonaFormatError
    from veil.persona.entities import flatten
    from veil.persona.schema import PersonaSchemaError, parse_persona
    from veil.persona.validate import validate
    from veil.persona.yamlio import load_yaml

    try:
        persona = parse_persona(load_yaml(data))  # parsed once, then validated
    except (PersonaFormatError, PersonaSchemaError):
        raise _invalid(1) from None
    errors = validate(persona).errors
    if errors:
        raise _invalid(len(errors))
    flat = flatten(persona)
    filled = fill_generated(flat, vault)
    if vault.dirty:
        with store.lock():
            vault = vault_file.load(identity)  # someone may have saved one meanwhile
            filled = fill_generated(flat, vault)
            if vault.dirty:
                vault_file.save(vault, identity, recipient=keystore.recipient())
    return build_lexicon(filled), vault


def _invalid(count: int) -> ValidationFailed:
    return ValidationFailed(
        f"the encrypted persona has {count} error(s); run `veil persona check` for the field paths"
    )
