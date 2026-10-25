"""Load the engine from the encrypted store (M1.7). Fails closed at every step.

    key → decrypt persona.age → validate (any error: refuse) → flatten
        → vault: generated fakes (saved under the store lock *before* any output)
        → lexicon (refuses on bijection errors) → Engine

Vault saving: the first run creates a vault with a fresh random seed. If it couldn't be saved,
the next run would draw a different seed and produce different fakes for the same values,
which would link outputs to the same person in a way the persona is meant to prevent. So the
save happens before anything is printed, and an unsaved vault means no translation. Two
concurrent first runs are serialized by the lock: the second reloads whatever the first saved
and refills from it, so both use the same seed.
"""

from collections.abc import Callable

from veil.crypto.keystore import KeyStore
from veil.engine.fill import fill_generated
from veil.engine.lexicon import build_lexicon
from veil.engine.matcher import Engine
from veil.engine.vault import VaultFile
from veil.errors import PersonaFormatError, ValidationFailed
from veil.persona.entities import flatten
from veil.persona.schema import PersonaSchemaError, parse_persona
from veil.persona.store import PersonaStore
from veil.persona.validate import validate
from veil.persona.yamlio import load_yaml


def load_engine(
    keystore: KeyStore, store: PersonaStore, *, ask_passphrase: Callable[[], str] | None = None
) -> Engine:
    identity = keystore.load(ask_passphrase)
    payload = store.load(identity)
    try:
        persona = parse_persona(load_yaml(payload.data))  # parsed once, then validated
    except (PersonaFormatError, PersonaSchemaError):
        raise _invalid(1) from None
    errors = validate(persona).errors
    if errors:
        raise _invalid(len(errors))
    flat = flatten(persona)
    vault_file = VaultFile(store.directory)
    vault = vault_file.load(identity)
    filled = fill_generated(flat, vault)
    if vault.dirty:
        with store.lock():
            vault = vault_file.load(identity)  # someone may have saved one meanwhile
            filled = fill_generated(flat, vault)
            if vault.dirty:
                vault_file.save(vault, identity, recipient=keystore.recipient())
    return Engine(build_lexicon(filled))


def _invalid(count: int) -> ValidationFailed:
    return ValidationFailed(
        f"the encrypted persona has {count} error(s); run `veil persona check` for the field paths"
    )
