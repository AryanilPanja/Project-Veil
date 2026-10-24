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
from veil.errors import ValidationFailed
from veil.persona.check import check_bytes
from veil.persona.entities import flatten
from veil.persona.schema import parse_persona
from veil.persona.store import PersonaStore
from veil.persona.yamlio import load_yaml


def load_engine(
    keystore: KeyStore, store: PersonaStore, *, ask_passphrase: Callable[[], str] | None = None
) -> Engine:
    identity = keystore.load(ask_passphrase)
    payload = store.load(identity)
    report = check_bytes(payload.data)
    if report.errors:
        raise ValidationFailed(
            f"the encrypted persona has {len(report.errors)} error(s); "
            "run `veil persona check` for the field paths"
        )
    flat = flatten(parse_persona(load_yaml(payload.data)))
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
