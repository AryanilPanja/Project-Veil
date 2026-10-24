"""`veil persona import FILE`: validate, add the canary, encrypt into the store (ADR-0024/0025).

The source file is only ever read. It is left exactly as it was (same bytes, same mtime) unless
`--shred` was given AND the user typed the confirmation word.

Order (nothing is written until every check has passed):
1. read + validate the source; any error → report, exit 1, nothing written;
2. take the store lock;
3. refuse to overwrite an existing store without `--replace`;
4. get the key: load the existing one, or create one if this is the first import;
   when replacing, the current store must decrypt with that key first;
5. insert a fresh canary, re-validate the exact payload, encrypt, verify, replace (+ `.bak`);
6. optionally shred the source.
"""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from veil import fsutil, ui
from veil.crypto.keystore import KeyBackend, KeyStore
from veil.errors import Aborted, ValidationFailed, VeilError
from veil.exitcodes import ExitCode
from veil.persona import canary
from veil.persona.check import check_bytes, read_source
from veil.persona.report import Report, render_text
from veil.persona.store import Payload, PersonaStore

SHRED_WORD = "shred"


@dataclass(frozen=True)
class ImportResult:
    created_key: KeyBackend | None  # the mode of a newly created key; None if one existed
    replaced: bool
    warnings: int
    shredded: bool


@dataclass(frozen=True)
class Prompts:
    """How to ask the human. The CLI wires these to `ui`; tests pass stand-ins."""

    passphrase: Callable[[], str]  # existing passphrase-mode key
    new_passphrase: Callable[[], str]  # first import in passphrase mode
    confirm_shred: Callable[[], bool]


def import_persona(
    source: Path,
    *,
    keystore: KeyStore,
    store: PersonaStore,
    prompts: Prompts,
    replace: bool = False,
    backend: KeyBackend | None = None,
    shred: bool = False,
) -> ImportResult:
    if shred:
        ui.require_tty("veil persona import --shred")  # ask before doing anything
    data = read_source(source)
    report = check_bytes(data)
    if report.errors:
        ui.out(render_text(report))
        raise ValidationFailed(
            f"the persona has {len(report.errors)} error(s); nothing was imported"
        )
    payload = _with_canary(data)  # before touching keys: a refusal here must leave no trace

    with store.lock():
        store_exists = store.exists()
        if store_exists and not replace:
            raise VeilError(
                "an encrypted persona already exists; use --replace to overwrite it "
                "(the current one is kept as a .bak)",
                exit_code=ExitCode.USAGE,
            )
        identity, created = _identity(keystore, store_exists, backend, prompts)
        if store_exists:
            store.load(identity)  # the key must open what we are about to replace
        store.save(payload, identity, recipient=keystore.recipient())

    _print_warnings(report)
    shredded = _maybe_shred(source, shred, prompts)
    return ImportResult(
        created_key=created, replaced=store_exists, warnings=len(report.warnings), shredded=shredded
    )


def _identity(keystore, store_exists, backend, prompts):
    existing = keystore.status().backend
    if existing is None:
        mode = backend or KeyBackend.KEYRING
        passphrase = prompts.new_passphrase() if mode is KeyBackend.FILE else None
        return keystore.create(mode, store_exists=store_exists, passphrase=passphrase), mode
    if backend is not None and backend is not existing:
        raise VeilError(
            f"a key already exists in {existing.value} mode; switching modes is not supported",
            exit_code=ExitCode.USAGE,
        )
    return keystore.load(prompts.passphrase), None


def _with_canary(data: bytes) -> Payload:
    text = data.decode("utf-8")  # check_bytes already proved it decodes
    payload = Payload(canary.insert(text, canary.generate()).encode("utf-8"))
    after = check_bytes(payload.data)
    if after.errors or payload.canary is None:
        # Should be impossible; if it happens, refuse rather than store something unreadable.
        raise ValidationFailed("adding the canary made the persona invalid; nothing was imported")
    return payload


def _print_warnings(report: Report) -> None:
    if report.findings:
        ui.out(render_text(report))


def _maybe_shred(source: Path, shred: bool, prompts: Prompts) -> bool:
    if not shred:
        ui.err(
            "veil: note: your plaintext persona file was left in place. The encrypted copy is "
            "now the source of truth; edits made with `veil persona edit` will not update it."
        )
        return False
    if not prompts.confirm_shred():
        raise Aborted("import done, but the plaintext file was NOT shredded (not confirmed)")
    fsutil.secure_remove(source, "the plaintext persona file")
    ui.err(
        "veil: plaintext file overwritten and removed (best effort: SSDs and snapshots may keep "
        "old copies; disk encryption is the real protection)"
    )
    return True
