"""`veil persona status`: safe diagnostics (agent-safe: no values, no paths, no key material).

Checks, each printed as one line:
- store: is there an encrypted persona (and a .bak)?
- key: keyring or passphrase mode, or not set up;
- unlock: in keyring mode, does the key load, match recipient.txt and open the store (with a
  valid canary)? Passphrase mode is skipped: it would need a prompt;
- runtime dir: is there a safe in-memory place for `veil persona edit`?
- swap: could memory reach disk unencrypted? (a warning, never a failure)

Exit code: 0 if everything that can be checked is fine, otherwise the code of the first failure.
"""

from veil import paths, ui
from veil.crypto.keystore import KeyBackend, KeyStore
from veil.errors import VeilError
from veil.exitcodes import ExitCode
from veil.persona.store import PersonaStore


def persona_status(
    keystore: KeyStore, store: PersonaStore, read: paths.TextReader = paths._read_text
) -> int:
    failures: list[ExitCode] = []

    has_store = store.exists()
    backup = " (backup present)" if store.backup_path.exists() else ""
    ui.out(
        f"store:       {'encrypted persona present' + backup if has_store else 'not imported yet'}"
    )

    key = keystore.status()
    ui.out(f"key:         {_describe_key(key.backend)}")

    if not has_store or key.backend is None:
        ui.out("unlock:      skipped (nothing imported yet)")
    elif key.backend is KeyBackend.FILE:
        ui.out("unlock:      skipped (passphrase mode; `veil persona check` asks for it)")
    else:
        try:
            store.load(keystore.load())
            ui.out("unlock:      ok (key matches, persona decrypts, canary present)")
        except VeilError as error:
            ui.out(f"unlock:      FAILED: {error.safe_message}")
            failures.append(error.exit_code)

    try:
        paths.runtime_base(read)
        ui.out("runtime dir: ok (private, in memory)")
    except VeilError as error:
        ui.out(f"runtime dir: FAILED: {error.safe_message}")
        failures.append(error.exit_code)

    swap = paths.swap_status(read)
    if swap.at_risk:
        ui.out(
            f"swap:        WARNING: {swap.unprotected} of {swap.active} swap area(s) are not "
            "encrypted; decrypted data in memory could be written to disk (plan P0.8)"
        )
    elif swap.active:
        ui.out(f"swap:        ok ({swap.active} area(s), all zram or encrypted)")
    else:
        ui.out("swap:        ok (none)")

    return int(failures[0]) if failures else int(ExitCode.OK)


def _describe_key(backend: KeyBackend | None) -> str:
    if backend is KeyBackend.KEYRING:
        return "desktop keyring (Secret Service)"
    if backend is KeyBackend.FILE:
        return "passphrase file"
    return "not set up"
