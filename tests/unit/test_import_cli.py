"""`veil persona import` / `check` (store) / `status` end to end through the CLI.

Uses a throwaway config dir and the in-memory keyring (`veil_home`), the synthetic persona only,
and fast scrypt. The source file must come out byte-identical with the same mtime (ADR-0024).
"""

import hashlib
import os
import shutil

import pytest

from tests.conftest import run_python
from tests.unit.test_check_cli import FIXTURE
from veil import cli, paths, ui
from veil.crypto import age
from veil.crypto.keystore import KEY_FILE, RECIPIENT_FILE, SERVICE, keyring_username
from veil.errors import StorageError, UnsafeEnvironment, VeilError
from veil.exitcodes import ExitCode
from veil.persona import canary
from veil.persona.schema import parse_persona
from veil.persona.store import STORE_FILE
from veil.persona.walk import iter_pair_records
from veil.persona.yamlio import load_yaml

PASS = "correct horse battery"


def _real_values() -> set[str]:
    persona = parse_persona(load_yaml(FIXTURE.read_bytes()))
    return {r for rec in iter_pair_records(persona) for r in rec.reals if len(r) >= 4}


REALS = _real_values()


def assert_no_values(text: str) -> None:
    leaked = sorted(v for v in REALS if v in text)
    assert not leaked, f"persona values in output: {len(leaked)}"
    assert "VEIL-CANARY-" not in text
    assert "AGE-SECRET-KEY" not in text


@pytest.fixture
def source(veil_home):
    path = veil_home.tmp / "draft.yaml"
    shutil.copyfile(FIXTURE, path)
    path.chmod(0o600)
    return path


def fingerprint(path):
    st = path.stat()
    return hashlib.sha256(path.read_bytes()).hexdigest(), st.st_mtime_ns, st.st_mode, st.st_ino


@pytest.fixture
def tty(monkeypatch):
    monkeypatch.setattr(ui, "_isatty", lambda _stream: True)


@pytest.fixture
def answers(monkeypatch):
    """Scripted answers for passphrase prompts and the shred confirmation."""
    state = {"secrets": [], "confirm": False, "asked": []}

    def prompt_secret(prompt):
        state["asked"].append(prompt)
        ui.require_tty("passphrase prompt")
        return state["secrets"].pop(0)

    def confirm_typed(prompt, expected):
        state["asked"].append(prompt)
        assert expected == "shred"
        return state["confirm"]

    monkeypatch.setattr(ui, "prompt_secret", prompt_secret)
    monkeypatch.setattr(ui, "confirm_typed", confirm_typed)
    return state


def veil(*args):
    return cli.main(list(args))


# ── happy path ────────────────────────────────────────────────────────────────


class TestImportKeyring:
    def test_first_import(self, veil_home, source, capsys):
        before = fingerprint(source)
        assert veil("persona", "import", str(source)) == ExitCode.OK
        assert fingerprint(source) == before
        config = veil_home.config
        assert (config / STORE_FILE).exists()
        assert (config / RECIPIENT_FILE).exists()
        assert not (config / KEY_FILE).exists()
        assert (SERVICE, keyring_username(veil_home.config)) in veil_home.ring.items
        out, err = capsys.readouterr()
        assert "persona imported and encrypted" in out
        assert "new key stored (keyring)" in out
        assert "left in place" in err
        assert_no_values(out + err)

    def test_store_decrypts_to_source_plus_canary(self, veil_home, source):
        veil("persona", "import", str(source))
        identity = age.parse_identity(
            veil_home.ring.items[(SERVICE, keyring_username(veil_home.config))]
        )
        data = age.decrypt((veil_home.config / STORE_FILE).read_bytes(), identity).decode()
        tokens = canary.find_all(data)
        assert len(tokens) == 2
        assert len(set(tokens)) == 1
        stripped = data.replace(f'veil_canary: "{tokens[0]}"\n', "").replace(
            f"# veil_canary: {tokens[0]}\n", ""
        )
        assert stripped == source.read_text()

    def test_check_reads_the_store_by_default(self, veil_home, source, capsys):
        veil("persona", "import", str(source))
        capsys.readouterr()
        assert veil("persona", "check") == ExitCode.OK
        out = capsys.readouterr().out
        assert "0 error(s)" in out
        assert_no_values(out)

    def test_check_strict_and_json_on_store(self, veil_home, source, capsys):
        veil("persona", "import", str(source))
        assert veil("persona", "check", "--strict", "--format", "json") == ExitCode.OK
        assert '"errors": 0' in capsys.readouterr().out

    def test_check_before_import(self, veil_home, capsys):
        assert veil("persona", "check") == ExitCode.KEY_UNAVAILABLE
        assert "no key has been set up" in capsys.readouterr().err

    def test_read_only_source_is_enough(self, veil_home, source):
        source.chmod(0o400)
        before = fingerprint(source)
        assert veil("persona", "import", str(source)) == ExitCode.OK
        assert fingerprint(source) == before

    def test_unicode_persona(self, veil_home, tmp_path, capsys):
        src = tmp_path / "indic.yaml"
        src.write_text(
            'version: "1"\nperson:\n  first_name: { real: জেন, fake: অ্যালেক্স }\n'
            "  last_name: { real: डो, fake: स्मिथ, allow_short: true }\n",
            encoding="utf-8",
        )
        assert veil("persona", "import", str(src)) == ExitCode.OK
        out, err = capsys.readouterr()
        for value in ("জেন", "অ্যালেক্স", "डो", "स्मिथ"):
            assert value not in out + err
        assert veil("persona", "check") == ExitCode.OK

    def test_warnings_are_printed_but_import_succeeds(self, veil_home, tmp_path, capsys):
        src = tmp_path / "warn.yaml"
        src.write_text(
            'version: "1"\nperson:\n  last_name: { real: Doe, fake: Smith }\n', encoding="utf-8"
        )
        assert veil("persona", "import", str(src)) == ExitCode.OK
        out = capsys.readouterr().out
        assert "W101" in out
        assert "(1 warning(s))" in out
        assert "Doe" not in out


# ── validation and refusals: nothing written ──────────────────────────────────


class TestNothingWritten:
    def assert_untouched(self, veil_home):
        assert not (veil_home.config / STORE_FILE).exists()
        assert not (veil_home.config / RECIPIENT_FILE).exists()
        assert veil_home.ring.items == {}

    def test_validation_errors(self, veil_home, tmp_path, capsys):
        src = tmp_path / "bad.yaml"
        src.write_text(
            'version: "1"\npeople: [{real: Ravi, fake: Om}, {real: Kiran, fake: Om}]\n',
            encoding="utf-8",
        )
        before = fingerprint(src)
        assert veil("persona", "import", str(src)) == ExitCode.FINDINGS
        out, err = capsys.readouterr()
        assert "E010" in out
        assert "nothing was imported" in err
        for value in ("Ravi", "Kiran", "Om"):
            assert value not in out + err
        assert fingerprint(src) == before
        self.assert_untouched(veil_home)

    @pytest.mark.parametrize(
        "text",
        ["", "version: [\n", 'version: "2"\n', "just text\n", 'version: "1"\nnope: 1\n'],
    )
    def test_broken_files(self, veil_home, tmp_path, text):
        src = tmp_path / "broken.yaml"
        src.write_text(text, encoding="utf-8")
        assert veil("persona", "import", str(src)) == ExitCode.FINDINGS
        self.assert_untouched(veil_home)

    def test_flow_style_version_cannot_carry_a_canary(self, veil_home, tmp_path, capsys):
        src = tmp_path / "flow.yaml"
        src.write_text('{version: "1"}\n', encoding="utf-8")
        assert veil("persona", "import", str(src)) == ExitCode.FINDINGS
        assert "version" in capsys.readouterr().err
        assert not (veil_home.config / STORE_FILE).exists()

    def test_missing_source(self, veil_home, tmp_path, capsys):
        assert veil("persona", "import", str(tmp_path / "missing.yaml")) == ExitCode.USAGE
        assert "not found" in capsys.readouterr().err
        self.assert_untouched(veil_home)

    def test_source_is_a_directory(self, veil_home, tmp_path):
        assert veil("persona", "import", str(tmp_path)) == ExitCode.USAGE
        self.assert_untouched(veil_home)

    def test_locked_keyring_on_first_import(self, veil_home, source, monkeypatch, capsys):
        from tests.helpers.memkeyring import FailingKeyring, LockedException
        from veil.crypto import keystore

        monkeypatch.setattr(
            keystore, "secret_service_backend", lambda: FailingKeyring(LockedException())
        )
        assert veil("persona", "import", str(source)) == ExitCode.KEY_UNAVAILABLE
        assert "locked" in capsys.readouterr().err
        assert not (veil_home.config / STORE_FILE).exists()
        assert not (veil_home.config / RECIPIENT_FILE).exists()

    def test_busy_when_another_import_holds_the_lock(self, veil_home, source, capsys):
        from veil import fsutil

        fsutil.ensure_private_dir(veil_home.config)
        with fsutil.flock_exclusive(veil_home.config / "persona.lock"):
            assert veil("persona", "import", str(source)) == ExitCode.BUSY
        assert "in use" in capsys.readouterr().err
        self.assert_untouched(veil_home)

    def test_disk_full_then_retry_succeeds(self, veil_home, source, monkeypatch):
        from veil.persona import store as store_module

        real = store_module.fsutil.atomic_write

        def full(path, data, **kw):
            if path.name == STORE_FILE:
                raise StorageError("not enough disk space to write the encrypted persona")
            return real(path, data, **kw)

        monkeypatch.setattr(store_module.fsutil, "atomic_write", full)
        assert veil("persona", "import", str(source)) == ExitCode.STORAGE
        assert not (veil_home.config / STORE_FILE).exists()
        monkeypatch.setattr(store_module.fsutil, "atomic_write", real)
        assert veil("persona", "import", str(source)) == ExitCode.OK
        assert veil("persona", "check") == ExitCode.OK


# ── replace ───────────────────────────────────────────────────────────────────


class TestReplace:
    def test_second_import_needs_replace(self, veil_home, source, capsys):
        veil("persona", "import", str(source))
        before = (veil_home.config / STORE_FILE).read_bytes()
        assert veil("persona", "import", str(source)) == ExitCode.USAGE
        assert "--replace" in capsys.readouterr().err
        assert (veil_home.config / STORE_FILE).read_bytes() == before

    def test_replace_keeps_backup_and_key(self, veil_home, source, capsys):
        veil("persona", "import", str(source))
        key = dict(veil_home.ring.items)
        first = (veil_home.config / STORE_FILE).read_bytes()
        assert veil("persona", "import", "--replace", str(source)) == ExitCode.OK
        assert "persona replaced" in capsys.readouterr().out
        assert veil_home.ring.items == key
        assert (veil_home.config / (STORE_FILE + ".bak")).read_bytes() == first
        assert veil("persona", "check") == ExitCode.OK

    def test_each_import_gets_a_fresh_canary(self, veil_home, source):
        identity = None
        seen = set()
        for args in (
            ("persona", "import", str(source)),
            ("persona", "import", "--replace", str(source)),
        ):
            veil(*args)
            identity = identity or age.parse_identity(
                veil_home.ring.items[(SERVICE, keyring_username(veil_home.config))]
            )
            data = age.decrypt((veil_home.config / STORE_FILE).read_bytes(), identity).decode()
            seen.add(canary.find_all(data)[0])
        assert len(seen) == 2

    def test_replace_refused_when_key_cannot_open_current_store(self, veil_home, source, capsys):
        veil("persona", "import", str(source))
        before = (veil_home.config / STORE_FILE).read_bytes()
        # Someone swapped both the keyring entry and recipient.txt for a new key.
        other = age.generate_identity()
        veil_home.ring.items[(SERVICE, keyring_username(veil_home.config))] = other.secret
        (veil_home.config / RECIPIENT_FILE).write_text(other.recipient + "\n")
        assert veil("persona", "import", "--replace", str(source)) == ExitCode.DECRYPT_FAILED
        assert (veil_home.config / STORE_FILE).read_bytes() == before

    def test_replace_with_invalid_new_file_keeps_old(self, veil_home, source, tmp_path):
        veil("persona", "import", str(source))
        before = (veil_home.config / STORE_FILE).read_bytes()
        bad = tmp_path / "bad.yaml"
        bad.write_text('version: "1"\npeople: [{real: A1b, fake: X}, {real: B2c, fake: X}]\n')
        assert veil("persona", "import", "--replace", str(bad)) == ExitCode.FINDINGS
        assert (veil_home.config / STORE_FILE).read_bytes() == before

    def test_store_without_key_is_refused(self, veil_home, source, capsys):
        veil("persona", "import", str(source))
        (veil_home.config / RECIPIENT_FILE).unlink()
        veil_home.ring.items.clear()
        assert veil("persona", "import", "--replace", str(source)) == ExitCode.USAGE
        assert "refusing to create a new key" in capsys.readouterr().err


# ── passphrase mode ───────────────────────────────────────────────────────────


def import_file_mode(home, source, *, replace=False):
    """Passphrase mode is not offered by the v0.1 CLI (board Q4), but the code path stays tested."""
    from veil.crypto.keystore import KeyBackend, KeyStore
    from veil.persona.importer import Prompts, import_persona
    from veil.persona.store import PersonaStore

    return import_persona(
        source,
        keystore=KeyStore(home.config, timeout=2),
        store=PersonaStore(home.config),
        prompts=Prompts(
            passphrase=lambda: ui.prompt_secret("Passphrase"),
            new_passphrase=lambda: ui.new_secret("New passphrase"),
            confirm_shred=lambda: False,
        ),
        replace=replace,
        backend=KeyBackend.FILE,
    )


class TestImportPassphrase:
    def test_cli_does_not_offer_passphrase_mode_in_v01(self, veil_home, source, capsys):
        with pytest.raises(SystemExit) as info:
            cli.main(["persona", "import", "--key-backend", "file", str(source)])
        assert info.value.code == ExitCode.USAGE
        assert "invalid choice" in capsys.readouterr().err
        assert not (veil_home.config / STORE_FILE).exists()

    def test_first_import_in_file_mode(self, veil_home, source, tty, answers):
        answers["secrets"] = [PASS, PASS]
        result = import_file_mode(veil_home, source)
        assert result.created_key is not None
        assert result.created_key.value == "file"
        assert (veil_home.config / KEY_FILE).exists()
        assert veil_home.ring.items == {}
        answers["secrets"] = [PASS]
        assert veil("persona", "check") == ExitCode.OK  # an existing key.age still loads

    def test_mismatched_new_passphrases(self, veil_home, source, tty, answers):
        answers["secrets"] = [PASS, PASS + "!"]
        with pytest.raises(VeilError, match="did not match") as info:
            import_file_mode(veil_home, source)
        assert info.value.exit_code == ExitCode.USAGE
        assert not (veil_home.config / KEY_FILE).exists()
        assert not (veil_home.config / STORE_FILE).exists()

    def test_weak_passphrase(self, veil_home, source, tty, answers):
        answers["secrets"] = ["short", "short"]
        with pytest.raises(VeilError) as info:
            import_file_mode(veil_home, source)
        assert info.value.exit_code == ExitCode.USAGE
        assert not (veil_home.config / STORE_FILE).exists()

    def test_wrong_passphrase_on_replace(self, veil_home, source, tty, answers, capsys):
        answers["secrets"] = [PASS, PASS]
        import_file_mode(veil_home, source)
        before = (veil_home.config / STORE_FILE).read_bytes()
        answers["secrets"] = ["wrong horse battery"]
        assert veil("persona", "import", "--replace", str(source)) == ExitCode.DECRYPT_FAILED
        assert "horse" not in capsys.readouterr().err
        assert (veil_home.config / STORE_FILE).read_bytes() == before

    def test_passphrase_prompt_needs_a_terminal(self, veil_home, source, answers):
        answers["secrets"] = [PASS, PASS]
        with pytest.raises(UnsafeEnvironment):
            import_file_mode(veil_home, source)
        assert not (veil_home.config / STORE_FILE).exists()

    def test_switching_modes_is_refused(self, veil_home, source, tty, answers):
        veil("persona", "import", str(source))
        with pytest.raises(VeilError, match="switching modes") as info:
            import_file_mode(veil_home, source, replace=True)
        assert info.value.exit_code == ExitCode.USAGE

    def test_explicit_keyring_backend_matches(self, veil_home, source):
        veil("persona", "import", "--key-backend", "keyring", str(source))
        assert veil("persona", "import", "--replace", "--key-backend", "keyring", str(source)) == 0


# ── shred ─────────────────────────────────────────────────────────────────────


class TestShred:
    def test_confirmed_shred_removes_source(self, veil_home, source, tty, answers, capsys):
        answers["confirm"] = True
        assert veil("persona", "import", "--shred", str(source)) == ExitCode.OK
        assert not source.exists()
        assert "best effort" in capsys.readouterr().err
        assert veil("persona", "check") == ExitCode.OK

    def test_declined_shred_keeps_source_and_import(self, veil_home, source, tty, answers, capsys):
        before = fingerprint(source)
        answers["confirm"] = False
        assert veil("persona", "import", "--shred", str(source)) == ExitCode.ABORTED
        assert fingerprint(source) == before
        assert "NOT shredded" in capsys.readouterr().err
        assert (veil_home.config / STORE_FILE).exists()

    def test_shred_without_terminal_refused_before_anything(self, veil_home, source, capsys):
        before = fingerprint(source)
        assert veil("persona", "import", "--shred", str(source)) == ExitCode.UNSAFE_ENVIRONMENT
        assert fingerprint(source) == before
        assert not (veil_home.config / STORE_FILE).exists()
        assert veil_home.ring.items == {}

    def test_shred_refuses_a_symlink(self, veil_home, source, tmp_path, tty, answers, capsys):
        # Through a link, only the link would go and the plaintext would stay (sweep 2026-10-26).
        link = tmp_path / "link.yaml"
        link.symlink_to(source)
        before = fingerprint(source)
        answers["confirm"] = True
        assert veil("persona", "import", "--shred", str(link)) == ExitCode.USAGE
        assert fingerprint(source) == before
        assert not (veil_home.config / STORE_FILE).exists()
        assert "symbolic link" in capsys.readouterr().err

    def test_shred_refuses_a_hard_linked_file(
        self, veil_home, source, tmp_path, tty, answers, capsys
    ):
        other = tmp_path / "other-name.yaml"
        os.link(source, other)
        answers["confirm"] = True
        assert veil("persona", "import", "--shred", str(source)) == ExitCode.USAGE
        assert source.read_bytes() == other.read_bytes() != b""
        assert "hard links" in capsys.readouterr().err

    def test_shred_after_failed_validation_never_happens(self, veil_home, tmp_path, tty, answers):
        src = tmp_path / "bad.yaml"
        src.write_text('version: "1"\npeople: [{real: A1b, fake: X}, {real: B2c, fake: X}]\n')
        answers["confirm"] = True
        assert veil("persona", "import", "--shred", str(src)) == ExitCode.FINDINGS
        assert src.exists()
        assert answers["asked"] == []


# ── status ────────────────────────────────────────────────────────────────────


@pytest.fixture
def safe_host(monkeypatch, tmp_path):
    """A fake tmpfs runtime dir and no swap, independent of the machine running the tests."""
    run = tmp_path / "rt-host"
    run.mkdir(mode=0o700)
    run.chmod(0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(run))
    files = {
        "/proc/self/mountinfo": f"1 0 0:1 / / rw - ext4 x rw\n2 1 0:2 / {run} rw - tmpfs t rw\n",
        "/proc/swaps": "Filename Type Size Used Priority\n",
    }

    def read(path):
        if path not in files:
            raise FileNotFoundError(path)
        return files[path]

    monkeypatch.setattr(paths, "_read_text", read)
    from veil.persona import status

    real = status.persona_status
    monkeypatch.setattr(status, "persona_status", lambda k, s, read=read: real(k, s, read))
    return files


class TestStatus:
    def test_nothing_imported(self, veil_home, safe_host, capsys):
        assert veil("persona", "status") == ExitCode.OK
        out = capsys.readouterr().out
        assert "store:       not imported yet" in out
        assert "key:         not set up" in out
        assert "runtime dir: ok" in out
        assert "swap:        ok (none)" in out

    def test_after_import(self, veil_home, source, safe_host, capsys):
        veil("persona", "import", str(source))
        capsys.readouterr()
        assert veil("persona", "status") == ExitCode.OK
        out = capsys.readouterr().out
        assert "encrypted persona present" in out
        assert "desktop keyring" in out
        assert "unlock:      ok" in out
        assert_no_values(out)
        assert str(veil_home.config) not in out

    def test_backup_reported(self, veil_home, source, safe_host, capsys):
        veil("persona", "import", str(source))
        veil("persona", "import", "--replace", str(source))
        capsys.readouterr()
        veil("persona", "status")
        assert "(backup present)" in capsys.readouterr().out

    def test_missing_keyring_entry_fails_with_4(self, veil_home, source, safe_host, capsys):
        veil("persona", "import", str(source))
        veil_home.ring.items.clear()
        capsys.readouterr()
        assert veil("persona", "status") == ExitCode.KEY_UNAVAILABLE
        assert "unlock:      FAILED: the key is missing" in capsys.readouterr().out

    def test_corrupt_store_fails_with_5(self, veil_home, source, safe_host, capsys):
        veil("persona", "import", str(source))
        (veil_home.config / STORE_FILE).write_bytes(b"garbage")
        capsys.readouterr()
        assert veil("persona", "status") == ExitCode.DECRYPT_FAILED

    def test_passphrase_mode_does_not_prompt(
        self, veil_home, source, tty, answers, safe_host, capsys
    ):
        answers["secrets"] = [PASS, PASS]
        import_file_mode(veil_home, source)
        capsys.readouterr()
        answers["asked"].clear()
        assert veil("persona", "status") == ExitCode.OK
        assert "skipped (passphrase mode" in capsys.readouterr().out
        assert answers["asked"] == []

    def test_unsafe_runtime_dir_fails_with_7(
        self, veil_home, safe_host, monkeypatch, tmp_path, capsys
    ):
        monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "nope"))
        assert veil("persona", "status") == ExitCode.UNSAFE_ENVIRONMENT
        assert "runtime dir: FAILED" in capsys.readouterr().out

    def test_unencrypted_swap_warns_but_passes(self, veil_home, safe_host, capsys):
        safe_host["/proc/swaps"] = "Filename Type Size Used Priority\n/dev/sda2 partition 1 0 -2\n"
        assert veil("persona", "status") == ExitCode.OK
        assert "WARNING: 1 of 1 swap area(s) are not encrypted" in capsys.readouterr().out

    def test_status_never_touches_keyring_when_nothing_imported(self, veil_home, safe_host):
        veil("persona", "status")
        assert veil_home.ring.calls == []


# ── import cost ───────────────────────────────────────────────────────────────


def test_cli_import_does_not_load_crypto_or_pydantic():
    result = run_python(
        "import sys, veil.cli; "
        "print(sorted(m for m in ('pyrage', 'keyring', 'pydantic', 'yaml') if m in sys.modules))"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"


def test_import_help_lists_options(capsys):
    with pytest.raises(SystemExit):
        cli.run(["persona", "import", "--help"])
    out = capsys.readouterr().out
    for option in ("--replace", "--key-backend", "--shred"):
        assert option in out
