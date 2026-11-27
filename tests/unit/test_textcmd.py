"""`veil translate` / `veil reverse` / `veil audit` end to end (M1.7), synthetic store only."""

import io
import shutil
import sys

import pytest

from tests.unit.test_check_cli import FIXTURE
from veil import cli
from veil.crypto import age
from veil.crypto.keystore import SERVICE, keyring_username
from veil.engine.vault import VAULT_FILE, Vault
from veil.exitcodes import ExitCode
from veil.persona.store import STORE_FILE

REAL_TEXT = (
    "Hi, I'm Jane Doe (jane.doe@xyz.example.test), MS thesis at XYZIT.\n"
    "Call +91 90000 00001. Born 14/03/2001. Roll 2024701001.\n"
    "Files: /home/janed/jane-thesis/main.tex\n"
)
REALS = (
    "Jane", "Doe", "jane.doe", "xyz.example", "XYZIT", "90000", "14/03/2001", "2024701001",
    "janed", "jane-thesis", "MS thesis",
)  # fmt: skip


@pytest.fixture
def imported(veil_home, tmp_path, capsys):
    source = tmp_path / "draft.yaml"
    shutil.copyfile(FIXTURE, source)
    assert cli.main(["persona", "import", str(source)]) == ExitCode.OK
    capsys.readouterr()
    return veil_home


def as_first_run(home) -> None:
    """Remove the vault and lexicon cache the import's pre-warm created (ADR-0029)."""
    for name in (VAULT_FILE, VAULT_FILE + ".bak", "persona.cache.age"):
        (home.config / name).unlink(missing_ok=True)


def feed(monkeypatch, data: str | bytes) -> None:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8"))


def run(monkeypatch, capsys, command: str, data: str | bytes, *extra: str):
    feed(monkeypatch, data)
    code = cli.main([command, *extra])
    out, err = capsys.readouterr()
    return code, out, err


# ── translate / reverse ───────────────────────────────────────────────────────


class TestTranslate:
    def test_translates_every_real_detail(self, imported, monkeypatch, capsys):
        code, out, err = run(monkeypatch, capsys, "translate", REAL_TEXT)
        assert code == ExitCode.OK
        for real in REALS:
            assert real not in out
        assert "Alex Smith" in out
        assert "alex.smith@abc.example.test" in out
        assert "PhD thesis" in out
        assert "/home/alexs/alex-thesis/main.tex" in out
        assert err == ""

    def test_output_is_byte_exact_no_newline_added(self, imported, monkeypatch, capsys):
        _, out, _ = run(monkeypatch, capsys, "translate", "no newline at end, Jane")
        assert out == "no newline at end, Alex"

    def test_untouched_text_is_identical(self, imported, monkeypatch, capsys):
        text = "nothing personal: ﬁle ＱＱ \t tabs\r\nand CRLF"
        _, out, _ = run(monkeypatch, capsys, "translate", text)
        assert out == text

    def test_empty_input(self, imported, monkeypatch, capsys):
        code, out, _ = run(monkeypatch, capsys, "translate", "")
        assert (code, out) == (ExitCode.OK, "")

    def test_round_trip_through_reverse(self, imported, monkeypatch, capsys):
        _, fake, _ = run(monkeypatch, capsys, "translate", REAL_TEXT)
        code, back, _ = run(monkeypatch, capsys, "reverse", fake)
        assert code == ExitCode.OK
        assert back == REAL_TEXT

    def test_same_output_across_runs(self, imported, monkeypatch, capsys):
        _, first, _ = run(monkeypatch, capsys, "translate", REAL_TEXT)
        _, second, _ = run(monkeypatch, capsys, "translate", REAL_TEXT)
        assert first == second

    def test_file_option(self, imported, monkeypatch, capsys, tmp_path):
        source = tmp_path / "in.txt"
        source.write_text("Jane wrote this", encoding="utf-8")
        code, out, _ = run(monkeypatch, capsys, "translate", "ignored stdin", "--file", str(source))
        assert (code, out) == (ExitCode.OK, "Alex wrote this")

    def test_ambiguity_warning_is_value_free(self, imported, monkeypatch, capsys):
        code, out, err = run(monkeypatch, capsys, "translate", "Alex met Jane in Rivertown")
        assert code == ExitCode.OK
        assert "already contains 2 fake form(s)" in err
        for value in ("Alex", "Rivertown", "Jane"):
            assert value not in err
        assert out == "Alex met Alex in Rivertown"

    def test_unicode_and_indic(self, imported, monkeypatch, capsys):
        _, out, _ = run(monkeypatch, capsys, "translate", "জেন লিখেছে, जेन ने लिखा")
        assert out == "অ্যালেক্স লিখেছে, एलेक्स ने लिखा"


# ── audit ─────────────────────────────────────────────────────────────────────


class TestAudit:
    def test_findings_by_position_and_path_never_values(self, imported, monkeypatch, capsys):
        code, out, _ = run(monkeypatch, capsys, "audit", REAL_TEXT)
        assert code == ExitCode.FINDINGS
        assert "1:9  person.full_name  (name)" in out
        assert "2:6  phones[0]  (phone)" in out
        assert "real form(s) found" in out
        for real in REALS:
            assert real not in out

    def test_clean_text_exits_zero(self, imported, monkeypatch, capsys):
        code, out, _ = run(monkeypatch, capsys, "audit", "Alex Smith at ABCU, nothing real")
        assert code == ExitCode.OK
        assert out.strip() == "0 real form(s) found"

    def test_translated_output_audits_clean(self, imported, monkeypatch, capsys):
        _, fake, _ = run(monkeypatch, capsys, "translate", REAL_TEXT)
        code, _, _ = run(monkeypatch, capsys, "audit", fake)
        assert code == ExitCode.OK

    def test_audit_ignores_context_guards(self, imported, monkeypatch, capsys):
        # "orion" is only translated near "ssh"/"slurm"/"cluster", but an audit reports it anyway.
        code, out, _ = run(monkeypatch, capsys, "audit", "the Orion nebula")
        assert code == ExitCode.FINDINGS
        assert "infra.clusters[0]" in out

    def test_columns_count_characters(self, imported, monkeypatch, capsys):
        _, out, _ = run(monkeypatch, capsys, "audit", "অ্যা Jane")
        assert out.startswith("1:6  ")


# ── failures: nothing on stdout ───────────────────────────────────────────────


class TestFailures:
    @pytest.mark.parametrize("command", ["translate", "reverse", "audit"])
    def test_invalid_utf8(self, imported, monkeypatch, capsys, command):
        code, out, err = run(monkeypatch, capsys, command, b"\xff\xfe Jane")
        assert code == ExitCode.USAGE
        assert out == ""
        assert "not valid UTF-8" in err

    def test_input_too_large(self, imported, monkeypatch, capsys):
        from veil import textcmd

        monkeypatch.setattr(textcmd, "MAX_INPUT_BYTES", 10)
        code, out, err = run(monkeypatch, capsys, "translate", "Jane " * 10)
        assert code == ExitCode.USAGE
        assert out == ""
        assert "larger than 10 bytes" in err

    @pytest.mark.parametrize("problem", ["missing", "directory"])
    def test_bad_file_option(self, imported, monkeypatch, capsys, tmp_path, problem):
        path = tmp_path / "nope" if problem == "missing" else tmp_path
        code, out, _ = run(monkeypatch, capsys, "translate", "", "--file", str(path))
        assert code == ExitCode.USAGE
        assert out == ""

    def test_nothing_imported(self, veil_home, monkeypatch, capsys):
        code, out, err = run(monkeypatch, capsys, "translate", "Jane")
        assert code == ExitCode.KEY_UNAVAILABLE
        assert out == ""
        assert "Jane" not in err

    def test_locked_keyring(self, imported, monkeypatch, capsys):
        from tests.helpers.memkeyring import FailingKeyring, LockedException
        from veil.crypto import keystore

        monkeypatch.setattr(
            keystore, "secret_service_backend", lambda: FailingKeyring(LockedException())
        )
        code, out, _ = run(monkeypatch, capsys, "translate", "Jane")
        assert code == ExitCode.KEY_UNAVAILABLE
        assert out == ""

    def test_corrupt_store(self, imported, monkeypatch, capsys):
        (imported.config / STORE_FILE).write_bytes(b"garbage")
        code, out, _ = run(monkeypatch, capsys, "translate", "Jane")
        assert code == ExitCode.DECRYPT_FAILED
        assert out == ""

    def test_corrupt_vault(self, imported, monkeypatch, capsys):
        run(monkeypatch, capsys, "translate", "Jane")  # creates the vault
        identity = age.parse_identity(
            imported.ring.items[(SERVICE, keyring_username(imported.config))]
        )
        (imported.config / VAULT_FILE).write_bytes(age.encrypt(b"{not json", identity.recipient))
        code, out, err = run(monkeypatch, capsys, "translate", "Jane")
        assert code == ExitCode.DECRYPT_FAILED
        assert out == ""
        assert "vault is corrupt" in err

    def test_vault_cannot_be_saved_means_no_output(self, imported, monkeypatch, capsys):
        as_first_run(imported)
        from veil.engine import vault as vault_module
        from veil.errors import StorageError

        def full(*_a, **_k):
            raise StorageError("not enough disk space to write the generated-fakes vault")

        monkeypatch.setattr(vault_module.fsutil, "atomic_write", full)
        code, out, _ = run(monkeypatch, capsys, "translate", "Call +91 90000 00001")
        assert code == ExitCode.STORAGE
        assert out == ""

    def test_busy_while_an_edit_holds_the_lock_and_vault_needs_saving(
        self, imported, monkeypatch, capsys
    ):
        as_first_run(imported)
        from veil.persona.store import PersonaStore

        with PersonaStore(imported.config).lock():
            code, out, _ = run(monkeypatch, capsys, "translate", "Jane")
        assert code == ExitCode.BUSY
        assert out == ""


# ── vault lifecycle ───────────────────────────────────────────────────────────


class TestVaultLifecycle:
    def test_first_run_creates_vault_then_reuses_it(self, imported, monkeypatch, capsys):
        as_first_run(imported)
        assert not (imported.config / VAULT_FILE).exists()
        run(monkeypatch, capsys, "translate", "Jane")
        path = imported.config / VAULT_FILE
        assert path.exists()
        first = path.read_bytes()
        run(monkeypatch, capsys, "translate", "Jane")
        assert path.read_bytes() == first  # nothing new to store: not rewritten

    def test_vault_holds_no_real_values(self, imported, monkeypatch, capsys):
        run(monkeypatch, capsys, "translate", REAL_TEXT)
        identity = age.parse_identity(
            imported.ring.items[(SERVICE, keyring_username(imported.config))]
        )
        plain = age.decrypt((imported.config / VAULT_FILE).read_bytes(), identity)
        for real in ("90000", "14/03/2001", "2024701001", "E-1001", "Jane"):
            assert real.encode() not in plain

    def test_concurrent_first_run_reuses_the_saved_seed(self, imported, monkeypatch, capsys):
        """A second process saved a vault after we loaded an empty one: we must adopt its seed."""
        as_first_run(imported)
        from veil.engine import load as load_module
        from veil.engine.vault import VaultFile

        identity = age.parse_identity(
            imported.ring.items[(SERVICE, keyring_username(imported.config))]
        )
        recipient = identity.recipient
        theirs = Vault(seed=b"t" * 32)
        real_load = VaultFile.load
        calls = {"n": 0}

        def load(self, ident):
            calls["n"] += 1
            if calls["n"] == 1:
                return Vault(seed=b"m" * 32, dirty=True)  # what we saw before taking the lock
            if not self.exists():  # meanwhile, another process saved its vault
                VaultFile(imported.config).save(theirs, identity, recipient=recipient)
            return real_load(self, ident)

        monkeypatch.setattr(load_module.VaultFile, "load", load)
        _, out, _ = run(monkeypatch, capsys, "translate", "Call +91 90000 00001")
        stored = real_load(VaultFile(imported.config), identity)
        assert stored.seed == theirs.seed
        assert stored.get("phone", "+91 90000 00001") in out
