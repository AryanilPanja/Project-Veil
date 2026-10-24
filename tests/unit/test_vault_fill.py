"""engine/vault.py + fill.py (M1.6): stable generated fakes, encrypted vault, bijection kept."""

import json
import stat
from pathlib import Path

import pytest

from veil.crypto import age
from veil.engine.fill import MAX_ATTEMPTS, fill_generated
from veil.engine.lexicon import build_lexicon
from veil.engine.matcher import Engine
from veil.engine.variants import expand_all, validate_expanded
from veil.engine.vault import VAULT_FILE, Vault, VaultFile
from veil.errors import DecryptFailed, KeyUnavailable, UnsafeEnvironment, ValidationFailed
from veil.persona.entities import flatten
from veil.persona.schema import parse_persona
from veil.persona.yamlio import load_yaml
from veil.text.normalize import canon

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic_jane.yaml"
ID = age.generate_identity()
OTHER = age.generate_identity()
REALS = ("14/03/2001", "+91 90000 00001", "2024701001", "E-1001")


def flat_from(text: str | None = None):
    return flatten(parse_persona(load_yaml(text if text is not None else FIXTURE.read_text())))


def generated(flat, vault):
    filled = fill_generated(flat, vault)
    return {
        e.id: dict(zip(e.real_forms, e.fake_forms, strict=True)) for e in filled.entities
    }, filled


# ── vault ─────────────────────────────────────────────────────────────────────


class TestVault:
    def test_new_has_random_seed_and_is_dirty(self):
        a, b = Vault.new(), Vault.new()
        assert a.seed != b.seed
        assert len(a.seed) == 32
        assert a.dirty

    def test_keys_are_hmacs_not_values(self):
        vault = Vault.new()
        vault.put("phone", "+91 90000 00001", "+91 98246 38262")
        blob = vault.to_bytes()
        assert b"90000" not in blob
        assert b"98246" in blob  # fakes are fine to store
        assert len(next(iter(vault.entries))) == 64

    def test_key_uses_canon(self):
        vault = Vault.new()
        assert vault.key("pan", "ABCPD1234E") == vault.key("pan", "abcpd1234e")
        assert vault.key("pan", "ABCPD1234E") != vault.key("card", "ABCPD1234E")

    def test_put_marks_dirty_only_on_change(self):
        vault = Vault(seed=b"s" * 32)
        vault.put("x", "a", "b")
        assert vault.dirty
        vault.dirty = False
        vault.put("x", "a", "b")
        assert not vault.dirty

    def test_round_trip_bytes(self):
        vault = Vault(seed=b"s" * 32, shift_days=-40)
        vault.put("x", "a", "b")
        again = Vault.from_bytes(vault.to_bytes())
        assert (again.seed, again.entries, again.shift_days) == (vault.seed, vault.entries, -40)

    @pytest.mark.parametrize(
        "blob",
        [
            b"",
            b"not json",
            b"[]",
            json.dumps({"version": 2, "seed": "AAAA", "entries": {}}).encode(),
            json.dumps({"version": 1, "seed": "@@", "entries": {}}).encode(),
            json.dumps({"version": 1, "seed": "AAAA", "entries": {}}).encode(),  # short seed
            json.dumps(
                {"version": 1, "seed": "A" * 44, "entries": [], "shift_days": None}
            ).encode(),
            json.dumps({"version": 1, "seed": "A" * 44, "entries": {}, "shift_days": "x"}).encode(),
        ],
    )
    def test_corrupt_contents(self, blob):
        with pytest.raises(DecryptFailed, match="corrupt"):
            Vault.from_bytes(blob)

    def test_repr_is_value_free(self):
        vault = Vault.new()
        vault.put("x", "a", "fakevalue")
        assert "fakevalue" not in repr(vault)
        assert repr(vault.seed) not in repr(vault)


class TestVaultFile:
    def test_missing_file_gives_new_vault(self, tmp_path):
        assert VaultFile(tmp_path).load(ID).dirty

    def test_save_load_round_trip(self, tmp_path):
        files = VaultFile(tmp_path / "veil")
        vault = Vault.new()
        vault.put("phone", "x", "y")
        files.save(vault, ID, recipient=ID.recipient)
        assert not vault.dirty
        again = files.load(ID)
        assert again.seed == vault.seed
        assert again.entries == vault.entries
        assert stat.S_IMODE(files.path.stat().st_mode) == 0o600
        assert files.path.name == VAULT_FILE

    def test_encrypted_on_disk(self, tmp_path):
        files = VaultFile(tmp_path)
        vault = Vault.new()
        vault.put("phone", "x", "fake-98246")
        files.save(vault, ID, recipient=ID.recipient)
        raw = files.path.read_bytes()
        assert age.is_age(raw)
        assert b"fake-98246" not in raw

    def test_wrong_key(self, tmp_path):
        files = VaultFile(tmp_path)
        files.save(Vault.new(), ID, recipient=ID.recipient)
        with pytest.raises(DecryptFailed):
            files.load(OTHER)

    def test_recipient_mismatch_refused(self, tmp_path):
        with pytest.raises(KeyUnavailable):
            VaultFile(tmp_path).save(Vault.new(), ID, recipient=OTHER.recipient)

    def test_backup_kept(self, tmp_path):
        files = VaultFile(tmp_path)
        files.save(Vault.new(), ID, recipient=ID.recipient)
        files.save(Vault.new(), ID, recipient=ID.recipient)
        assert (tmp_path / (VAULT_FILE + ".bak")).exists()

    def test_symlink_refused(self, tmp_path):
        victim = tmp_path / "victim"
        victim.write_bytes(b"keep")
        (tmp_path / VAULT_FILE).symlink_to(victim)
        with pytest.raises(UnsafeEnvironment):
            VaultFile(tmp_path).save(Vault.new(), ID, recipient=ID.recipient)
        assert victim.read_bytes() == b"keep"


# ── fill ──────────────────────────────────────────────────────────────────────


class TestFill:
    def test_every_entity_gets_fakes(self):
        flat = flat_from()
        assert any(e.needs_generation for e in flat.entities)
        _, filled = generated(flat, Vault(seed=b"s" * 32))
        assert not any(e.needs_generation for e in filled.entities)
        assert all(len(e.real_forms) == len(e.fake_forms) for e in filled.entities)

    def test_deterministic_for_the_same_seed(self):
        a, _ = generated(flat_from(), Vault(seed=b"s" * 32))
        b, _ = generated(flat_from(), Vault(seed=b"s" * 32))
        assert a == b

    def test_different_seeds_differ(self):
        a, _ = generated(flat_from(), Vault(seed=b"s" * 32))
        b, _ = generated(flat_from(), Vault(seed=b"t" * 32))
        assert a["phones[0]"] != b["phones[0]"]

    def test_stored_fakes_win_over_regeneration(self):
        vault = Vault(seed=b"s" * 32)
        vault.put("phone", "+91 90000 00001", "+91 91111 22222")
        out, _ = generated(flat_from(), vault)
        assert out["phones[0]"]["+91 90000 00001"] == "+91 91111 22222"
        assert out["phones[0]"]["9000000001"] == "9111122222"

    def test_vault_records_new_fakes_and_only_then_is_dirty(self):
        vault = Vault(seed=b"s" * 32)
        generated(flat_from(), vault)
        assert vault.dirty
        assert len(vault.entries) == 4
        vault.dirty = False
        generated(flat_from(), vault)
        assert not vault.dirty

    def test_persona_date_shift_is_used(self):
        out, _ = generated(flat_from(), Vault(seed=b"s" * 32))
        assert out["person.date_of_birth"]["14/03/2001"] == "05/02/2001"  # fixture: -37 days

    def test_zero_shift_gets_a_stored_random_shift(self):
        text = FIXTURE.read_text().replace('date_shift_days: "-37"', "date_shift_days: 0")
        vault = Vault(seed=b"s" * 32)
        out, _ = generated(flat_from(text), vault)
        assert vault.shift_days is not None
        assert 30 <= abs(vault.shift_days) <= 365
        assert out["person.date_of_birth"]["14/03/2001"] != "14/03/2001"

    def test_unparseable_shift_date_falls_back_to_shape(self):
        text = FIXTURE.read_text().replace('"14/03/2001"', '"14th March"')
        out, _ = generated(flat_from(text), Vault(seed=b"s" * 32))
        fake = out["person.date_of_birth"]["14th March"]
        assert fake != "14th March"
        assert len(fake) == len("14th March")

    def test_stored_fake_that_now_collides_is_replaced(self):
        vault = Vault(seed=b"s" * 32)
        vault.put("employee_id", "E-1001", "Globex")  # collides with work[0].employer's fake
        out, _ = generated(flat_from(), vault)
        assert out["work[0].employee_id"]["E-1001"] != "Globex"

    def test_fails_closed_when_no_unique_fake_exists(self, monkeypatch):
        from veil.engine import fill as fill_module

        class NothingIsFree(fill_module._Taken):
            def free(self, real, fake):
                return False

        monkeypatch.setattr(fill_module, "_Taken", NothingIsFree)
        flat = flat_from('version: "1"\nids:\n  passport: { real: "7", fake: "", policy: FPE }\n')
        with pytest.raises(ValidationFailed, match=f"after {MAX_ATTEMPTS} attempts") as info:
            fill_generated(flat, Vault(seed=b"s" * 32))
        assert "ids.passport" in str(info.value)
        assert "7" not in str(info.value).replace(str(MAX_ATTEMPTS), "")

    def test_no_generation_needed_returns_same_object(self):
        flat = flat_from('version: "1"\nperson:\n  first_name: { real: Jane, fake: Alex }\n')
        assert fill_generated(flat, Vault.new()) is flat


class TestBijectionAndEngine:
    def test_filled_persona_passes_expanded_validation(self):
        _, filled = generated(flat_from(), Vault(seed=b"s" * 32))
        assert validate_expanded(expand_all(filled)) == []

    def test_generated_fakes_never_collide_with_other_forms(self):
        _, filled = generated(flat_from(), Vault(seed=b"s" * 32))
        generated_ids = {
            "person.date_of_birth",
            "phones[0]",
            "education[0].roll_number",
            "work[0].employee_id",
        }
        others = {
            canon(f)
            for e in filled.entities
            if e.id not in generated_ids
            for f in (*e.real_forms, *e.fake_forms)
        }
        for e in filled.entities:
            if e.id in generated_ids:
                assert not {canon(f) for f in e.fake_forms} & others

    @pytest.mark.parametrize(
        "text",
        [
            "call +91 90000 00001 or 9000000001",
            "born 14/03/2001, i.e. 14 March 2001 (2001-03-14)",
            "roll 2024701001, emp E-1001",
        ],
    )
    def test_engine_round_trip(self, text):
        _, filled = generated(flat_from(), Vault(seed=b"s" * 32))
        engine = Engine(build_lexicon(filled))
        out = engine.forward(text)
        for real in REALS:
            assert real not in out
        assert engine.reverse(out) == text

    @pytest.mark.parametrize("seed_byte", range(8))
    def test_many_seeds_stay_bijective(self, seed_byte):
        _, filled = generated(flat_from(), Vault(seed=bytes([seed_byte]) * 32))
        assert validate_expanded(expand_all(filled)) == []
