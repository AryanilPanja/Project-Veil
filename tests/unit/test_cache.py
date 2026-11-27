"""engine/cache.py + load.py warm path (ADR-0029): same results, strictly optional, invalidated."""

import io
import shutil
import sys
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.conftest import run_python
from tests.unit.test_check_cli import FIXTURE
from veil import cli
from veil.crypto import age
from veil.crypto.keystore import SERVICE, KeyStore, keyring_username
from veil.engine import cache as cache_module
from veil.engine import load as load_module
from veil.engine.cache import CACHE_FILE, CacheFile, cache_key, decode, encode
from veil.engine.fill import fill_generated
from veil.engine.lexicon import build_lexicon
from veil.engine.matcher import Engine
from veil.engine.vault import Vault
from veil.exitcodes import ExitCode
from veil.persona.entities import flatten
from veil.persona.schema import parse_persona
from veil.persona.store import PersonaStore
from veil.persona.yamlio import load_yaml

ID = age.generate_identity()
OTHER = age.generate_identity()
SAMPLES = [
    "Jane Doe (jane.doe@xyz.example.test), MS thesis at XYZIT, 2nd year",
    "Call +91 90000 00001; born 14/03/2001; /home/janed/jane-thesis",
    "ssh orion and JDoe and Ravi Kumar, জেন লিখেছে",
]


@pytest.fixture(scope="module")
def lexicon():
    flat = flatten(parse_persona(load_yaml(FIXTURE.read_bytes())))
    return build_lexicon(fill_generated(flat, Vault(seed=b"s" * 32)))


# ── encode / decode ───────────────────────────────────────────────────────────


class TestCodec:
    def test_round_trip_gives_the_same_translations(self, lexicon):
        again = decode(encode(lexicon, "k1"), "k1")
        assert again is not None
        a, b = Engine(lexicon), Engine(again)
        for text in SAMPLES:
            assert b.forward(text) == a.forward(text)
            assert b.reverse(a.forward(text)) == a.reverse(a.forward(text))
            assert b.audit(text) == a.audit(text)
            assert b.ambiguous(text) == a.ambiguous(text)

    def test_round_trip_keeps_structure(self, lexicon):
        again = decode(encode(lexicon, "k"), "k")
        assert len(again.forward) == len(lexicon.forward)
        assert len(again.reverse) == len(lexicon.reverse)
        assert again.never_translate == lexicon.never_translate
        assert again.never_reverse == lexicon.never_reverse
        assert [f.entity.contexts for f in again.forward] == [
            f.entity.contexts for f in lexicon.forward
        ]
        assert [f.entity.meta for f in again.reverse] == [f.entity.meta for f in lexicon.reverse]

    def test_wrong_key_is_a_miss(self, lexicon):
        assert decode(encode(lexicon, "k1"), "k2") is None

    @pytest.mark.parametrize(
        "blob",
        [b"", b"not json", b"[]", b'{"format": 99, "key": "k"}', b'{"format": 1, "key": "k"}'],
    )
    def test_malformed_is_a_miss(self, blob):
        assert decode(blob, "k") is None

    def test_tampered_entity_kind_is_a_miss(self, lexicon):
        blob = encode(lexicon, "k").replace(b'"kind":"name"', b'"kind":"bogus"', 1)
        assert decode(blob, "k") is None

    @settings(max_examples=100)
    @given(st.lists(st.sampled_from([*SAMPLES, "the", "Janet", "42", "\n", "Alex"]), max_size=8))
    def test_property_cached_engine_equals_built_engine(self, lexicon, parts):
        text = " ".join(parts)
        cached = Engine(decode(encode(lexicon, "k"), "k"))
        built = Engine(lexicon)
        assert cached.forward(text) == built.forward(text)
        assert cached.reverse(text) == built.reverse(text)


class TestKey:
    def test_every_input_matters(self, monkeypatch):
        base = cache_key(b"persona", b"vault")
        assert cache_key(b"persona!", b"vault") != base
        assert cache_key(b"persona", b"vault!") != base
        monkeypatch.setattr(cache_module, "code_fingerprint", lambda: "other-code")
        assert cache_key(b"persona", b"vault") != base

    def test_no_ambiguous_concatenation(self):
        assert cache_key(b"ab", b"c") != cache_key(b"a", b"bc")

    def test_code_fingerprint_is_stable(self):
        assert cache_module.code_fingerprint() == cache_module.code_fingerprint()
        assert len(cache_module.code_fingerprint()) == 64


# ── the file ──────────────────────────────────────────────────────────────────


class TestCacheFile:
    def test_save_and_load(self, tmp_path, lexicon):
        files = CacheFile(tmp_path / "veil")
        assert files.save(lexicon, "k", recipient=ID.recipient)
        assert files.load(ID, "k") is not None
        assert (tmp_path / "veil" / CACHE_FILE).stat().st_mode & 0o777 == 0o600

    def test_encrypted_on_disk(self, tmp_path, lexicon):
        files = CacheFile(tmp_path)
        files.save(lexicon, "k", recipient=ID.recipient)
        raw = files.path.read_bytes()
        assert age.is_age(raw)
        for real in (b"Jane", b"jane.doe", b"Springfield", b"XYZIT"):
            assert real not in raw

    def test_missing_wrong_key_corrupt_or_symlink_all_mean_miss(self, tmp_path, lexicon):
        files = CacheFile(tmp_path)
        assert files.load(ID, "k") is None
        files.save(lexicon, "k", recipient=ID.recipient)
        assert files.load(OTHER, "k") is None
        assert files.load(ID, "other-key") is None
        files.path.write_bytes(b"garbage")
        assert files.load(ID, "k") is None
        files.path.unlink()
        target = tmp_path / "elsewhere"
        target.write_bytes(age.encrypt(encode(lexicon, "k"), ID.recipient))
        files.path.symlink_to(target)
        assert files.load(ID, "k") is None

    def test_save_failure_is_not_an_error(self, tmp_path, lexicon, monkeypatch):
        from veil import fsutil

        def full(*_a, **_k):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(fsutil.os, "write", full)
        assert CacheFile(tmp_path).save(lexicon, "k", recipient=ID.recipient) is False


# ── load_engine: warm and cold paths ──────────────────────────────────────────


@pytest.fixture
def imported(veil_home, tmp_path, capsys):
    source = tmp_path / "draft.yaml"
    shutil.copyfile(FIXTURE, source)
    assert cli.main(["persona", "import", str(source)]) == ExitCode.OK
    capsys.readouterr()
    return veil_home


def stores(home):
    return KeyStore(home.config, timeout=2), PersonaStore(home.config)


@pytest.fixture
def build_calls(monkeypatch):
    calls = []
    real = load_module._build

    def spy(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(load_module, "_build", spy)
    return calls


class TestWarmPath:
    @pytest.fixture(autouse=True)
    def _start_cold(self, imported):
        """The import already pre-warmed the cache; these tests start from a cold state."""
        (imported.config / CACHE_FILE).unlink(missing_ok=True)

    def test_first_run_builds_second_uses_cache(self, imported, build_calls):
        ks, st_ = stores(imported)
        first = load_module.load_engine(ks, st_)
        assert build_calls == [1]
        assert (imported.config / CACHE_FILE).exists()
        second = load_module.load_engine(ks, st_)
        assert build_calls == [1]  # warm: no rebuild
        for text in SAMPLES:
            assert second.forward(text) == first.forward(text)

    def test_persona_change_invalidates(self, imported, build_calls, tmp_path, capsys):
        ks, st_ = stores(imported)
        load_module.load_engine(ks, st_)
        source = tmp_path / "changed.yaml"
        source.write_text(FIXTURE.read_text().replace("fake: Rivertown }", "fake: Lakeside }"))
        assert cli.main(["persona", "import", "--replace", str(source)]) == ExitCode.OK
        engine = load_module.load_engine(ks, st_)
        assert build_calls == [1, 1]
        assert "Lakeside" in engine.forward("Springfield")

    def test_vault_change_invalidates(self, imported, build_calls):
        from veil.engine.vault import VaultFile

        ks, st_ = stores(imported)
        load_module.load_engine(ks, st_)
        identity = age.parse_identity(
            imported.ring.items[(SERVICE, keyring_username(imported.config))]
        )
        vault = VaultFile(imported.config).load(identity)
        vault.put("phone", "+91 90000 00001", "+91 91111 22222")
        VaultFile(imported.config).save(vault, identity, recipient=identity.recipient)
        engine = load_module.load_engine(ks, st_)
        assert build_calls == [1, 1]
        assert "+91 91111 22222" in engine.forward("+91 90000 00001")

    def test_code_change_invalidates(self, imported, build_calls, monkeypatch):
        ks, st_ = stores(imported)
        load_module.load_engine(ks, st_)
        monkeypatch.setattr(cache_module, "code_fingerprint", lambda: "new-code")
        load_module.load_engine(ks, st_)
        assert build_calls == [1, 1]

    def test_corrupt_cache_is_rebuilt_and_rewritten(self, imported, build_calls):
        ks, st_ = stores(imported)
        load_module.load_engine(ks, st_)
        (imported.config / CACHE_FILE).write_bytes(b"garbage")
        load_module.load_engine(ks, st_)
        assert build_calls == [1, 1]
        load_module.load_engine(ks, st_)
        assert build_calls == [1, 1]  # the rewritten cache is used again

    def test_cache_cannot_bypass_a_corrupt_store(self, imported):
        ks, st_ = stores(imported)
        load_module.load_engine(ks, st_)
        (imported.config / "persona.age").write_bytes(b"garbage")
        from veil.errors import DecryptFailed

        with pytest.raises(DecryptFailed):
            load_module.load_engine(ks, st_)

    def test_cache_cannot_bypass_a_missing_key(self, imported):
        ks, st_ = stores(imported)
        load_module.load_engine(ks, st_)
        imported.ring.items.clear()
        from veil.errors import KeyUnavailable

        with pytest.raises(KeyUnavailable):
            load_module.load_engine(ks, st_)

    def test_cli_output_identical_warm_and_cold(self, imported, monkeypatch, capsys):
        outputs = []
        for _ in range(2):
            monkeypatch.setattr(
                sys, "stdin", io.TextIOWrapper(io.BytesIO(SAMPLES[0].encode()), encoding="utf-8")
            )
            assert cli.main(["translate"]) == ExitCode.OK
            outputs.append(capsys.readouterr().out)
        assert outputs[0] == outputs[1]
        assert "Jane" not in outputs[0]


def test_warm_path_imports_neither_pydantic_nor_yaml(imported, tmp_path):
    """The point of ADR-0029: a warm translate never loads the schema stack."""
    ks, st_ = stores(imported)
    load_module.load_engine(ks, st_)  # create vault + cache
    import json
    import os

    ring = json.dumps({"|".join(k): v for k, v in imported.ring.items.items()})
    script = f"""
import json, os, sys
sys.path.insert(0, {str(Path(__file__).resolve().parents[2])!r})
os.environ["XDG_CONFIG_HOME"] = {str(imported.config.parent)!r}
from tests.helpers.memkeyring import MemoryKeyring
from veil.crypto import keystore
ring = MemoryKeyring()
ring.items.update({{tuple(k.split("|")): v for k, v in json.loads({ring!r}).items()}})
keystore.secret_service_backend = lambda: ring
from veil.crypto.keystore import KeyStore
from veil.persona.store import PersonaStore
from veil.engine.load import load_engine
from pathlib import Path
cfg = Path(os.environ["XDG_CONFIG_HOME"]) / "veil"
engine = load_engine(KeyStore(cfg), PersonaStore(cfg))
assert "Alex" in engine.forward("Jane")
print(sorted(m for m in ("pydantic", "yaml") if m in sys.modules))
"""
    result = run_python(script)
    assert result.returncode == 0, result.stderr[-500:]
    assert result.stdout.strip() == "[]"
    assert os.environ.get("XDG_CONFIG_HOME")  # the sandbox, never the real config


class TestPrewarm:
    def test_import_prewarms_the_cache(self, imported, build_calls):
        assert (imported.config / CACHE_FILE).exists()
        ks, st_ = stores(imported)
        load_module.load_engine(ks, st_)
        assert build_calls == []  # already warm right after import

    def test_replace_import_prewarms_for_the_new_payload(
        self, imported, build_calls, tmp_path, capsys
    ):
        source = tmp_path / "changed.yaml"
        source.write_text(FIXTURE.read_text().replace("fake: Rivertown }", "fake: Lakeside }"))
        assert cli.main(["persona", "import", "--replace", str(source)]) == ExitCode.OK
        ks, st_ = stores(imported)
        engine = load_module.load_engine(ks, st_)
        assert build_calls == [1]  # only the prewarm inside the import built it
        assert "Lakeside" in engine.forward("Springfield")

    def test_prewarm_failure_never_fails_the_import(self, veil_home, tmp_path, capsys, monkeypatch):
        def broken(*_a, **_k):
            raise RuntimeError("cache build exploded")

        monkeypatch.setattr(load_module, "load_engine", broken)
        source = tmp_path / "draft.yaml"
        shutil.copyfile(FIXTURE, source)
        assert cli.main(["persona", "import", str(source)]) == ExitCode.OK
        assert "exploded" not in capsys.readouterr().err
