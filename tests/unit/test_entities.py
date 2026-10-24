"""Flattening a persona into entities: the M0 → M1 contract."""

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel

from veil.persona import schema
from veil.persona.entities import Entity, FlatPersona, flatten
from veil.persona.policy import Policy
from veil.persona.schema import Persona, parse_persona
from veil.persona.walk import EntityKind, PairRecord, iter_pair_records
from veil.persona.yamlio import load_yaml

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "synthetic_jane.yaml"
TEMPLATE = ROOT / "persona.example.yaml"
V = 'version: "1"\n'


def flat_of(doc: str) -> FlatPersona:
    return flatten(parse_persona(load_yaml(doc)))


@pytest.fixture(scope="module")
def flat() -> FlatPersona:
    return flatten(parse_persona(load_yaml(FIXTURE.read_bytes())))


@pytest.fixture(scope="module")
def by_id(flat) -> dict[str, Entity]:
    return {e.id: e for e in flat.entities}


# ── What comes out of the synthetic persona ───────────────────────────────────


@pytest.mark.parametrize(
    ("entity_id", "kind", "policy", "reals", "fakes"),
    [
        ("person.first_name", EntityKind.NAME, Policy.SWAP, ("Jane",), ("Alex",)),
        ("person.full_name", EntityKind.NAME, Policy.SWAP, ("Jane Doe",), ("Alex Smith",)),
        ("person.name_in_other_scripts[2]", EntityKind.NAME, Policy.SWAP, ("ஜேன்",), ("அலெக்ஸ்",)),
        (
            "person.hometown",
            EntityKind.PLACE,
            Policy.SWAP,
            ("Springfield", "Springfield City"),
            ("Rivertown", "Rivertown City"),
        ),
        (
            "education[0].institution",
            EntityKind.ORG,
            Policy.SWAP,
            ("XYZ Institute of Technology", "XYZIT", "XYZ-IT"),
            ("ABC University", "ABCU", "ABC-U"),
        ),
        (
            "education[0].domain",
            EntityKind.DOMAIN,
            Policy.SWAP,
            ("xyz.example.test", "research.xyz.example.test"),
            ("abc.example.test", "research.abc.example.test"),
        ),
        (
            "education[0].lab",
            EntityKind.ORG,
            Policy.SWAP,
            ("Vision Lab", "VL"),
            ("Signal Group", "SG"),
        ),
        (
            "education[0].degree.phrases",
            EntityKind.CLASS_TERM,
            Policy.SWAP,
            ("MS student", "my MS", "MS thesis"),
            ("PhD student", "my PhD", "PhD thesis"),
        ),
        ("education[0].year_of_study", EntityKind.YEAR, Policy.SWAP, ("2",), ("3",)),
        (
            "education[0].advisor",
            EntityKind.PERSON_NAME,
            Policy.SWAP,
            ("Prof. Mary Major", "M. Major", "mmajor"),
            ("Prof. Ann Minor", "A. Minor", "aminor"),
        ),
        ("people[3]", EntityKind.PERSON_NAME, Policy.SWAP, ("Ravi Kumar",), ("Om Prakash",)),
        ("infra.home_dir", EntityKind.PATH, Policy.SWAP, ("/home/janed",), ("/home/alexs",)),
        (
            "ids.address[0]",
            EntityKind.ADDRESS,
            Policy.SWAP,
            ("1 Example Street Springfield",),
            ("9 Sample Road Rivertown",),
        ),
        ("ids.pin_codes[0]", EntityKind.POSTAL_CODE, Policy.FPE, ("000001",), ("999999",)),
        (
            "footprint.public_repo_names[0]",
            EntityKind.TOKEN,
            Policy.SWAP,
            ("ocr-toolkit",),
            ("vision-toolkit",),
        ),
    ],
)
def test_entities(by_id, entity_id, kind, policy, reals, fakes):
    entity = by_id[entity_id]
    assert entity.kind is kind
    assert entity.policy is policy
    assert entity.real_forms == reals
    assert entity.fake_forms == fakes
    assert entity.needs_generation is False


@pytest.mark.parametrize(
    "entity_id",
    [
        "phones[0]",
        "education[0].roll_number",
        "work[0].employee_id",
        "person.date_of_birth",  # SHIFT with an empty fake
    ],
)
def test_empty_fake_with_fpe_or_shift_needs_generation(by_id, entity_id):
    entity = by_id[entity_id]
    assert entity.needs_generation is True
    assert entity.fake_forms == ()
    assert entity.real_forms != ()


@pytest.mark.parametrize(
    "excluded",
    [
        "person.current_city",  # KEEP
        "person.languages",  # KEEP
        "person.gender",  # f → f: identical, nothing to translate
        "person.pronouns",  # identical
        "person.middle_name",  # empty
        "education[0].department",  # KEEP
        "education[0].research_area",  # enabled: false
        "education[1].board",  # KEEP
        "work[0].role",  # KEEP
        "attributes.favourite_food",  # KEEP
        "attributes.hobbies[0]",  # KEEP
        "attributes.pets[0].species",  # SWAP_NAME_ONLY keeps species (cat → cat anyway)
        "ids.aadhaar",  # empty real
        "handles.gitlab",  # empty
    ],
)
def test_excluded_fields_produce_no_entity(flat, excluded):
    assert all(excluded not in e.sources for e in flat.entities)


def test_identical_pairs_from_different_fields_are_merged(by_id):
    assert by_id["handles.linux_user"].sources == ("handles.linux_user", "infra.hostname")
    assert by_id["education[1].institution"].sources == (
        "education[1].institution",
        "attributes.first_school",
    )
    assert by_id["attributes.pets[0].name"].sources == (
        "attributes.pets[0].name",
        "attributes.first_pet_name",
    )
    assert "infra.hostname" not in by_id  # merged, not a separate entity


def test_forms_are_index_aligned(flat):
    for entity in flat.entities:
        if not entity.needs_generation:
            assert len(entity.real_forms) == len(entity.fake_forms), entity.id
        assert all(form.strip() for form in entity.real_forms), entity.id


def test_no_kept_or_asked_policies_and_reversibility(flat):
    for entity in flat.entities:
        assert entity.policy not in (Policy.KEEP, Policy.ASK)
        assert entity.reversible is (entity.policy is not Policy.GENERALIZE)


def test_generalize_entity_is_one_way(by_id):
    paper = by_id["footprint.paper_titles[0]"]
    assert paper.policy is Policy.GENERALIZE
    assert paper.reversible is False


def test_contexts_allow_short_and_meta_are_carried(by_id):
    assert by_id["infra.clusters[0]"].contexts == ("ssh", "slurm", "cluster")
    assert by_id["person.nicknames[0]"].allow_short is True
    assert by_id["people[0]"].meta_value("relation") == "father"
    assert by_id["attributes.custom[0]"].meta_value("category") == "club"
    assert by_id["education[0].year_of_study"].meta_value("context_required") == "true"
    assert by_id["person.first_name"].meta_value("missing", "default") == "default"


def test_sensitive_terms_pattern_rules_and_settings(flat):
    [health] = flat.sensitive  # empty categories are skipped
    assert (health.category, health.terms, health.policy) == ("health", ("asthma",), Policy.ASK)
    assert health.generalized == "a chronic condition"
    assert {(r.kind, r.policy) for r in flat.pattern_rules} == {
        ("ip", Policy.FPE),
        ("mac", Policy.FPE),
    }
    assert flat.never_translate == frozenset({"Ruby", "Julia"})
    assert flat.never_reverse == frozenset({"Alex Smith Stadium"})
    assert flat.settings.date_shift_days == -37
    assert flat.settings.ask_timeout_seconds == 120
    assert flat.settings.sensitive_default is Policy.ASK
    assert flat.canary == ""


def test_flatten_is_deterministic(flat):
    again = flatten(parse_persona(load_yaml(FIXTURE.read_bytes())))
    assert again == flat
    assert [e.id for e in again.entities] == [e.id for e in flat.entities]


def test_order_follows_the_schema(flat):
    ids = [e.id for e in flat.entities]
    assert (
        ids.index("person.first_name")
        < ids.index("emails[0]")
        < ids.index("education[0].institution")
    )
    assert (
        ids.index("education[0].institution")
        < ids.index("work[0].employer")
        < ids.index("people[0]")
    )


def test_template_flattens_to_nothing():
    flat = flatten(parse_persona(load_yaml(TEMPLATE.read_bytes())))
    assert flat.entities == ()
    assert flat.sensitive == ()
    assert flat.never_translate == frozenset({"Ruby", "Julia"})


# ── Rules on small documents ──────────────────────────────────────────────────


def test_empty_fake_without_fpe_or_shift_is_not_emitted():
    """E016 (validator): the engine never receives an entity it cannot apply."""
    assert flat_of(V + "person: {first_name: {real: Jane, fake: ''}}\n").entities == ()


def test_partially_filled_list_is_not_emitted():
    doc = (
        V
        + "education: [{institution: {real: A Inst, fake: B Inst}, "
        + "aliases: {real: [AI], fake: ['']}}]\n"
    )
    assert flat_of(doc).entities == ()


def test_unequal_lists_keep_the_aligned_prefix():
    doc = (
        V
        + "education: [{institution: {real: A Inst, fake: B Inst}, "
        + "aliases: {real: [AI, AX], fake: [BI]}}]\n"
    )
    [entity] = flat_of(doc).entities
    assert entity.real_forms == ("A Inst", "AI")
    assert entity.fake_forms == ("B Inst", "BI")


def test_empty_list_slots_are_dropped_pairwise():
    doc = (
        V
        + "education: [{institution: {real: A Inst, fake: B Inst}, "
        + "aliases: {real: ['', AI], fake: [X, BI]}}]\n"
    )
    [entity] = flat_of(doc).entities
    assert entity.real_forms == ("A Inst", "AI")
    assert entity.fake_forms == ("B Inst", "BI")


def test_identity_is_judged_canonically():
    assert flat_of(V + "person: {first_name: {real: Jane, fake: JANE}}\n").entities == ()


def test_explicit_policy_overrides_the_section_default():
    [entity] = flat_of(
        V + "ids: {pan: {real: ABCDE1234F, fake: ZZZZZ9999Z, policy: SWAP}}\n"
    ).entities
    assert entity.policy is Policy.SWAP


def test_disabled_degree_and_year_are_excluded():
    doc = V + (
        "education: [{degree: {enabled: false, phrases: {real: [MS student], fake: [PhD student]}},"
        " year_of_study: {enabled: false, real: '2', fake: '3'}}]\n"
    )
    assert flat_of(doc).entities == ()


def test_year_needs_both_numbers():
    doc = V + "education: [{year_of_study: {enabled: true, real: '2', fake: ''}}]\n"
    assert flat_of(doc).entities == ()


def test_degree_word_alone_is_never_an_entity():
    doc = V + "education: [{degree: {enabled: true, real: MS, fake: PhD}}]\n"
    assert flat_of(doc).entities == ()


@pytest.mark.parametrize(
    ("pet_policy", "expected_ids"),
    [
        ("SWAP_NAME_ONLY", {"attributes.pets[0].name"}),
        ("", {"attributes.pets[0].name"}),  # unset behaves like SWAP_NAME_ONLY
        (
            "SWAP",
            {"attributes.pets[0].name", "attributes.pets[0].species", "attributes.pets[0].breed"},
        ),
        ("KEEP", set()),
    ],
)
def test_pet_policies(pet_policy, expected_ids):
    doc = V + (
        "attributes: {pets: [{species: {real: cat, fake: dog}, name: {real: Mochi, fake: Bruno},"
        f" breed: {{real: tabby, fake: pug}}, policy: '{pet_policy}'}}]}}\n"
    )
    assert {e.id for e in flat_of(doc).entities} == expected_ids


def test_pet_sub_pair_policy_wins():
    doc = V + (
        "attributes: {pets: [{species: {real: cat, fake: dog, policy: SWAP},"
        " name: {real: Mochi, fake: Bruno}, policy: SWAP_NAME_ONLY}]}\n"
    )
    assert {e.id for e in flat_of(doc).entities} == {
        "attributes.pets[0].name",
        "attributes.pets[0].species",
    }


def test_custom_attribute_without_category():
    [entity] = flat_of(V + "attributes: {custom: [{real: a club, fake: b club}]}\n").entities
    assert entity.role == "custom"


def test_sensitive_entry_without_policy_uses_default():
    doc = (
        V
        + "sensitive: {default_policy: GENERALIZE, health: {real: [x-condition], generalized: g}}\n"
    )
    [term] = flat_of(doc).sensitive
    assert term.policy is Policy.GENERALIZE


def test_kept_pattern_rule_is_dropped():
    doc = V + "infra: {ip_addresses: {policy: KEEP}}\n"
    assert {r.kind for r in flat_of(doc).pattern_rules} == {"mac"}


def test_blank_never_lists_are_ignored():
    flat = flat_of(V + "never_translate: ['', '  ', Ruby]\nnever_reverse: ['']\n")
    assert flat.never_translate == frozenset({"Ruby"})
    assert flat.never_reverse == frozenset()


def test_merge_combines_contexts_and_flags():
    doc = V + (
        "handles: {linux_user: {real: janed, fake: alexs, contexts: [ssh]}}\n"
        "infra: {hostname: {real: janed, fake: alexs, contexts: [ssh, host], allow_short: true}}\n"
    )
    [entity] = flat_of(doc).entities
    assert entity.contexts == ("ssh", "host")
    assert entity.allow_short is True


# ── Redaction ─────────────────────────────────────────────────────────────────


def test_repr_never_contains_values(flat):
    texts = [repr(flat), *(repr(e) for e in flat.entities), *(repr(t) for t in flat.sensitive)]
    for text in texts:
        for value in ("Jane", "Alex", "asthma", "janed", "Springfield", "জেন"):
            assert value not in text


def test_pair_record_repr_is_redacted():
    persona = parse_persona(load_yaml(FIXTURE.read_bytes()))
    for record in iter_pair_records(persona):
        assert "Jane" not in repr(record)
        assert "Alex" not in repr(record)


# ── Coverage: every Pair/ListPair in the schema is walked ─────────────────────

NOT_WALKED = {"education[0].advisor.title"}  # template material, not an identity


def _pair_paths(model: type[BaseModel], base: str) -> list[str]:
    """All paths to Pair / ListPair nodes, using index [0] for lists."""
    out: list[str] = []
    for name, field in model.model_fields.items():
        path = f"{base}.{name}" if base else name
        inner = schema._model_in(field.annotation)
        if inner is None:
            continue
        is_list = "tuple" in str(field.annotation)
        target = f"{path}[0]" if is_list else path
        if issubclass(inner, schema.Pair) or issubclass(inner, schema.ListPair):
            out.append(target)
        if inner not in (schema.Pair, schema.ListPair):
            out.extend(_pair_paths(inner, target))
    return out


def _fill(model: type[BaseModel], counter: list[int]) -> dict:
    """A document where every Pair has a unique real/fake and every list has one item."""
    doc: dict = {}
    for name, field in model.model_fields.items():
        inner = schema._model_in(field.annotation)
        if inner is None:
            continue
        if issubclass(inner, schema.ListPair):
            counter[0] += 1
            value = {"real": [f"rl{counter[0]}x"], "fake": [f"fk{counter[0]}x"]}
        elif issubclass(inner, schema.Pair):
            counter[0] += 1
            value = {
                "real": f"rl{counter[0]}x",
                "fake": f"fk{counter[0]}x",
                **_fill_extra(inner, counter),
            }
        elif inner is schema.ClassTerm:
            counter[0] += 1
            value = {
                "enabled": True,
                "phrases": {"real": [f"rl{counter[0]}x"], "fake": [f"fk{counter[0]}x"]},
            }
        elif inner is schema.YearOfStudy:
            value = {"enabled": True, "real": "2", "fake": "3"}
        elif inner in (schema.PolicyOnly, schema.SensitiveEntry, schema.Numbers, schema.Sensitive):
            continue
        else:
            value = _fill(inner, counter)
        is_list = "tuple" in str(field.annotation)
        doc[name] = [value] if is_list else value
    return doc


def _fill_extra(model: type[BaseModel], counter: list[int]) -> dict:
    extra = _fill(model, counter)
    for key in ("real", "fake", "policy", "allow_short", "contexts", "enabled"):
        extra.pop(key, None)
    return extra


def test_every_pair_field_in_the_schema_is_walked():
    doc = {"version": "1", **_fill(Persona, [0])}
    persona = parse_persona(doc)
    walked = {r.path for r in iter_pair_records(persona)}
    # grouped records are reported at their head path; their extra lists count as walked
    grouped_extras = {
        "person.hometown_aliases": "person.hometown",
        "aliases": "institution",
        "sub_domains": "domain",
        "lab.aliases": "lab",
        "advisor.forms": "advisor",
        "degree.phrases": "degree.phrases",
    }
    missing = []
    for path in _pair_paths(Persona, ""):
        if path in NOT_WALKED or path.startswith("footprint.profile_urls"):
            continue
        if path in walked:
            continue
        matches = [k for k in grouped_extras if path.endswith(k)]
        key = max(matches, key=len) if matches else None  # most specific rule wins
        head = path[: -len(key)] + grouped_extras[key] if key else None
        if head in walked:
            continue
        missing.append(path)
    assert missing == []


def test_filled_document_entities_are_all_distinct():
    persona = parse_persona({"version": "1", **_fill(Persona, [0])})
    flat = flatten(persona)
    reals = [form for e in flat.entities for form in e.real_forms]
    assert len(reals) == len(set(reals))


# ── Properties ────────────────────────────────────────────────────────────────

names = st.text(alphabet="abcdefghij", min_size=3, max_size=6)


@given(st.lists(st.tuples(names, names), max_size=8))
def test_people_flatten_to_one_entity_per_distinct_pair(pairs):
    doc = {"version": "1", "people": [{"real": r, "fake": f} for r, f in pairs]}
    flat = flatten(parse_persona(doc))
    expected = {(r.casefold(), f.casefold()) for r, f in pairs if r.casefold() != f.casefold()}
    got = {(e.real_forms[0].casefold(), e.fake_forms[0].casefold()) for e in flat.entities}
    assert got == expected
    # Each source appears exactly once across all entities
    sources = [s for e in flat.entities for s in e.sources]
    assert len(sources) == len(set(sources))


@given(st.lists(st.tuples(names, names), min_size=1, max_size=6))
def test_flatten_never_returns_kept_or_empty_entities(pairs):
    doc = {
        "version": "1",
        "emails": [{"real": r, "fake": f} for r, f in pairs],
        "phones": [{"real": r, "fake": "", "policy": "FPE"} for r, _ in pairs],
    }
    for entity in flatten(parse_persona(doc)).entities:
        assert entity.real_forms
        assert entity.policy not in (Policy.KEEP, Policy.ASK)
        assert entity.needs_generation == (entity.fake_forms == ())


def test_pair_record_is_a_value_object():
    record = PairRecord(path="x", kind=EntityKind.TOKEN, role="r", reals=("a",), fakes=("b",))
    assert record == PairRecord(
        path="x", kind=EntityKind.TOKEN, role="r", reals=("a",), fakes=("b",)
    )
