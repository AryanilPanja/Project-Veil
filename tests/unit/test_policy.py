import pytest

from veil.persona.policy import REVERSIBLE, Policy, default_policy, effective_policy, is_allowed


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("person.first_name", Policy.SWAP),
        ("handles.github", Policy.SWAP),
        ("handles.orcid", Policy.FPE),
        ("handles.google_scholar_id", Policy.FPE),
        ("ids.pan", Policy.FPE),
        ("ids.bank_accounts[0]", Policy.FPE),
        ("phones[2]", Policy.FPE),
        ("sensitive.health", Policy.ASK),
        ("footprint.paper_titles[0]", Policy.GENERALIZE),
        ("infra.ip_addresses", Policy.FPE),
        ("infra.mac_addresses", Policy.FPE),
        ("infra.hostname", Policy.SWAP),
        ("education[0].roll_number", Policy.FPE),
        ("education[3].roll_number", Policy.FPE),
        ("work[1].employee_id", Policy.FPE),
        ("education[0].institution", Policy.SWAP),
        ("ids.address[0]", Policy.SWAP),  # field default beats the `ids` section default
        ("ids.pin_codes[0]", Policy.FPE),
        ("footprint.public_repo_names[0]", Policy.SWAP),
        ("footprint.thesis_title", Policy.GENERALIZE),
        ("idsx.thing", Policy.SWAP),  # prefix must match a whole segment
        ("sensitive_notes", Policy.SWAP),
        ("", Policy.SWAP),
    ],
)
def test_default_policy(path, expected):
    assert default_policy(path) is expected


def test_explicit_policy_wins():
    assert effective_policy(Policy.KEEP, "ids.pan") is Policy.KEEP
    assert effective_policy(None, "ids.pan") is Policy.FPE


@pytest.mark.parametrize(
    ("policy", "path", "allowed"),
    [
        (Policy.ASK, "sensitive.health", True),
        (Policy.ASK, "person.first_name", False),
        (Policy.SWAP_NAME_ONLY, "attributes.pets[0]", True),
        (Policy.SWAP_NAME_ONLY, "attributes.first_pet_name", False),
        (Policy.SHIFT, "person.date_of_birth", True),
        (Policy.SHIFT, "person.first_name", False),
        (Policy.SWAP, "anything.at.all", True),
        (Policy.KEEP, "ids.pan", True),
        (Policy.GENERALIZE, "education[0].research_area", True),
    ],
)
def test_is_allowed(policy, path, allowed):
    assert is_allowed(policy, path) is allowed


def test_reversible_set():
    assert Policy.GENERALIZE not in REVERSIBLE
    assert Policy.KEEP not in REVERSIBLE
    assert Policy.ASK not in REVERSIBLE
    assert {Policy.SWAP, Policy.FPE, Policy.SHIFT} <= REVERSIBLE


def test_policy_values_are_their_names():
    for policy in Policy:
        assert policy.value == policy.name
        assert isinstance(policy, str)
