"""Translation policies and their section defaults (ADR-0026)."""

from enum import StrEnum


class Policy(StrEnum):
    SWAP = "SWAP"  # realistic surrogate
    FPE = "FPE"  # format-preserving fake (empty fake → generated in M1)
    SHIFT = "SHIFT"  # constant offset (dates)
    GENERALIZE = "GENERALIZE"  # one-way replacement with a coarser phrase
    REDACT = "REDACT"  # format-valid dummy (secrets)
    KEEP = "KEEP"  # pass through
    ASK = "ASK"  # ask before sending (special categories)
    SWAP_NAME_ONLY = "SWAP_NAME_ONLY"  # pets: swap the name, keep species/breed


# Default policy by field-path prefix; the longest matching prefix wins. Anything else is SWAP.
SECTION_DEFAULTS: dict[str, Policy] = {
    "ids": Policy.FPE,
    "phones": Policy.FPE,
    "sensitive": Policy.ASK,
    "footprint": Policy.GENERALIZE,
    "infra.ip_addresses": Policy.FPE,
    "infra.mac_addresses": Policy.FPE,
    "handles.google_scholar_id": Policy.FPE,
    "handles.orcid": Policy.FPE,
}

# Leaf names whose default overrides their section's, wherever they appear.
FIELD_DEFAULTS: dict[str, Policy] = {
    "roll_number": Policy.FPE,
    "employee_id": Policy.FPE,
    "address": Policy.SWAP,  # under `ids`, but an address is a realistic swap, not a token
    "public_repo_names": Policy.SWAP,  # under `footprint`, but a repo name is a name to swap
}

# Where a policy may be used at all (checked by the validator, E020). None = anywhere.
ALLOWED_SECTIONS: dict[Policy, tuple[str, ...] | None] = {
    Policy.ASK: ("sensitive",),
    Policy.SWAP_NAME_ONLY: ("attributes.pets",),
    Policy.SHIFT: ("person.date_of_birth",),
}

REVERSIBLE: frozenset[Policy] = frozenset(
    {Policy.SWAP, Policy.FPE, Policy.SHIFT, Policy.REDACT, Policy.SWAP_NAME_ONLY}
)


def default_policy(path: str) -> Policy:
    """Default policy for a dotted field path like 'education[0].roll_number'."""
    plain = _strip_indices(path)
    leaf = plain.rsplit(".", 1)[-1]
    if leaf in FIELD_DEFAULTS:
        return FIELD_DEFAULTS[leaf]
    best: Policy | None = None
    best_len = -1
    for prefix, policy in SECTION_DEFAULTS.items():
        if (plain == prefix or plain.startswith(prefix + ".")) and len(prefix) > best_len:
            best, best_len = policy, len(prefix)
    return best if best is not None else Policy.SWAP


def effective_policy(explicit: Policy | None, path: str) -> Policy:
    return explicit if explicit is not None else default_policy(path)


def is_allowed(policy: Policy, path: str) -> bool:
    sections = ALLOWED_SECTIONS.get(policy)
    if sections is None:
        return True
    plain = _strip_indices(path)
    return any(plain == s or plain.startswith(s + ".") for s in sections)


def _strip_indices(path: str) -> str:
    out: list[str] = []
    depth = 0
    for ch in path:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)
