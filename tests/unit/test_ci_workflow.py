"""CI workflow pinning and dependency-audit checks (W3, issues #32 and #33).

The YAML is parsed with PyYAML's SafeLoader and the comments are checked against the raw text:
PyYAML discards comments, so a pin can only be verified end-to-end by reading both. Ruff TID251
bans `yaml.safe_load` in this repo; `SafeLoader(...).get_single_data()` is the equivalent safe
parse.

Pins are checked by shape, never against fixed SHAs or versions (T5): Dependabot bumps the
pin and its version comment without this suite going red.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
DEPENDABOT = ROOT / ".github" / "dependabot.yml"
CONTRIBUTING = ROOT / "CONTRIBUTING.md"

REQUIRED_JOB_NAMES = frozenset({"DCO sign-off", "lint + tests (Python 3.13)"})
EXPECTED_REPOS = frozenset({"actions/checkout", "astral-sh/setup-uv"})
ERROR_CODES = frozenset({"not-a-uses-line", "bad-ref", "not-full-sha", "bad-version-comment"})
SHA = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)\s*(?:#\s*(.*?))?\s*$")
VERSION_COMMENT = re.compile(r"^v\d+(?:\.\d+)*$")


def _yaml(text: str) -> dict[str, object]:
    """Safe YAML parse (equivalent to safe_load, which ruff bans here)."""
    loader = yaml.SafeLoader(text)
    try:
        data = loader.get_single_data()
    finally:
        loader.dispose()
    assert isinstance(data, dict)
    return data


def _uses_lines() -> list[str]:
    return [line for line in CI.read_text(encoding="utf-8").splitlines() if USES.match(line)]


def uses_error(line: str) -> str | None:
    """Return a fixed violation code for a `uses:` line, or None when fully pinned."""
    match = USES.match(line)
    if match is None:
        return "not-a-uses-line"
    ref, comment = match.group(1), match.group(2)
    repo, at, pin = ref.partition("@")
    if not at or "/" not in repo or not pin:
        return "bad-ref"
    if SHA.fullmatch(pin) is None:
        return "not-full-sha"
    if comment is None or VERSION_COMMENT.fullmatch(comment.strip()) is None:
        return "bad-version-comment"
    return None


def test_workflow_uses_are_fully_pinned() -> None:
    lines = _uses_lines()
    assert lines, "no uses: lines found (workflow shape changed)"
    # Assertions carry line numbers and fixed codes only, never the line text.
    bad = [(number, uses_error(line)) for number, line in enumerate(lines, 1) if uses_error(line)]
    assert bad == [], bad


def test_pins_match_the_contract() -> None:
    # Shape is checked in test_workflow_uses_are_fully_pinned; no SHA or version is fixed here,
    # so Dependabot can refresh a pin without this test failing (T5).
    repos: set[str] = set()
    for line in _uses_lines():
        match = USES.match(line)
        assert match is not None
        repo, _, _pin = match.group(1).partition("@")
        repos.add(repo)
    assert repos == EXPECTED_REPOS


def _bumped(line: str) -> str:
    """A synthetic Dependabot refresh: new valid SHA and a newer version comment."""
    match = USES.match(line)
    assert match is not None
    assert uses_error(line) is None
    ref, comment = match.group(1), match.group(2)
    repo, _, sha = ref.partition("@")
    assert comment is not None
    new_sha = ("0" if sha[0] != "0" else "1") + sha[1:]
    major = int(comment[1:].split(".")[0])
    return f"{line[: match.start(1)]}{repo}@{new_sha} # v{major + 100}.0.0"


def test_dependabot_sha_bumps_are_accepted() -> None:
    original = CI.read_text(encoding="utf-8")
    refreshed = "\n".join(
        _bumped(line) if USES.match(line) and uses_error(line) is None else line
        for line in original.splitlines()
    ) + ("\n" if original.endswith("\n") else "")
    assert refreshed != original  # the simulated bump really changed the pins
    uses = [line for line in refreshed.splitlines() if USES.match(line)]
    assert len(uses) == len(_uses_lines())
    assert all(uses_error(line) is None for line in uses)
    repos: set[str] = set()
    for line in uses:
        match = USES.match(line)
        assert match is not None
        repos.add(match.group(1).partition("@")[0])
    assert repos == EXPECTED_REPOS


def test_tag_refresh_is_rejected() -> None:
    line = next(line for line in _uses_lines() if uses_error(line) is None)
    tag = re.sub(r"@[0-9a-f]{40}", "@v10", line, count=1)
    assert uses_error(tag) == "not-full-sha"


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("      - uses: actions/checkout@v7", "not-full-sha"),
        ("        uses: actions/checkout@3d3c42e", "not-full-sha"),
        (
            "      - uses: actions/checkout@3D3C42E5AAC5BA805825DA76410C181273BA90B1 # v7.0.1",
            "not-full-sha",
        ),
        (
            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90g1 # v7.0.1",
            "not-full-sha",
        ),
        (
            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "bad-version-comment",
        ),
        (
            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 #",
            "bad-version-comment",
        ),
        (
            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # 7.0.1",
            "bad-version-comment",
        ),
        (
            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1 extra",
            "bad-version-comment",
        ),
        ("      - uses: actions/checkout", "bad-ref"),
        ("checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1", "not-a-uses-line"),
    ],
)
def test_checker_rejects_bad_pins(line: str, code: str) -> None:
    assert uses_error(line) == code


@pytest.mark.parametrize(
    "line",
    [
        "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
        "        uses: astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78 # v7.6.0",
    ],
)
def test_checker_accepts_valid_pins(line: str) -> None:
    assert uses_error(line) is None


def test_checker_codes_are_value_free() -> None:
    """A violation is reported as a fixed code, never as the offending text."""
    code = uses_error("      - uses: owner/repo@v7")
    assert code == "not-full-sha"
    assert code in ERROR_CODES
    assert "owner/repo" not in code
    assert "v7" not in code


def test_required_check_names_are_unchanged() -> None:
    jobs = _yaml(CI.read_text(encoding="utf-8"))["jobs"]
    assert isinstance(jobs, dict)
    names: set[str] = set()
    for job in jobs.values():
        assert isinstance(job, dict)
        names.add(job["name"])
    # The branch ruleset requires exactly these two check names; a new job needs a ruleset change.
    assert names == REQUIRED_JOB_NAMES


def test_audit_step_is_in_the_test_job_after_sync() -> None:
    jobs = _yaml(CI.read_text(encoding="utf-8"))["jobs"]
    assert isinstance(jobs, dict)
    test_job = next(job for job in jobs.values() if job["name"] == "lint + tests (Python 3.13)")
    steps = test_job["steps"]
    sync_index = next(
        i for i, step in enumerate(steps) if "uv sync --locked" in step.get("run", "")
    )
    audit_index = next(i for i, step in enumerate(steps) if step.get("name") == "Dependency audit")
    assert audit_index > sync_index


def test_audit_command_is_exact_and_pinned() -> None:
    text = CI.read_text(encoding="utf-8")
    assert "uv export --frozen --no-hashes --no-emit-project" in text
    assert "uvx pip-audit==2.9.0 -r /tmp/veil-requirements.txt" in text


def test_dependabot_groups_both_ecosystems() -> None:
    data = _yaml(DEPENDABOT.read_text(encoding="utf-8"))
    updates = data["updates"]
    assert isinstance(updates, list)
    by_ecosystem = {}
    for update in updates:
        assert isinstance(update, dict)
        by_ecosystem[update["package-ecosystem"]] = update
    assert {"github-actions", "uv"} <= by_ecosystem.keys()

    actions_groups = by_ecosystem["github-actions"]["groups"]
    assert any("*" in group.get("patterns", []) for group in actions_groups.values())

    uv_groups = by_ecosystem["uv"]["groups"]
    assert any(
        "*" in group.get("patterns", [])
        and set(group.get("update-types", [])) == {"minor", "patch"}
        for group in uv_groups.values()
    )


def test_contributing_documents_false_positive_handling() -> None:
    text = CONTRIBUTING.read_text(encoding="utf-8")
    assert "## Dependency audit" in text
    assert "--ignore-vuln <ID>" in text
    assert "advisory" in text
