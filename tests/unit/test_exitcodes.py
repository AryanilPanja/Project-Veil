import pytest

from veil.exitcodes import ExitCode

# The table from ADR-0027. Changing a value is a breaking change for scripts and hotkeys.
ADR_0027_TABLE = {
    "OK": 0,
    "FINDINGS": 1,
    "USAGE": 2,
    "OFF": 3,
    "KEY_UNAVAILABLE": 4,
    "DECRYPT_FAILED": 5,
    "BUSY": 6,
    "UNSAFE_ENVIRONMENT": 7,
    "ABORTED": 8,
    "STORAGE": 9,
    "INTERNAL": 70,
    "INTERRUPTED": 130,
}


def test_table_matches_adr_exactly():
    assert {code.name: code.value for code in ExitCode} == ADR_0027_TABLE


def test_values_are_unique():
    values = [code.value for code in ExitCode]
    assert len(values) == len(set(values))


@pytest.mark.parametrize("code", list(ExitCode))
def test_codes_are_valid_process_exit_statuses(code):
    assert isinstance(code, int)
    assert 0 <= int(code) <= 255


def test_only_ok_is_zero():
    assert [c for c in ExitCode if c == 0] == [ExitCode.OK]
