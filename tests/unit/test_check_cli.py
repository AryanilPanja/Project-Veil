"""`veil persona check --file`: exit codes, formats, and value-free output."""

import json
import os
from pathlib import Path

import pytest

from tests.conftest import run_python
from veil import cli
from veil.exitcodes import ExitCode
from veil.persona import check as check_module

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "synthetic_jane.yaml"


def write(tmp_path: Path, text: str, name: str = "p.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_file_exits_zero(capsys):
    assert cli.main(["persona", "check", "--file", str(FIXTURE)]) == ExitCode.OK
    assert "0 error(s)" in capsys.readouterr().out


def test_invalid_file_exits_one_with_findings(tmp_path, capsys):
    path = write(
        tmp_path, 'version: "1"\npeople: [{real: Ravi, fake: Om}, {real: Kiran, fake: Om}]\n'
    )
    assert cli.main(["persona", "check", "--file", str(path)]) == ExitCode.FINDINGS
    out = capsys.readouterr().out
    assert "E010 people[1]" in out
    for value in ("Ravi", "Kiran"):
        assert value not in out


def test_yaml_error_is_reported_at_file_with_position(tmp_path, capsys):
    path = write(tmp_path, 'version: "1"\nreal: "Jane Doe\n')
    assert cli.main(["persona", "check", "--file", str(path)]) == ExitCode.FINDINGS
    out = capsys.readouterr().out
    assert "E001 <file>" in out
    assert "line" in out
    assert "Jane" not in out


def test_schema_errors_are_reported_by_path(tmp_path, capsys):
    path = write(tmp_path, 'version: "1"\nperson: {fist_name: {real: Jane}}\n')
    assert cli.main(["persona", "check", "--file", str(path)]) == ExitCode.FINDINGS
    out = capsys.readouterr().out
    assert "E003 person: unknown field (did you mean 'first_name'?)" in out


def test_json_format(tmp_path, capsys):
    path = write(tmp_path, 'version: "1"\npeople: [{real: Ravi}]\n')
    assert cli.main(["persona", "check", "--file", str(path), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["errors"] == 1
    assert data["findings"][0]["code"] == "E016"
    assert data["findings"][0]["path"] == "people[0]"


def test_strict_flag_is_accepted(capsys):
    assert cli.main(["persona", "check", "--file", str(FIXTURE), "--strict"]) == ExitCode.OK


def test_missing_file(tmp_path, capsys):
    secret_dir = tmp_path / "JaneDoeSecret"
    code = cli.main(["persona", "check", "--file", str(secret_dir / "x.yaml")])
    assert code == ExitCode.USAGE
    err = capsys.readouterr().err
    assert "persona file not found" in err
    assert "JaneDoeSecret" not in err  # the path is never echoed


def test_directory_instead_of_file(tmp_path, capsys):
    assert cli.main(["persona", "check", "--file", str(tmp_path)]) == ExitCode.USAGE
    assert "directory" in capsys.readouterr().err


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_unreadable_file(tmp_path, capsys):
    path = write(tmp_path, 'version: "1"\n')
    path.chmod(0o000)
    try:
        assert cli.main(["persona", "check", "--file", str(path)]) == ExitCode.USAGE
        assert "permission denied" in capsys.readouterr().err
    finally:
        path.chmod(0o600)


def test_too_large_file(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(check_module, "MAX_BYTES", 10)
    path = write(tmp_path, 'version: "1"\nperson: {}\n')
    assert cli.main(["persona", "check", "--file", str(path)]) == ExitCode.USAGE
    assert "too large" in capsys.readouterr().err


def test_no_file_is_a_usage_error(capsys):
    assert cli.main(["persona", "check"]) == ExitCode.USAGE
    assert "--file" in capsys.readouterr().err


def test_persona_without_subcommand_shows_help(capsys):
    with pytest.raises(SystemExit) as info:
        cli.main(["persona"])
    assert info.value.code == 0
    assert "check" in capsys.readouterr().out


def test_bad_format_is_rejected(capsys):
    with pytest.raises(SystemExit) as info:
        cli.main(["persona", "check", "--file", str(FIXTURE), "--format", "xml"])
    assert info.value.code == ExitCode.USAGE


def test_end_to_end_real_process(tmp_path):
    path = write(
        tmp_path, 'version: "1"\npeople: [{real: Ravi, fake: Om}, {real: Ravi, fake: Sam}]\n'
    )
    result = run_python(
        "import sys\nfrom veil.cli import main\n"
        f"sys.exit(main(['persona', 'check', '--file', {str(path)!r}]))"
    )
    assert result.returncode == ExitCode.FINDINGS
    assert "E011 people[1]" in result.stdout
    assert "Ravi" not in result.stdout + result.stderr
