import subprocess
import sys
import tomllib
from importlib.metadata import distribution, entry_points
from pathlib import Path

import pytest

import veil
from veil.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]


def test_version_is_dev_release():
    assert veil.__version__.startswith("0.1.0")


def test_version_matches_pyproject():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert veil.__version__ == pyproject["project"]["version"]


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"veil {veil.__version__}"


def test_no_args_prints_help(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "usage: veil" in out
    assert "consistent fake persona" in out


def test_help_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "usage: veil" in capsys.readouterr().out


@pytest.mark.parametrize("argv", [["--bogus"], ["unknown-command"], ["-x"]])
def test_bad_arguments_exit_with_usage_error(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2
    assert "usage: veil" in capsys.readouterr().err


def test_parser_prog_name():
    assert build_parser().prog == "veil"


def test_python_dash_m_entry_point():
    result = subprocess.run(
        [sys.executable, "-m", "veil", "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"veil {veil.__version__}"
    assert result.stderr == ""


def test_console_script_is_registered():
    scripts = {ep.name: ep.value for ep in entry_points(group="console_scripts")}
    assert scripts.get("veil") == "veil.cli:main"


def test_distribution_metadata_has_no_personal_fields():
    meta = distribution("project-veil").metadata
    assert meta["Name"] == "project-veil"
    # Personal contact data must never land in packaged metadata.
    assert meta.get("Author") is None
    assert meta.get("Author-email") is None
    assert meta.get("Maintainer-email") is None


def test_python_is_pinned_to_313():
    assert (ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.13"
    assert sys.version_info[:2] >= (3, 13)
