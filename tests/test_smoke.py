import pytest

import veil
from veil.cli import main


def test_version_is_dev_release():
    assert veil.__version__.startswith("0.1.0")


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"veil {veil.__version__}"


def test_no_args_prints_help(capsys):
    assert main([]) == 0
    assert "usage: veil" in capsys.readouterr().out
