from typer.testing import CliRunner
from dracxx.cli.main import app

runner = CliRunner()


def test_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "DRACXX" in result.stdout


def test_tools_command_runs():
    result = runner.invoke(app, ["tools"])
    assert result.exit_code == 0


def test_doctor_command_runs():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Exploitation: DISABLED" in result.stdout
