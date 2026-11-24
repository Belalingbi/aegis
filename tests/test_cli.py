from click.testing import CliRunner
import pytest
from aegis.cli import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "AEGIS" in result.output
    assert "recon" in result.output
    assert "audit" in result.output
    assert "forensic" in result.output
    assert "doctor" in result.output


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.2.0" in result.output


def test_cli_dashboard_default():
    runner = CliRunner()
    result = runner.invoke(main, [])
    assert result.exit_code == 0
    assert "AEGIS SECURITY FRAMEWORK" in result.output
    assert "Tableau de Bord" in result.output


def test_cli_doctor():
    runner = CliRunner()
    result = runner.invoke(main, ["doctor"])
    assert result.exit_code == 0
    assert "AEGIS Doctor" in result.output


def test_cli_auto_system_health():
    runner = CliRunner()
    result = runner.invoke(main, ["auto", "-w", "system-health"])
    assert result.exit_code == 0
    assert "System Health" in result.output


def test_cli_auto_hardening_check():
    runner = CliRunner()
    result = runner.invoke(main, ["auto", "-w", "hardening-check"])
    assert result.exit_code == 0
    assert "Hardening" in result.output
