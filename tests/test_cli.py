import json
from pathlib import Path

from typer.testing import CliRunner

from nulltrace import __version__
from nulltrace.cli.app import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert __version__ in result.output


def test_doctor_command() -> None:
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "Registered modules" in result.output


def test_modules_command_lists_checks() -> None:
    result = runner.invoke(app, ["modules"])

    assert result.exit_code == 0
    assert "NT-PI-001" in result.output
    assert "rag_security" in result.output


def test_demo_command_runs_offline() -> None:
    result = runner.invoke(app, ["demo"])

    assert result.exit_code == 0
    assert "No external system was contacted" in result.output


def test_assess_mock_writes_valid_json_report(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["assess", "--mode", "mock", "--profile", "quick", "--output", str(output)],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["project"] == "NullTrace AI"
    assert data["synthetic_target"] is True
    assert data["summary"]["checks_executed"] > 0


def test_assess_vulnerable_mock_writes_markdown(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    markdown = tmp_path / "report.md"
    result = runner.invoke(
        app,
        [
            "assess",
            "--mode",
            "mock",
            "--mock-profile",
            "vulnerable",
            "--profile",
            "full",
            "--output",
            str(output),
            "--markdown-output",
            str(markdown),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "Findings:" in result.output
    rendered = markdown.read_text(encoding="utf-8")
    assert "## Findings" in rendered
    assert "pending_review" in rendered


def test_assess_rejects_invalid_mock_profile(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["assess", "--mode", "mock", "--mock-profile", "bogus"]
    )

    assert result.exit_code != 0


def test_targets_command_lists_demo_lab() -> None:
    result = runner.invoke(app, ["targets"])

    assert result.exit_code == 0
    assert "Demo Target Lab" in result.output
    assert "simulated" in result.output.lower()


def test_assess_demo_target_detects_seeded_weaknesses(tmp_path: Path) -> None:
    output = tmp_path / "demo-crm.json"
    result = runner.invoke(
        app,
        [
            "assess",
            "--mode",
            "demo",
            "--target",
            "demo-crm-assistant",
            "--profile",
            "full",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(output.read_text(encoding="utf-8"))
    failed = {
        r["check_id"] for r in data["results"] if r["status"] == "fail"
    }
    assert failed == {"NT-ID-002", "NT-AZ-002"}


def test_assess_demo_secure_variant_has_no_findings(tmp_path: Path) -> None:
    output = tmp_path / "demo-crm-secure.json"
    result = runner.invoke(
        app,
        [
            "assess",
            "--mode",
            "demo",
            "--target",
            "demo-crm-assistant",
            "--secure-variant",
            "--profile",
            "full",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["summary"]["findings_total"] == 0


def test_assess_demo_requires_known_target() -> None:
    result = runner.invoke(
        app, ["assess", "--mode", "demo", "--target", "bogus"]
    )

    assert result.exit_code != 0


def test_assess_api_requires_network_consent() -> None:
    result = runner.invoke(
        app, ["assess", "--mode", "api", "--model", "test-model"]
    )

    assert result.exit_code != 0
    assert "allow-network" in result.output


def test_assess_api_requires_model() -> None:
    result = runner.invoke(
        app, ["assess", "--mode", "api", "--allow-network"]
    )

    assert result.exit_code != 0
    assert "--model" in result.output


def test_assess_api_rejects_private_base_url() -> None:
    result = runner.invoke(
        app,
        [
            "assess",
            "--mode",
            "api",
            "--allow-network",
            "--model",
            "test-model",
            "--base-url",
            "https://169.254.169.254/v1",
        ],
    )

    assert result.exit_code != 0


def test_assess_rejects_unknown_module(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["assess", "--mode", "mock", "--modules", "bogus_module"],
    )

    assert result.exit_code != 0
    assert "Unknown assessment module" in result.output


def test_report_and_findings_commands(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    assess = runner.invoke(
        app,
        [
            "assess",
            "--mode",
            "mock",
            "--mock-profile",
            "vulnerable",
            "--profile",
            "full",
            "--output",
            str(output),
        ],
    )
    assert assess.exit_code == 0, assess.output

    rendered = runner.invoke(app, ["report", str(output)])
    assert rendered.exit_code == 0
    assert "security assessment" in rendered.output

    summary = runner.invoke(
        app, ["report", str(output), "--format", "summary"]
    )
    assert summary.exit_code == 0
    assert "Findings:" in summary.output

    listing = runner.invoke(app, ["findings", str(output)])
    assert listing.exit_code == 0
    assert "Findings" in listing.output
    assert "critical" in listing.output

    filtered = runner.invoke(
        app, ["findings", str(output), "--severity", "critical"]
    )
    assert filtered.exit_code == 0
    assert "critical" in filtered.output


def test_report_rejects_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")

    result = runner.invoke(app, ["report", str(bad)])

    assert result.exit_code != 0


def test_report_rejects_schema_violations(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"project": "x"}), encoding="utf-8")

    result = runner.invoke(app, ["report", str(bad)])

    assert result.exit_code != 0


def test_validate_target_accepts_public_https() -> None:
    result = runner.invoke(
        app, ["validate-target", "--base-url", "https://api.example.com/v1"]
    )

    assert result.exit_code == 0
    assert "accepted" in result.output
    assert "No network request" in result.output


def test_validate_target_rejects_private_url() -> None:
    result = runner.invoke(
        app, ["validate-target", "--base-url", "https://192.168.1.1/v1"]
    )

    assert result.exit_code == 1
    assert "rejected" in result.output


def test_serve_command_help_lists_options() -> None:
    result = runner.invoke(app, ["serve", "--help"])

    assert result.exit_code == 0
    assert "--host" in result.output
    assert "--port" in result.output


def test_serve_command_is_registered() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "serve" in result.output
