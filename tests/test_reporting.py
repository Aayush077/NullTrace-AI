import pytest

from nulltrace.core.runner import run_local_assessment
from nulltrace.reporting.render import (
    ReportValidationError,
    to_markdown,
    validate_report,
)


def test_markdown_report_contains_core_sections() -> None:
    report = run_local_assessment(profile="full")
    rendered = to_markdown(report.to_dict())

    assert "local-mock-agent" in rendered
    assert report.assessment_id in rendered
    assert "## Executive summary" in rendered
    assert "## Methodology" in rendered
    assert "Probe corpus version:" in rendered
    assert "## Results summary" in rendered
    assert "## Findings" in rendered
    assert "## Check results" in rendered
    assert "## Limitations" in rendered
    assert "Synthetic target:** yes" in rendered


def test_markdown_renders_findings_with_full_fields() -> None:
    report = run_local_assessment(profile="full", mock_profile="vulnerable")
    rendered = to_markdown(report.to_dict())

    finding = report.findings[0]
    assert finding.finding_id in rendered
    assert "**Severity:**" in rendered
    assert "**Confidence:**" in rendered
    assert "**Reproduction steps:**" in rendered
    assert "**Evidence:**" in rendered
    assert "pending_review" in rendered


def test_hardened_report_states_no_findings_without_security_claim() -> None:
    rendered = to_markdown(run_local_assessment(profile="quick").to_dict())

    assert "does not establish that the target is secure" in rendered


def test_validate_report_accepts_generated_reports() -> None:
    validate_report(run_local_assessment(profile="quick").to_dict())


def test_validate_report_rejects_missing_fields() -> None:
    data = run_local_assessment(profile="quick").to_dict()
    del data["assessment_id"]

    with pytest.raises(ReportValidationError, match="assessment_id"):
        validate_report(data)


def test_validate_report_rejects_wrong_schema_version() -> None:
    data = run_local_assessment(profile="quick").to_dict()
    data["schema_version"] = "999"

    with pytest.raises(ReportValidationError, match="schema version"):
        validate_report(data)


def test_validate_report_rejects_malformed_finding() -> None:
    data = run_local_assessment(
        profile="full", mock_profile="vulnerable"
    ).to_dict()
    del data["findings"][0]["evidence"]

    with pytest.raises(ReportValidationError, match="evidence"):
        validate_report(data)


def test_findings_sorted_by_severity_in_markdown() -> None:
    report = run_local_assessment(profile="full", mock_profile="vulnerable")
    rendered = to_markdown(report.to_dict())

    critical_pos = rendered.find("Vertical privilege escalation")
    info_pos = rendered.find("Markup passthrough")

    assert critical_pos != -1 and info_pos != -1
    assert critical_pos < info_pos
