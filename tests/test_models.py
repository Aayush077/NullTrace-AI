from nulltrace.core.context import AssessmentContext
from nulltrace.core.models import (
    SCHEMA_VERSION,
    AssessmentReport,
    CheckResult,
    CheckStatus,
    Confidence,
    Evidence,
    Finding,
    Severity,
    ValidationStatus,
    make_finding_id,
    new_assessment_id,
    utc_now_iso,
)


def _finding(actual: str = "observed behavior") -> Finding:
    return Finding(
        finding_id="NTA-x-NT-T-01",
        check_id="NT-T-001",
        title="Test finding",
        description="desc",
        category="prompt_injection",
        affected_component="target",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        evidence=[Evidence(probe="p", response="r", synthetic=True)],
        reproduction_steps=["step 1"],
        expected_behavior="expected",
        actual_behavior=actual,
        impact="impact",
        remediation="fix",
    )


def test_new_findings_are_pending_review() -> None:
    assert _finding().validation_status is ValidationStatus.PENDING_REVIEW


def test_finding_serializes_all_required_fields() -> None:
    data = _finding().to_dict()

    for key in (
        "finding_id",
        "check_id",
        "title",
        "description",
        "category",
        "affected_component",
        "severity",
        "confidence",
        "evidence",
        "reproduction_steps",
        "expected_behavior",
        "actual_behavior",
        "impact",
        "remediation",
        "references",
        "assessment_id",
        "timestamp",
        "validation_status",
    ):
        assert key in data

    assert data["severity"] == "high"
    assert data["validation_status"] == "pending_review"
    assert data["evidence"][0]["synthetic"] is True


def test_dedup_key_distinguishes_different_behavior() -> None:
    assert _finding("a").dedup_key() != _finding("b").dedup_key()
    assert _finding("a").dedup_key() == _finding("a").dedup_key()


def test_assessment_ids_are_unique() -> None:
    assert new_assessment_id() != new_assessment_id()
    assert new_assessment_id().startswith("NTA-")


def test_finding_id_format() -> None:
    assert make_finding_id("NTA-abc", "NT-PI-001", 3) == "NTA-abc-NT-PI-001-03"


def test_probe_tokens_are_deterministic_per_assessment() -> None:
    context = AssessmentContext(assessment_id="NTA-fixed")
    other = AssessmentContext(assessment_id="NTA-other")

    assert context.probe_token("NT-PI-001") == context.probe_token("NT-PI-001")
    assert context.probe_token("NT-PI-001") != context.probe_token("NT-PI-002")
    assert context.probe_token("NT-PI-001") != other.probe_token("NT-PI-001")
    assert context.probe_token("NT-PI-001").startswith("NTPROBE-")


def _report(results: list[CheckResult], findings: list[Finding]) -> AssessmentReport:
    now = utc_now_iso()
    return AssessmentReport(
        assessment_id="NTA-test",
        project="NullTrace AI",
        project_version="0.0.0",
        target="t",
        mode="mock",
        scope="synthetic",
        profile="full",
        modules_executed=["baseline"],
        started_at=now,
        completed_at=now,
        results=results,
        findings=findings,
    )


def test_report_counts_statuses_and_severities() -> None:
    results = [
        CheckResult("A", "m", "t", CheckStatus.PASS),
        CheckResult("B", "m", "t", CheckStatus.FAIL),
        CheckResult("C", "m", "t", CheckStatus.SKIPPED),
    ]
    report = _report(results, [_finding()])
    data = report.to_dict()

    assert data["schema_version"] == SCHEMA_VERSION
    assert data["summary"]["status_counts"]["pass"] == 1
    assert data["summary"]["status_counts"]["fail"] == 1
    assert data["summary"]["status_counts"]["skipped"] == 1
    assert data["summary"]["findings_by_severity"]["high"] == 1
    assert data["summary"]["findings_total"] == 1
