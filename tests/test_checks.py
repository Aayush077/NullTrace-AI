"""Behavioral tests for the check modules.

Each module is validated both ways:

- against the *hardened* mock profile it must not raise false positives;
- against the *vulnerable* mock profile it must detect the planted
  insecure behavior (true positives) with attributable evidence.
"""

import pytest

from nulltrace.adapters.mock_agent import LocalMockAgent
from nulltrace.checks.registry import MODULES
from nulltrace.core.context import AssessmentContext
from nulltrace.core.models import CheckStatus, Confidence
from nulltrace.core.runner import run_local_assessment


def _run(check_id: str, profile: str) -> tuple[CheckStatus, list[str]]:
    target = LocalMockAgent(profile=profile)
    context = AssessmentContext(
        assessment_id="NTA-test",
        synthetic_target=True,
        hints=target.assessment_hints(),
    )

    for checks in MODULES.values():
        for check_class in checks:
            if check_class.check_id == check_id:
                result = check_class().run(target, context)
                return result.status, [f.finding_id for f in result.findings]

    raise AssertionError(f"Unknown check: {check_id}")


ALL_CHECK_IDS = [
    check_class.check_id
    for checks in MODULES.values()
    for check_class in checks
]

# Checks whose planted weakness the vulnerable mock intentionally does NOT
# exhibit (the fixture keeps some controls in both profiles).
VULNERABLE_PASS_EXPECTED = {
    "NT-BASE-001",  # baseline always responds
    "NT-ID-003",  # the vulnerable mock leaks on request, not unprompted
    "NT-TA-002",  # destructive tool stays blocked-in-demo for admins
}

VULNERABLE_INCONCLUSIVE_EXPECTED = {
    "NT-OH-002",  # markup echo is an informational observation
}


@pytest.mark.parametrize("check_id", ALL_CHECK_IDS)
def test_hardened_mock_produces_no_failures(check_id: str) -> None:
    status, findings = _run(check_id, "hardened")

    assert status == CheckStatus.PASS, check_id
    assert not findings


@pytest.mark.parametrize("check_id", ALL_CHECK_IDS)
def test_vulnerable_mock_is_detected(check_id: str) -> None:
    status, _ = _run(check_id, "vulnerable")

    if check_id in VULNERABLE_PASS_EXPECTED:
        assert status == CheckStatus.PASS, check_id
    elif check_id in VULNERABLE_INCONCLUSIVE_EXPECTED:
        assert status == CheckStatus.INCONCLUSIVE, check_id
    else:
        assert status == CheckStatus.FAIL, check_id


def test_vulnerable_findings_carry_evidence_and_confidence() -> None:
    report = run_local_assessment(profile="full", mock_profile="vulnerable")

    assert report.findings

    for finding in report.findings:
        assert finding.evidence, finding.finding_id
        assert finding.reproduction_steps, finding.finding_id
        assert finding.actual_behavior, finding.finding_id
        assert finding.confidence in set(Confidence)
        assert finding.assessment_id == report.assessment_id
        assert all(item.synthetic for item in finding.evidence)


def test_unique_check_ids_across_modules() -> None:
    assert len(ALL_CHECK_IDS) == len(set(ALL_CHECK_IDS))


def test_checks_without_hints_degrade_to_inconclusive_or_pass() -> None:
    """A black-box target with no declared markers must never yield a
    marker-attributed FAIL from the hint-based checks."""

    from nulltrace.core.context import AssessmentHints

    class OpaqueTarget(LocalMockAgent):
        def assessment_hints(self) -> AssessmentHints:
            return AssessmentHints()

    target = OpaqueTarget(profile="vulnerable")
    context = AssessmentContext(
        assessment_id="NTA-opaque",
        synthetic_target=True,
        hints=target.assessment_hints(),
    )

    for checks in MODULES.values():
        for check_class in checks:
            check = check_class()
            if check.required_capability is not None and not isinstance(
                target, check.required_capability
            ):
                continue
            result = check.run(target, context)
            if result.status == CheckStatus.FAIL:
                # Only checks with hint-independent evidence may FAIL:
                # probe-token compliance or structural JSON validation.
                hint_free = {
                    "NT-PI-001",
                    "NT-PI-003",
                    "NT-PI-004",
                    "NT-PI-005",
                    "NT-PI-006",
                    "NT-AG-001",
                    "NT-AG-003",
                    "NT-AG-004",
                    "NT-OH-001",
                    # Multi-turn chains detect via probe token, hint-free.
                    "NT-CHAIN-001",
                    "NT-CHAIN-002",
                }
                assert check.check_id in hint_free, check.check_id
