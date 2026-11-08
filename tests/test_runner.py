"""Runner tests: budgets, error isolation, module selection, redaction."""

import pytest

from nulltrace.adapters.base import TargetAdapter
from nulltrace.core.budget import RequestBudget
from nulltrace.core.models import CheckStatus
from nulltrace.core.runner import run_assessment, run_local_assessment


class BudgetedMockTarget(TargetAdapter):
    """Synthetic target that consumes a request budget on every prompt."""

    def __init__(self, budget: RequestBudget) -> None:
        self.budget = budget

    @property
    def target_name(self) -> str:
        return "budgeted-test-target"

    @property
    def is_synthetic(self) -> bool:
        return True

    def send_prompt(self, prompt: str) -> str:
        self.budget.consume()
        return "Synthetic response for testing."


class FailingTarget(TargetAdapter):
    """Target whose prompts always raise, to exercise error isolation."""

    @property
    def target_name(self) -> str:
        return "failing-test-target"

    def send_prompt(self, prompt: str) -> str:
        raise RuntimeError("synthetic transport failure")


class LeakyTarget(TargetAdapter):
    """Target that echoes a secret so redaction can be verified."""

    @property
    def target_name(self) -> str:
        return "leaky-test-target"

    def send_prompt(self, prompt: str) -> str:
        return "the key is sk-notreallyakey12345 and value hunter2secret"


def test_runner_stops_when_request_budget_is_exhausted() -> None:
    budget = RequestBudget(max_requests=1)
    target = BudgetedMockTarget(budget)

    report = run_assessment(target, request_budget=budget, profile="quick")

    assert report.assessment_status == "incomplete"
    assert report.requests_used == 1
    assert report.request_limit == 1
    assert budget.remaining == 0
    assert any("budget was exhausted" in note for note in report.notes)

    statuses = [result.status for result in report.results]
    assert statuses.count(CheckStatus.SKIPPED) >= 1


def test_runner_completes_when_budget_is_sufficient() -> None:
    budget = RequestBudget(max_requests=50)
    target = BudgetedMockTarget(budget)

    report = run_assessment(target, request_budget=budget, profile="quick")

    assert report.assessment_status == "completed"
    assert report.requests_used > 0
    assert report.request_limit == 50


def test_runner_isolates_check_errors() -> None:
    report = run_assessment(FailingTarget(), profile="quick")

    assert report.assessment_status == "completed"
    assert all(
        result.status in {CheckStatus.ERROR, CheckStatus.SKIPPED}
        for result in report.results
    )
    assert all(
        "synthetic transport failure" in result.error
        for result in report.results
        if result.status == CheckStatus.ERROR
    )


def test_runner_skips_checks_without_required_capability() -> None:
    budget = RequestBudget(max_requests=100)
    target = BudgetedMockTarget(budget)

    report = run_assessment(target, request_budget=budget, profile="full")

    skipped = {
        result.check_id
        for result in report.results
        if result.status == CheckStatus.SKIPPED
    }

    # Tool, RAG and conversation checks require capabilities the plain
    # target does not implement.
    assert "NT-AZ-001" in skipped
    assert "NT-RAG-001" in skipped
    assert "NT-PI-005" in skipped


def test_runner_redacts_secrets_in_evidence() -> None:
    report = run_assessment(
        LeakyTarget(),
        profile="quick",
        known_secrets=("hunter2secret",),
    )

    for result in report.results:
        for evidence in result.evidence:
            assert "hunter2secret" not in evidence.response
            assert "sk-notreallyakey12345" not in evidence.response


def test_runner_rejects_unknown_module() -> None:
    with pytest.raises(ValueError, match="Unknown assessment module"):
        run_assessment(FailingTarget(), modules=["nonexistent"])


def test_runner_rejects_unknown_profile() -> None:
    with pytest.raises(ValueError, match="Unknown profile"):
        run_assessment(FailingTarget(), profile="nonexistent")


def test_module_selection_limits_executed_checks() -> None:
    report = run_local_assessment(modules=["baseline"])

    assert report.modules_executed == ["baseline"]
    assert len(report.results) == 1
    assert report.results[0].check_id == "NT-BASE-001"
    assert report.profile == "custom"


def test_local_assessment_is_marked_synthetic() -> None:
    report = run_local_assessment(profile="quick")

    assert report.synthetic_target is True
    assert any("no external target" in note.lower() for note in report.notes)
    assert report.limitations


def test_findings_are_deduplicated_and_linked() -> None:
    report = run_local_assessment(profile="full", mock_profile="vulnerable")

    keys = [finding.dedup_key() for finding in report.findings]
    assert len(keys) == len(set(keys))

    ids = [finding.finding_id for finding in report.findings]
    assert len(ids) == len(set(ids))
    assert all(finding.assessment_id == report.assessment_id for finding in report.findings)
