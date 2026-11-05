
from nulltrace.adapters.base import TargetAdapter
from nulltrace.core.budget import RequestBudget
from nulltrace.core.runner import run_assessment


class BudgetedMockTarget(TargetAdapter):
    """Synthetic target that consumes a request budget on every prompt."""

    def __init__(self, budget: RequestBudget) -> None:
        self.budget = budget

    @property
    def target_name(self) -> str:
        return "budgeted-test-target"

    def send_prompt(self, prompt: str) -> str:
        self.budget.consume()
        return "Synthetic response for testing."


def test_runner_stops_when_request_budget_is_exhausted() -> None:
    budget = RequestBudget(max_requests=1)
    target = BudgetedMockTarget(budget)

    report = run_assessment(target, request_budget=budget)

    assert report.assessment_status == "incomplete"
    assert report.requests_used == 1
    assert report.request_limit == 1
    assert len(report.findings) == 1
    assert any("budget was exhausted" in note for note in report.notes)


def test_runner_completes_when_budget_is_sufficient() -> None:
    budget = RequestBudget(max_requests=2)
    target = BudgetedMockTarget(budget)

    report = run_assessment(target, request_budget=budget)

    assert report.assessment_status == "completed"
    assert report.requests_used == 2
    assert report.request_limit == 2
    assert len(report.findings) == 2


def test_runner_does_not_make_requests_after_budget_exhaustion() -> None:
    budget = RequestBudget(max_requests=1)
    target = BudgetedMockTarget(budget)

    report = run_assessment(target, request_budget=budget)

    assert budget.requests_used == 1
    assert budget.remaining == 0
    assert report.assessment_status == "incomplete"
