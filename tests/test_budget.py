
import pytest

from nulltrace.core.budget import RequestBudget, RequestBudgetExceeded


def test_budget_starts_with_full_capacity() -> None:
    budget = RequestBudget(max_requests=10)

    assert budget.requests_used == 0
    assert budget.remaining == 10


def test_budget_consumes_requests() -> None:
    budget = RequestBudget(max_requests=3)

    budget.consume()
    budget.consume()

    assert budget.requests_used == 2
    assert budget.remaining == 1


def test_budget_rejects_excess_requests() -> None:
    budget = RequestBudget(max_requests=2)

    budget.consume()
    budget.consume()

    with pytest.raises(RequestBudgetExceeded):
        budget.consume()

    assert budget.requests_used == 2
    assert budget.remaining == 0


@pytest.mark.parametrize("limit", [0, -1])
def test_budget_rejects_invalid_limits(limit: int) -> None:
    with pytest.raises(ValueError):
        RequestBudget(max_requests=limit)

