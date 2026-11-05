
class RequestBudgetExceeded(RuntimeError):
    """Raised when an assessment exceeds its request budget."""


class RequestBudget:
    """Track and enforce the maximum number of target requests."""

    def __init__(self, max_requests: int = 10) -> None:
        if max_requests <= 0:
            raise ValueError("Maximum requests must be greater than zero.")

        self.max_requests = max_requests
        self.requests_used = 0

    @property
    def remaining(self) -> int:
        """Return the number of requests remaining."""
        return self.max_requests - self.requests_used

    def consume(self) -> None:
        """Consume one request from the assessment budget."""

        if self.requests_used >= self.max_requests:
            raise RequestBudgetExceeded(
                "Assessment request budget exhausted."
            )

        self.requests_used += 1

