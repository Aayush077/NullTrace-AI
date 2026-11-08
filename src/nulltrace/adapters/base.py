from abc import ABC, abstractmethod

from nulltrace.core.context import AssessmentHints


class TargetAdapter(ABC):
    """Common interface for AI application security assessment targets."""

    @property
    @abstractmethod
    def target_name(self) -> str:
        """Return a human-readable target identifier."""
        raise NotImplementedError

    @abstractmethod
    def send_prompt(self, prompt: str) -> str:
        """Send a prompt to the target and return its text response."""
        raise NotImplementedError

    def assessment_hints(self) -> AssessmentHints:
        """Markers the target declares about itself for exact detection.

        External black-box targets return no hints; synthetic fixtures
        declare their canaries and synthetic secrets so checks can produce
        directly attributable evidence.
        """

        return AssessmentHints()

    @property
    def is_synthetic(self) -> bool:
        """Whether this target is a local synthetic fixture."""

        return False
