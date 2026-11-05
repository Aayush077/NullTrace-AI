from abc import ABC, abstractmethod


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
