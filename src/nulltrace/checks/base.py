from abc import ABC, abstractmethod

from nulltrace.adapters.base import TargetAdapter
from nulltrace.core.models import Finding


class Check(ABC):
    """Base class for independently executable security checks."""

    check_id: str
    title: str

    @abstractmethod
    def run(self, target: TargetAdapter) -> Finding:
        """Execute this security check against a target adapter."""
        raise NotImplementedError
