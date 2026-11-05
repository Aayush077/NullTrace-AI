from abc import ABC, abstractmethod


class ToolExecutionCapability(ABC):
    """Interface for targets that expose tool execution for assessment."""

    @abstractmethod
    def execute_tool(self, tool: str, role: str) -> str:
        """Execute a synthetic or authorized tool operation."""
        raise NotImplementedError
