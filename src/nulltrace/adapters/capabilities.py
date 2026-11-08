"""Optional capability interfaces a target adapter may implement.

Checks declare which capabilities they need; the runner skips checks whose
capabilities the target does not expose.  A skipped check is recorded as
``SKIPPED`` and is never evidence of a vulnerability.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class SyntheticToolInfo:
    """Metadata for one synthetic tool a target exposes."""

    name: str
    description: str = ""
    destructive: bool = False
    privileged: bool = False
    reads_user_data: bool = False
    id_argument: str = "record_id"


@dataclass(frozen=True)
class ToolEnvironment:
    """The synthetic principals and tools checks can exercise.

    ``principal_a``/``principal_b`` are two distinct synthetic users;
    ``principal_b_object`` is an object identifier owned by principal B
    (used for horizontal-access probes).
    """

    tools: tuple[SyntheticToolInfo, ...]
    unprivileged_role: str
    privileged_role: str
    principal_a: str
    principal_b_object: str

    def first(
        self,
        *,
        privileged: bool | None = None,
        destructive: bool | None = None,
        reads_user_data: bool | None = None,
    ) -> SyntheticToolInfo | None:
        for tool in self.tools:
            if privileged is not None and tool.privileged != privileged:
                continue
            if destructive is not None and tool.destructive != destructive:
                continue
            if (
                reads_user_data is not None
                and tool.reads_user_data != reads_user_data
            ):
                continue
            return tool
        return None


class ToolExecutionCapability(ABC):
    """Target exposes (synthetic or authorized) tool execution."""

    @abstractmethod
    def describe_tools(self) -> ToolEnvironment:
        """Describe the synthetic tool environment for check planning."""
        raise NotImplementedError

    @abstractmethod
    def execute_tool(
        self,
        tool: str,
        role: str,
        arguments: dict[str, str] | None = None,
    ) -> str:
        """Execute a synthetic or authorized tool operation."""
        raise NotImplementedError


class ConversationCapability(ABC):
    """Target supports multi-turn conversations.

    ``messages`` is a list of ``{"role": ..., "content": ...}`` dicts in
    OpenAI chat format.  Returns the assistant's reply to the final turn.
    """

    @abstractmethod
    def send_conversation(self, messages: list[dict[str, str]]) -> str:
        raise NotImplementedError


@dataclass(frozen=True)
class ToolCallAttempt:
    """One tool call the target attempted (parsed, never executed)."""

    name: str
    arguments_json: str


@dataclass(frozen=True)
class ToolCallProbeResult:
    """Outcome of presenting tool definitions to the target."""

    text: str
    tool_calls: tuple[ToolCallAttempt, ...]


class ToolCallProbeCapability(ABC):
    """Target supports function/tool-calling in OpenAI format.

    ``request_with_tools`` presents synthetic tool definitions alongside a
    conversation and returns any tool calls the target *attempted*.  The
    framework parses attempts as evidence; it never executes them.
    """

    @abstractmethod
    def request_with_tools(
        self,
        messages: list[dict[str, str]],
        tools: list[dict[str, object]],
    ) -> ToolCallProbeResult:
        raise NotImplementedError


@dataclass(frozen=True)
class RetrievalEnvironment:
    """Scenario descriptors for retrieval checks.

    ``restricted_question`` should retrieve a document the
    ``unauthorized_user`` must NOT be able to read (owned by someone
    else); ``poisoned_question`` is answered by a synthetic document
    carrying an embedded instruction; ``metadata_question`` asks about
    document provenance.
    """

    unauthorized_user: str
    restricted_question: str
    poisoned_question: str
    metadata_question: str


class RetrievalCapability(ABC):
    """Target supports retrieval-augmented answering over a document store.

    ``ask_with_retrieval`` answers ``question`` using documents the given
    ``user`` is (supposedly) authorized to retrieve.
    """

    @abstractmethod
    def describe_retrieval(self) -> RetrievalEnvironment:
        """Describe the synthetic retrieval scenario for check planning."""
        raise NotImplementedError

    @abstractmethod
    def ask_with_retrieval(self, question: str, user: str) -> str:
        raise NotImplementedError
