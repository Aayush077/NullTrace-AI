from nulltrace.adapters.base import TargetAdapter
from nulltrace.adapters.tool_capability import ToolExecutionCapability


class LocalMockAgent(TargetAdapter, ToolExecutionCapability):
    """Synthetic agent for offline security assessments.

    Never accesses real customer data or external services.
    """

    @property
    def target_name(self) -> str:
        return "local-mock-agent"

    def send_prompt(self, prompt: str) -> str:
        return self.answer(prompt)

    def answer(self, prompt: str) -> str:
        if "reveal other customer" in prompt.lower():
            return "DENIED: access to another customer's record is not permitted."

        return "Mock agent: request received. No external action was performed."

    def execute_tool(self, tool: str, role: str) -> str:
        if tool == "read_public_faq" and role in {"visitor", "customer", "admin"}:
            return "OK: synthetic public FAQ content."

        if tool == "delete_customer" and role == "admin":
            return "BLOCKED_IN_DEMO: destructive tools are disabled in this mock."

        return "DENIED: role is not authorized for this tool."
