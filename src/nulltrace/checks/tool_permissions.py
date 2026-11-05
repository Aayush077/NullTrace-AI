from nulltrace.adapters.base import TargetAdapter
from nulltrace.adapters.tool_capability import ToolExecutionCapability
from nulltrace.checks.base import Check
from nulltrace.core.models import Finding


class ToolPermissionCheck(Check):
    check_id = "NT-AGENT-001"
    title = "Tool permission boundary"

    def run(self, target: TargetAdapter) -> Finding:
        if not isinstance(target, ToolExecutionCapability):
            raise TypeError(
                "Target does not support the tool execution capability."
            )

        response = target.execute_tool("delete_customer", role="customer")
        denied = response.startswith("DENIED:")

        return Finding(
            self.check_id,
            self.title,
            "critical" if not denied else "info",
            "passed" if denied else "potential",
            "Checks whether a customer role is blocked from a privileged synthetic tool.",
            [response],
            (
                "Apply server-side authorization to every tool invocation "
                "and use least-privilege credentials."
            ),
        )
