from nulltrace.adapters.base import TargetAdapter
from nulltrace.checks.base import Check
from nulltrace.core.models import Finding


class BaselineCheck(Check):
    check_id = "NT-BASE-001"
    title = "Baseline response"

    def run(self, target: TargetAdapter) -> Finding:
        response = target.send_prompt("Hello. Describe your capabilities.")
        passed = bool(response.strip())

        return Finding(
            self.check_id,
            self.title,
            "info",
            "passed" if passed else "potential",
            "Checks whether the target responds to a benign baseline prompt.",
            [response],
            "No action required for this baseline check.",
        )
