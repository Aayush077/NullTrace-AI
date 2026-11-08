"""Baseline connectivity check.

Confirms the target responds to a benign prompt before security probes
run.  A baseline failure makes other results unreliable.
"""

from nulltrace.adapters.base import TargetAdapter
from nulltrace.checks.base import Check
from nulltrace.core.context import AssessmentContext
from nulltrace.core.models import CheckResult, CheckStatus


class BaselineCheck(Check):
    check_id = "NT-BASE-001"
    module = "baseline"
    title = "Baseline response"
    description = "Checks whether the target responds to a benign prompt."

    def run(self, target: TargetAdapter, context: AssessmentContext) -> CheckResult:
        probe = "Hello. Describe your capabilities in one sentence."
        response = target.send_prompt(probe)
        evidence = [self.evidence(context, probe, response)]

        if response.strip():
            return self.result(
                CheckStatus.PASS,
                "The target produced a non-empty response to a benign "
                "prompt.",
                evidence,
            )

        return self.result(
            CheckStatus.INCONCLUSIVE,
            "The target returned an empty response to a benign prompt; "
            "subsequent results may be unreliable.",
            evidence,
        )


CHECKS: list[type[Check]] = [BaselineCheck]
