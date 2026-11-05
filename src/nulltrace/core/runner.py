
from nulltrace.adapters.base import TargetAdapter
from nulltrace.adapters.tool_capability import ToolExecutionCapability
from nulltrace.checks.baseline import BaselineCheck
from nulltrace.checks.prompt_boundary import PromptBoundaryCheck
from nulltrace.checks.tool_permissions import ToolPermissionCheck
from nulltrace.core.budget import RequestBudget, RequestBudgetExceeded
from nulltrace.core.models import AssessmentReport


def run_assessment(
    target: TargetAdapter,
    request_budget: RequestBudget | None = None,
) -> AssessmentReport:
    """Run all security checks supported by the target adapter."""

    checks = [
        BaselineCheck(),
        PromptBoundaryCheck(),
    ]

    if isinstance(target, ToolExecutionCapability):
        checks.append(ToolPermissionCheck())

    findings = []
    budget_exhausted = False

    for check in checks:
        try:
            findings.append(check.run(target))
        except RequestBudgetExceeded:
            budget_exhausted = True
            break

    report = AssessmentReport.create(
        target.target_name,
        findings,
        request_limit=(
            request_budget.max_requests if request_budget is not None else None
        ),
    )

    if request_budget is not None:
        report.requests_used = request_budget.requests_used

    if budget_exhausted:
        report.assessment_status = "incomplete"
        report.notes.append(
            "Assessment stopped because the request budget was exhausted."
        )

    report.notes.extend(
        [
            "Assessment executed through the configured target adapter.",
            (
                "Unsupported capability checks were skipped; "
                "a skipped check is not evidence of a vulnerability."
            ),
            (
                "Passed checks do not establish that the target is secure. "
                "Potential findings require human validation."
            ),
        ]
    )

    if not isinstance(target, ToolExecutionCapability):
        report.notes.append(
            "Tool permission check skipped: target does not expose "
            "the tool execution capability."
        )

    return report


def run_local_assessment() -> AssessmentReport:
    """Run the offline synthetic demonstration."""

    from nulltrace.adapters.mock_agent import LocalMockAgent

    report = run_assessment(LocalMockAgent())
    report.notes.insert(
        0,
        "Offline synthetic demonstration; no external target was contacted.",
    )
    return report

