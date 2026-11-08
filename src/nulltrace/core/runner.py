"""Assessment orchestrator.

Responsibilities:

- resolve the module list (explicit modules or a named profile);
- execute each check with error isolation (one failing check never
  aborts the run);
- stop safely when the request budget is exhausted, marking remaining
  checks as skipped;
- redact secrets from all stored evidence;
- assign finding identifiers, deduplicate findings, and assemble the
  final report with honest notes and limitations.
"""

from nulltrace import __version__
from nulltrace.adapters.base import TargetAdapter
from nulltrace.checks.base import Check
from nulltrace.checks.registry import (
    PROFILE_EXECUTION,
    checks_for_modules,
    resolve_modules,
)
from nulltrace.core.budget import RequestBudget, RequestBudgetExceeded
from nulltrace.core.context import AssessmentContext
from nulltrace.core.models import (
    AssessmentReport,
    CheckResult,
    CheckStatus,
    Finding,
    make_finding_id,
    new_assessment_id,
    utc_now_iso,
)
from nulltrace.core.redaction import redact_text
from nulltrace.core.sampling import SamplingConfig, SamplingPolicy


def _corpus_version() -> str:
    from nulltrace.probes import corpus

    return corpus.CORPUS_VERSION


_STANDARD_LIMITATIONS = [
    "A finite probe set cannot prove the target secure; passed checks "
    "mean the specific probes were resisted, nothing more.",
    "Model behavior can be nondeterministic; reproduce findings before "
    "acting on them.",
    "Findings are generated in 'pending_review' status and require human "
    "validation before being treated as confirmed vulnerabilities.",
]


def _is_budget_exhaustion(exc: Exception) -> bool:
    if isinstance(exc, RequestBudgetExceeded):
        return True
    return "budget exhausted" in str(exc).lower()


def _redact_result(result: CheckResult, known_secrets: tuple[str, ...]) -> None:
    for evidence in result.evidence:
        evidence.probe = redact_text(evidence.probe, known_secrets)
        evidence.response = redact_text(evidence.response, known_secrets)
    for finding in result.findings:
        finding.actual_behavior = redact_text(
            finding.actual_behavior, known_secrets
        )
        for evidence in finding.evidence:
            evidence.probe = redact_text(evidence.probe, known_secrets)
            evidence.response = redact_text(evidence.response, known_secrets)


def _skip_result(check: Check, reason: str) -> CheckResult:
    return CheckResult(
        check_id=check.check_id,
        module=check.module,
        title=check.title,
        status=CheckStatus.SKIPPED,
        details=reason,
    )


def run_assessment(
    target: TargetAdapter,
    request_budget: RequestBudget | None = None,
    modules: list[str] | None = None,
    profile: str = "standard",
    mode: str = "mock",
    known_secrets: tuple[str, ...] = (),
    assessment_id: str | None = None,
) -> AssessmentReport:
    """Run the selected security checks against a target adapter."""

    module_names = resolve_modules(modules, profile)
    checks = checks_for_modules(module_names)

    if assessment_id is None:
        assessment_id = new_assessment_id()
    execution = PROFILE_EXECUTION.get(profile, PROFILE_EXECUTION["standard"])
    context = AssessmentContext(
        assessment_id=assessment_id,
        synthetic_target=target.is_synthetic,
        hints=target.assessment_hints(),
        corpus_depth=execution.corpus_depth,
        mutations=execution.mutations,
        sampling=SamplingConfig(
            policy=SamplingPolicy(execution.sampling_policy),
            samples=execution.samples,
        ),
    )

    started_at = utc_now_iso()
    results: list[CheckResult] = []
    budget_exhausted = False

    for check in checks:
        if budget_exhausted:
            results.append(
                _skip_result(
                    check, "Skipped: the request budget was exhausted."
                )
            )
            continue

        if check.required_capability is not None and not isinstance(
            target, check.required_capability
        ):
            results.append(
                _skip_result(
                    check,
                    "Skipped: the target does not expose the required "
                    f"capability ({check.required_capability.__name__}). "
                    "A skipped check is not evidence of a vulnerability.",
                )
            )
            continue

        try:
            result = check.run(target, context)
        except Exception as exc:  # noqa: BLE001 - error isolation by design
            if _is_budget_exhaustion(exc):
                budget_exhausted = True
                results.append(
                    _skip_result(
                        check,
                        "Skipped: the request budget was exhausted while "
                        "this check was running.",
                    )
                )
                continue
            result = CheckResult(
                check_id=check.check_id,
                module=check.module,
                title=check.title,
                status=CheckStatus.ERROR,
                details="The check could not be executed.",
                error=redact_text(f"{type(exc).__name__}: {exc}", known_secrets),
            )

        _redact_result(result, known_secrets)
        results.append(result)

    # Collect, link, and deduplicate findings.
    findings: list[Finding] = []
    seen_keys: set[tuple[str, str, str]] = set()
    ordinal = 1

    for result in results:
        for finding in result.findings:
            key = finding.dedup_key()
            if key in seen_keys:
                continue
            seen_keys.add(key)
            finding.assessment_id = assessment_id
            finding.finding_id = make_finding_id(
                assessment_id, finding.check_id, ordinal
            )
            ordinal += 1
            findings.append(finding)

    report = AssessmentReport(
        assessment_id=assessment_id,
        project="NullTrace AI",
        project_version=__version__,
        target=target.target_name,
        mode=mode,
        scope=(
            "Local synthetic fixture; no external systems were contacted."
            if target.is_synthetic
            else "Explicitly configured target endpoint only."
        ),
        profile=profile if not modules else "custom",
        modules_executed=module_names,
        started_at=started_at,
        completed_at=utc_now_iso(),
        results=results,
        findings=findings,
        synthetic_target=target.is_synthetic,
        request_limit=(
            request_budget.max_requests if request_budget is not None else None
        ),
        config={
            "modules": module_names,
            "profile": profile if not modules else "custom",
            "request_limit": (
                request_budget.max_requests
                if request_budget is not None
                else None
            ),
            "methodology": {
                "corpus_version": _corpus_version(),
                "corpus_depth": execution.corpus_depth,
                "mutations": execution.mutations,
                "sampling_policy": execution.sampling_policy,
                "samples_per_probe": execution.samples,
                "profile_description": execution.description,
            },
        },
    )

    if request_budget is not None:
        report.requests_used = request_budget.requests_used

    if budget_exhausted:
        report.assessment_status = "incomplete"
        report.notes.append(
            "Assessment stopped early: the request budget was exhausted. "
            "Remaining checks were skipped."
        )

    if target.is_synthetic:
        report.notes.append(
            "The target is a local synthetic fixture; all evidence is "
            "synthetic and no real data was involved."
        )

    report.limitations.extend(_STANDARD_LIMITATIONS)

    return report


def run_local_assessment(
    profile: str = "full",
    modules: list[str] | None = None,
    mock_profile: str = "hardened",
) -> AssessmentReport:
    """Run the offline synthetic assessment against the bundled mock agent."""

    from nulltrace.adapters.mock_agent import LocalMockAgent

    report = run_assessment(
        LocalMockAgent(profile=mock_profile),
        modules=modules,
        profile=profile,
        mode="mock",
    )
    report.notes.insert(
        0,
        "Offline synthetic demonstration; no external target was contacted.",
    )
    return report
