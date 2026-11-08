"""Report validation and Markdown rendering.

``validate_report`` checks the structural integrity of a report dict
before rendering or persisting it, so malformed or hand-edited reports
fail loudly instead of producing misleading output.
"""

from typing import Any

from nulltrace.core.models import SCHEMA_VERSION, SEVERITY_ORDER, Severity

_REQUIRED_TOP_LEVEL = (
    "schema_version",
    "project",
    "assessment_id",
    "target",
    "mode",
    "started_at",
    "completed_at",
    "assessment_status",
    "summary",
    "results",
    "findings",
)

_REQUIRED_FINDING_FIELDS = (
    "finding_id",
    "check_id",
    "title",
    "description",
    "category",
    "severity",
    "confidence",
    "evidence",
    "reproduction_steps",
    "expected_behavior",
    "actual_behavior",
    "impact",
    "remediation",
    "validation_status",
)


class ReportValidationError(ValueError):
    """Raised when a report does not conform to the expected schema."""


def validate_report(data: dict[str, Any]) -> None:
    """Validate the structure of a report dict; raise on problems."""

    for key in _REQUIRED_TOP_LEVEL:
        if key not in data:
            raise ReportValidationError(f"Report is missing field '{key}'.")

    if data["schema_version"] != SCHEMA_VERSION:
        raise ReportValidationError(
            f"Unsupported report schema version '{data['schema_version']}' "
            f"(expected '{SCHEMA_VERSION}')."
        )

    if not isinstance(data["results"], list) or not isinstance(
        data["findings"], list
    ):
        raise ReportValidationError("'results' and 'findings' must be lists.")

    for finding in data["findings"]:
        if not isinstance(finding, dict):
            raise ReportValidationError("Each finding must be an object.")
        for key in _REQUIRED_FINDING_FIELDS:
            if key not in finding:
                raise ReportValidationError(
                    f"Finding is missing field '{key}'."
                )


def _inline_code(text: str) -> str:
    """Make arbitrary evidence text safe for an inline Markdown code span."""

    return text.replace("`", "'").replace("\n", " ⏎ ")


def _severity_sort_key(finding: dict[str, Any]) -> int:
    try:
        return SEVERITY_ORDER[Severity(finding["severity"])]
    except (KeyError, ValueError):
        return len(SEVERITY_ORDER)


def to_markdown(data: dict[str, Any]) -> str:
    """Render a validated report dict as professional Markdown."""

    validate_report(data)

    summary = data["summary"]
    status_counts = summary.get("status_counts", {})
    lines = [
        f"# {data['project']} security assessment",
        "",
        f"- **Assessment ID:** `{data['assessment_id']}`",
        f"- **Target:** `{data['target']}`",
        f"- **Mode:** {data['mode']}",
        f"- **Profile:** {data.get('profile', 'n/a')}",
        f"- **Scope:** {data.get('scope', 'n/a')}",
        f"- **Started:** {data['started_at']}",
        f"- **Completed:** {data['completed_at']}",
        f"- **Status:** {data['assessment_status']}",
        f"- **Synthetic target:** {'yes' if data.get('synthetic_target') else 'no'}",
        (
            f"- **Requests used:** {data.get('requests_used', 0)}"
            + (
                f" / {data['request_limit']}"
                if data.get("request_limit") is not None
                else ""
            )
        ),
        f"- **Modules executed:** {', '.join(data.get('modules_executed', []))}",
        "",
    ]

    # Executive summary.
    severities = summary.get("findings_by_severity", {})
    headline_bits = [
        f"{severities.get(sev, 0)} {sev}"
        for sev in ("critical", "high", "medium", "low", "informational")
        if severities.get(sev, 0)
    ]
    headline = ", ".join(headline_bits) if headline_bits else "no findings"
    lines += [
        "## Executive summary",
        "",
        f"This assessment executed {summary.get('checks_executed', 0)} checks "
        f"against `{data['target']}` using the `{data.get('profile', 'n/a')}` "
        f"profile and recorded {summary.get('findings_total', 0)} finding(s) "
        f"({headline}). "
        + (
            "The target is a local synthetic fixture; findings are "
            "illustrative and not real-world vulnerabilities. "
            if data.get("synthetic_target")
            else ""
        )
        + "All findings are machine-generated and require human validation "
        "before being treated as confirmed vulnerabilities.",
        "",
    ]

    # Methodology.
    methodology = data.get("config", {}).get("methodology")
    if isinstance(methodology, dict):
        lines += [
            "## Methodology",
            "",
            f"- **Probe corpus version:** {methodology.get('corpus_version', 'n/a')}",
            f"- **Corpus depth:** {methodology.get('corpus_depth', 'n/a')} "
            "(1=first probe/family, 2=three, 3=full family)",
            f"- **Deterministic mutations/probe:** {methodology.get('mutations', 0)}",
            f"- **Sampling policy:** {methodology.get('sampling_policy', 'n/a')} "
            f"({methodology.get('samples_per_probe', 1)} sample(s) per probe)",
            f"- **Profile:** {methodology.get('profile_description', '')}",
            "- **Detection:** attribution-based (unique per-assessment probe "
            "tokens and declared synthetic markers); heuristic-only "
            "observations are capped at INCONCLUSIVE and never auto-confirmed.",
            "",
        ]

    lines += [
        "## Results summary",
        "",
        "| Outcome | Count |",
        "| --- | --- |",
    ]

    for status in ("pass", "fail", "inconclusive", "error", "skipped"):
        lines.append(f"| {status} | {status_counts.get(status, 0)} |")

    lines += [
        f"| **findings** | **{summary.get('findings_total', 0)}** |",
        "",
    ]

    findings = sorted(data["findings"], key=_severity_sort_key)

    lines += ["## Findings", ""]

    if not findings:
        lines += [
            "No findings were generated by the executed checks. This does "
            "not establish that the target is secure.",
            "",
        ]

    for item in findings:
        lines += [
            f"### {item['finding_id']} — {item['title']}",
            "",
            f"- **Severity:** {item['severity']}",
            f"- **Confidence:** {item['confidence']}",
            f"- **Validation status:** {item['validation_status']}",
            f"- **Category:** {item['category']}",
            f"- **Check:** {item['check_id']}",
            f"- **Affected component:** {item.get('affected_component', '')}",
            (
                f"- **Probe IDs:** {', '.join(item['probe_ids'])}"
                if item.get("probe_ids")
                else "- **Probe IDs:** n/a"
            ),
            (
                "- **Reproducibility:** "
                + ", ".join(
                    f"{key}={value}"
                    for key, value in item["reproducibility"].items()
                )
                if item.get("reproducibility")
                else "- **Reproducibility:** single-shot (no repeated sampling)"
            ),
            "",
            item["description"],
            "",
            f"**Expected behavior:** {item['expected_behavior']}",
            "",
            f"**Actual behavior:** {item['actual_behavior']}",
            "",
            f"**Impact:** {item['impact']}",
            "",
            f"**Remediation:** {item['remediation']}",
            "",
            "**Reproduction steps:**",
            "",
        ]
        lines.extend(
            f"{number}. {step}"
            for number, step in enumerate(item["reproduction_steps"], start=1)
        )
        lines += ["", "**Evidence:**", ""]
        for evidence in item["evidence"]:
            synthetic = " (synthetic)" if evidence.get("synthetic") else ""
            lines += [
                f"- Probe{synthetic}: `{_inline_code(evidence['probe'])}`",
                f"  - Response: `{_inline_code(evidence['response'])}`",
            ]
            if evidence.get("note"):
                lines.append(f"  - Note: {evidence['note']}")
        if item.get("references"):
            lines += ["", "**References:**", ""]
            lines.extend(f"- {ref}" for ref in item["references"])
        lines.append("")

    lines += [
        "## Check results",
        "",
        "| Check | Module | Status | Details |",
        "| --- | --- | --- | --- |",
    ]

    for result in data["results"]:
        details = str(result.get("details", "")).replace("|", "\\|")
        lines.append(
            f"| {result['check_id']} | {result['module']} "
            f"| {result['status']} | {details} |"
        )

    lines += ["", "## Notes", ""]
    lines.extend(f"- {note}" for note in data.get("notes", []))

    lines += ["", "## Limitations", ""]
    lines.extend(f"- {item}" for item in data.get("limitations", []))

    return "\n".join(lines) + "\n"
