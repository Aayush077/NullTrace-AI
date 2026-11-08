"""Core data models for assessments, check results, findings, and evidence.

Terminology
-----------
- A *check* is one executable security test.  It always produces a
  ``CheckResult`` whose status describes the *security outcome* of the
  check (``PASS``/``FAIL``/``INCONCLUSIVE``) or an *execution* problem
  (``ERROR``/``SKIPPED``).  A failed security check is not the same thing
  as a failed test execution.
- A *finding* is a structured, evidence-backed statement about the target,
  derived from one or more check results.  A finding starts in
  ``PENDING_REVIEW`` validation status; automation never promotes a
  potential vulnerability to a confirmed one.
"""

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = "1.0"


class CheckStatus(StrEnum):
    """Security outcome (or execution state) of one check."""

    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    SKIPPED = "skipped"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Confidence(StrEnum):
    """How strongly the collected evidence supports the finding."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ValidationStatus(StrEnum):
    """Human-review state of a finding. Automation only ever sets PENDING."""

    PENDING_REVIEW = "pending_review"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    NEEDS_RETESTING = "needs_retesting"


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class Evidence:
    """One probe/response pair preserved as assessment evidence.

    ``probe`` and ``response`` are stored after redaction; ``synthetic``
    marks evidence produced against a synthetic (mock) target or fixture.
    """

    probe: str
    response: str
    note: str = ""
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """Structured, evidence-backed security finding."""

    finding_id: str
    check_id: str
    title: str
    description: str
    category: str
    affected_component: str
    severity: Severity
    confidence: Confidence
    evidence: list[Evidence]
    reproduction_steps: list[str]
    expected_behavior: str
    actual_behavior: str
    impact: str
    remediation: str
    references: list[str] = field(default_factory=list)
    assessment_id: str = ""
    timestamp: str = field(default_factory=utc_now_iso)
    validation_status: ValidationStatus = ValidationStatus.PENDING_REVIEW
    #: Probe/variant IDs that produced this finding (corpus traceability).
    probe_ids: list[str] = field(default_factory=list)
    #: Reproducibility summary from repeated sampling (empty = single-shot).
    reproducibility: dict[str, Any] = field(default_factory=dict)

    def dedup_key(self) -> tuple[str, str, str]:
        digest = hashlib.sha256(self.actual_behavior.encode("utf-8")).hexdigest()[:16]
        return (self.check_id, self.title, digest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "affected_component": self.affected_component,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence": [item.to_dict() for item in self.evidence],
            "reproduction_steps": self.reproduction_steps,
            "expected_behavior": self.expected_behavior,
            "actual_behavior": self.actual_behavior,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "assessment_id": self.assessment_id,
            "timestamp": self.timestamp,
            "validation_status": self.validation_status.value,
            "probe_ids": self.probe_ids,
            "reproducibility": self.reproducibility,
        }


@dataclass
class CheckResult:
    """Outcome of executing a single check."""

    check_id: str
    module: str
    title: str
    status: CheckStatus
    details: str = ""
    objective: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    executed_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "module": self.module,
            "title": self.title,
            "status": self.status.value,
            "details": self.details,
            "objective": self.objective,
            "evidence": [item.to_dict() for item in self.evidence],
            "error": self.error,
            "executed_at": self.executed_at,
            "finding_ids": [finding.finding_id for finding in self.findings],
        }


def new_assessment_id() -> str:
    return f"NTA-{uuid.uuid4().hex[:12]}"


def make_finding_id(assessment_id: str, check_id: str, ordinal: int) -> str:
    return f"{assessment_id}-{check_id}-{ordinal:02d}"


@dataclass
class AssessmentReport:
    """Complete result of one assessment run."""

    assessment_id: str
    project: str
    project_version: str
    target: str
    mode: str
    scope: str
    profile: str
    modules_executed: list[str]
    started_at: str
    completed_at: str
    results: list[CheckResult]
    findings: list[Finding]
    notes: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    assessment_status: str = "completed"
    requests_used: int = 0
    request_limit: int | None = None
    synthetic_target: bool = False
    config: dict[str, Any] = field(default_factory=dict)

    @property
    def status_counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in CheckStatus}
        for result in self.results:
            counts[result.status.value] += 1
        return counts

    @property
    def findings_by_severity(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "project": self.project,
            "project_version": self.project_version,
            "assessment_id": self.assessment_id,
            "target": self.target,
            "mode": self.mode,
            "scope": self.scope,
            "profile": self.profile,
            "modules_executed": self.modules_executed,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "assessment_status": self.assessment_status,
            "synthetic_target": self.synthetic_target,
            "requests_used": self.requests_used,
            "request_limit": self.request_limit,
            "summary": {
                "checks_executed": len(self.results),
                "status_counts": self.status_counts,
                "findings_total": len(self.findings),
                "findings_by_severity": self.findings_by_severity,
            },
            "results": [result.to_dict() for result in self.results],
            "findings": [finding.to_dict() for finding in self.findings],
            "notes": self.notes,
            "limitations": self.limitations,
            "config": self.config,
        }
