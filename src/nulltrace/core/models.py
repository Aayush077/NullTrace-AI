
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    status: str
    description: str
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AssessmentReport:
    project: str
    target: str
    started_at: str
    completed_at: str
    findings: list[Finding]
    notes: list[str] = field(default_factory=list)
    assessment_status: str = "completed"
    requests_used: int = 0
    request_limit: int | None = None

    @classmethod
    def create(
        cls,
        target: str,
        findings: list[Finding],
        request_limit: int | None = None,
    ) -> "AssessmentReport":
        now = datetime.now(UTC).isoformat()

        return cls(
            project="NullTrace AI",
            target=target,
            started_at=now,
            completed_at=now,
            findings=findings,
            request_limit=request_limit,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "target": self.target,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "assessment_status": self.assessment_status,
            "requests_used": self.requests_used,
            "request_limit": self.request_limit,
            "findings": [item.to_dict() for item in self.findings],
            "notes": self.notes,
        }

