"""Web service layer: wires the API to the existing assessment engine.

No business logic is duplicated here: assessments run through
``nulltrace.core.runner.run_assessment`` exactly as the CLI does.  Mock
assessments execute synchronously (they are instant and offline); API
assessments run in a background thread so the server is never blocked by
network waits.
"""

import json
import os
import threading
from pathlib import Path
from typing import Any

from nulltrace.adapters.base import TargetAdapter
from nulltrace.adapters.openai_compatible import (
    OpenAICompatibleAdapter,
    validate_base_url,
)
from nulltrace.checks.registry import MODULES, PROFILES
from nulltrace.core.budget import RequestBudget
from nulltrace.core.models import ValidationStatus, new_assessment_id
from nulltrace.core.redaction import redact_text
from nulltrace.core.runner import run_assessment
from nulltrace.reporting.render import to_markdown
from nulltrace.targets.registry import (
    DEMO_TARGETS,
    get_definition,
    list_demo_targets,
)
from nulltrace.web import auth
from nulltrace.web.db import Database


class ServiceError(ValueError):
    """Raised for invalid requests to the web service."""


class NotFoundError(ServiceError):
    """Raised when a referenced entity does not exist."""


class AuthError(ServiceError):
    """Raised for authentication/authorization failures."""


class AssessmentService:
    def __init__(self, db_path: Path) -> None:
        self.db = Database(db_path)

    # ------------------------------------------------------------------
    # Authentication, users, audit
    # ------------------------------------------------------------------

    def setup_mode(self) -> bool:
        """True when no users exist: the platform is open for local setup."""

        return self.db.count_users() == 0

    def create_user(self, username: str, password: str, role: str) -> int:
        username = username.strip()
        if not username or len(username) > 64:
            raise ServiceError("Username must be 1-64 characters.")
        parsed_role = auth.parse_role(role)
        try:
            password_hash = auth.hash_password(password)
        except ValueError as exc:
            raise ServiceError(str(exc)) from exc
        if self.db.get_user_by_name(username) is not None:
            raise ServiceError("A user with this name already exists.")
        return self.db.create_user(username, password_hash, parsed_role.value)

    def authenticate(self, username: str, password: str) -> str:
        """Verify credentials and return a new session token (raw)."""

        user = self.db.get_user_by_name(username.strip())
        # Always run a hash verification to reduce username enumeration
        # via timing, even when the user does not exist.
        stored = user["password_hash"] if user else auth.hash_password(
            "x" * 12
        )
        valid = auth.verify_password(password, stored)
        if not user or bool(user["disabled"]) or not valid:
            raise AuthError("Invalid username or password.")

        token = auth.new_session_token()
        self.db.create_session(
            auth.hash_session_token(token),
            int(user["id"]),
            auth.session_expiry(),
        )
        return token

    def resolve_session(self, token: str) -> dict[str, Any] | None:
        """Return the user for a valid, unexpired session token, else None."""

        session = self.db.get_session(auth.hash_session_token(token))
        if session is None:
            return None
        if auth.is_expired(str(session["expires_at"])):
            self.db.delete_session(str(session["token_hash"]))
            return None
        user = self.db.get_user(int(session["user_id"]))
        if user is None or bool(user["disabled"]):
            return None
        return user

    def logout(self, token: str) -> None:
        self.db.delete_session(auth.hash_session_token(token))

    def list_users(self) -> list[dict[str, Any]]:
        return self.db.list_users()

    def set_user_disabled(self, user_id: int, disabled: bool) -> None:
        if not self.db.set_user_disabled(user_id, disabled):
            raise NotFoundError("User not found.")

    def audit(
        self, actor: str, action: str, detail: str = "", outcome: str = "ok"
    ) -> None:
        # Redact any secrets that might appear in a detail string.
        self.db.append_audit(actor, action, redact_text(detail), outcome)

    def list_audit(self, limit: int = 200) -> list[dict[str, Any]]:
        return self.db.list_audit(limit)

    # ------------------------------------------------------------------
    # Modules
    # ------------------------------------------------------------------

    def list_modules(self) -> list[dict[str, Any]]:
        modules: list[dict[str, Any]] = []

        for name, checks in MODULES.items():
            modules.append(
                {
                    "name": name,
                    "check_count": len(checks),
                    "implemented": True,
                    "checks": [
                        {
                            "check_id": check.check_id,
                            "title": check.title,
                            "description": check.description,
                            "required_capability": (
                                check.required_capability.__name__
                                if check.required_capability is not None
                                else None
                            ),
                        }
                        for check in checks
                    ],
                    "profiles": [
                        profile
                        for profile, members in PROFILES.items()
                        if name in members
                    ],
                }
            )

        return modules

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    def list_demo_targets(self) -> list[dict[str, Any]]:
        return list_demo_targets()

    def list_targets(self) -> list[dict[str, Any]]:
        builtin = [
            {
                "id": definition.info.id,
                "name": definition.info.display_name,
                "type": "demo_lab",
                "base_url": None,
                "model": definition.info.model_label,
                "api_key_env": None,
                "timeout": None,
                "max_requests": None,
                "allow_network": False,
                "builtin": True,
                "description": definition.info.description,
                "provider_label": definition.info.provider_label,
                "security_profile": definition.info.security_profile,
                "environment": definition.info.environment,
            }
            for definition in DEMO_TARGETS.values()
        ]

        stored = [
            {
                "id": row["id"],
                "name": row["name"],
                "type": row["type"],
                "base_url": row["base_url"],
                "model": row["model"],
                "api_key_env": row["api_key_env"],
                "timeout": row["timeout"],
                "max_requests": row["max_requests"],
                "allow_network": bool(row["allow_network"]),
                "builtin": False,
                "description": "Configured OpenAI-compatible API target.",
            }
            for row in self.db.list_targets()
        ]

        return builtin + stored

    def create_target(
        self,
        name: str,
        base_url: str,
        model: str,
        api_key_env: str,
        timeout: float,
        max_requests: int,
        allow_network: bool,
    ) -> int:
        name = name.strip()

        if not name:
            raise ServiceError("Target name cannot be empty.")

        if name in DEMO_TARGETS:
            raise ServiceError("Target name conflicts with a built-in target.")

        if not model.strip():
            raise ServiceError("Model name cannot be empty.")

        if not api_key_env.strip() or "=" in api_key_env:
            raise ServiceError("API key environment variable name is invalid.")

        if timeout <= 0 or timeout > 300:
            raise ServiceError("Timeout must be between 1 and 300 seconds.")

        if max_requests <= 0 or max_requests > 500:
            raise ServiceError("Request budget must be between 1 and 500.")

        try:
            normalized = validate_base_url(base_url)
        except ValueError as exc:
            raise ServiceError(f"Base URL rejected: {exc}") from exc

        try:
            return self.db.create_target(
                name=name,
                type_="openai_compatible",
                base_url=normalized,
                model=model.strip(),
                api_key_env=api_key_env.strip(),
                timeout=timeout,
                max_requests=max_requests,
                allow_network=allow_network,
            )
        except Exception as exc:  # sqlite IntegrityError on duplicate name
            raise ServiceError(
                "A target with this name already exists."
            ) from exc

    def delete_target(self, target_id: int) -> None:
        if not self.db.delete_target(target_id):
            raise NotFoundError("Target not found.")

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def start_assessment(
        self,
        target_id: str,
        profile: str = "standard",
        modules: list[str] | None = None,
        max_requests: int | None = None,
        timeout: float | None = None,
        allow_network: bool = False,
        secure_variant: bool = False,
    ) -> dict[str, Any]:
        if modules:
            unknown = [name for name in modules if name not in MODULES]
            if unknown:
                raise ServiceError(
                    f"Unknown assessment module(s): {', '.join(sorted(unknown))}."
                )
        elif profile not in PROFILES:
            raise ServiceError(f"Unknown profile '{profile}'.")

        assessment_id = new_assessment_id()

        definition = get_definition(target_id)

        if definition is not None:
            variant = "secure" if secure_variant else definition.default_profile
            target = definition.build(variant)

            self.db.create_assessment(
                assessment_id,
                target_ref=target_id,
                target_name=target.target_name,
                mode="mock",
                profile=profile if not modules else "custom",
                modules=modules or PROFILES.get(profile, []),
                status="running",
                provider_label=definition.info.provider_label,
                model_label=definition.info.model_label,
                security_profile=definition.info.security_profile,
                variant=variant,
            )

            self._execute(
                assessment_id,
                target=target,
                request_budget=None,
                modules=modules,
                profile=profile,
                mode="mock",
                known_secrets=(),
            )
            record = self.db.get_assessment(assessment_id)
            assert record is not None
            record["modules"] = json.loads(record["modules"])
            record.pop("report_json", None)
            return record

        # Stored API target.
        try:
            numeric_id = int(target_id)
        except ValueError as exc:
            raise NotFoundError("Target not found.") from exc

        row = self.db.get_target(numeric_id)

        if row is None:
            raise NotFoundError("Target not found.")

        if not allow_network or not bool(row["allow_network"]):
            raise ServiceError(
                "Network assessments require explicit authorization: the "
                "target must be marked network-authorized AND the request "
                "must set allow_network."
            )

        budget = RequestBudget(
            max_requests=max_requests or int(row["max_requests"])
        )

        adapter = OpenAICompatibleAdapter(
            model=str(row["model"]),
            base_url=str(row["base_url"]),
            api_key_env=str(row["api_key_env"]),
            timeout=timeout or float(row["timeout"]),
            request_budget=budget,
        )

        api_key = os.getenv(str(row["api_key_env"])) or ""

        self.db.create_assessment(
            assessment_id,
            target_ref=f"target:{numeric_id}",
            target_name=adapter.target_name,
            mode="api",
            profile=profile if not modules else "custom",
            modules=modules or PROFILES.get(profile, []),
            status="running",
        )

        thread = threading.Thread(
            target=self._execute,
            kwargs={
                "assessment_id": assessment_id,
                "target": adapter,
                "request_budget": budget,
                "modules": modules,
                "profile": profile,
                "mode": "api",
                "known_secrets": (api_key,) if api_key else (),
            },
            daemon=True,
        )
        thread.start()

        record = self.db.get_assessment(assessment_id)
        assert record is not None
        record["modules"] = json.loads(record["modules"])
        record.pop("report_json", None)
        return record

    def _execute(
        self,
        assessment_id: str,
        target: TargetAdapter,
        request_budget: RequestBudget | None,
        modules: list[str] | None,
        profile: str,
        mode: str,
        known_secrets: tuple[str, ...],
    ) -> None:
        try:
            report = run_assessment(
                target,
                request_budget=request_budget,
                modules=modules,
                profile=profile,
                mode=mode,
                known_secrets=known_secrets,
                assessment_id=assessment_id,
            )
        except Exception as exc:  # noqa: BLE001 - persisted, never raised to API
            self.db.finish_assessment(
                assessment_id,
                status="failed",
                report=None,
                error=redact_text(f"{type(exc).__name__}: {exc}", known_secrets),
            )
            return

        data = report.to_dict()
        self.db.finish_assessment(
            assessment_id,
            status=report.assessment_status,
            report=data,
        )
        self.db.insert_findings(assessment_id, data["findings"])

    def delete_assessments(self, ids: list[str]) -> dict[str, Any]:
        """Delete assessments (and, via cascade, their findings).

        Reports are rendered from the stored assessment row, so deleting
        the row removes the assessment's report as well. Targets, module
        configuration, and other assessments are never affected.

        Assessments still ``running`` are refused (``skipped_running``)
        so a background worker never writes into a deleted row. Unknown
        ids are reported back, not treated as an error for the batch.
        """

        unique_ids = list(dict.fromkeys(ids))

        if not unique_ids:
            raise ServiceError("At least one assessment id is required.")

        if len(unique_ids) > 100:
            raise ServiceError(
                "At most 100 assessments can be deleted per request."
            )

        statuses = self.db.get_assessment_statuses(unique_ids)
        not_found = [aid for aid in unique_ids if aid not in statuses]
        skipped_running = [
            aid for aid, status in statuses.items() if status == "running"
        ]
        deletable = [
            aid
            for aid in unique_ids
            if aid in statuses and aid not in skipped_running
        ]

        deleted_count = self.db.delete_assessments(deletable)

        return {
            "deleted": deletable,
            "deleted_count": deleted_count,
            "not_found": not_found,
            "skipped_running": skipped_running,
        }

    def list_assessments(self) -> list[dict[str, Any]]:
        records = self.db.list_assessments()

        for record in records:
            record["modules"] = json.loads(record["modules"])
            record["summary"] = self._summary_for(record["id"])

        return records

    def _summary_for(self, assessment_id: str) -> dict[str, Any] | None:
        record = self.db.get_assessment(assessment_id)

        if record is None or not record.get("report_json"):
            return None

        report = json.loads(record["report_json"])
        summary: dict[str, Any] = report["summary"]
        return summary

    def get_assessment(self, assessment_id: str) -> dict[str, Any]:
        record = self.db.get_assessment(assessment_id)

        if record is None:
            raise NotFoundError("Assessment not found.")

        record["modules"] = json.loads(record["modules"])
        record["report"] = (
            json.loads(record.pop("report_json"))
            if record.get("report_json")
            else None
        )
        # Reflect current review state in the returned report.
        if record["report"] is not None:
            current = {
                row["finding_id"]: row
                for row in self.db.query_findings(assessment_id=assessment_id)
            }
            for finding in record["report"]["findings"]:
                row = current.get(finding["finding_id"])
                if row is not None:
                    finding["validation_status"] = row["validation_status"]
                    finding["review_note"] = row["review_note"]
        return record

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def query_findings(self, **filters: Any) -> list[dict[str, Any]]:
        rows = self.db.query_findings(**filters)
        return [self._finding_payload(row) for row in rows]

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        row = self.db.get_finding(finding_id)

        if row is None:
            raise NotFoundError("Finding not found.")

        return self._finding_payload(row)

    @staticmethod
    def _finding_payload(row: dict[str, Any]) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(row["data_json"])
        data["validation_status"] = row["validation_status"]
        data["review_note"] = row["review_note"]
        return data

    def review_finding(
        self, finding_id: str, validation_status: str, note: str = ""
    ) -> dict[str, Any]:
        try:
            status = ValidationStatus(validation_status)
        except ValueError as exc:
            valid = ", ".join(item.value for item in ValidationStatus)
            raise ServiceError(
                f"Invalid validation status. Valid values: {valid}."
            ) from exc

        row = self.db.get_finding(finding_id)

        if row is None:
            raise NotFoundError("Finding not found.")

        self.db.update_finding_review(finding_id, status.value, note)

        # Patch the stored report so downloads reflect review state.
        record = self.db.get_assessment(row["assessment_id"])
        if record is not None and record.get("report_json"):
            report = json.loads(record["report_json"])
            for finding in report["findings"]:
                if finding["finding_id"] == finding_id:
                    finding["validation_status"] = status.value
                    finding["review_note"] = note
            self.db.update_report_json(row["assessment_id"], report)

        return self.get_finding(finding_id)

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def render_report(
        self, assessment_id: str, output_format: str
    ) -> tuple[str, str, str]:
        """Return (content, media_type, filename) for a report download."""

        record = self.get_assessment(assessment_id)
        report = record["report"]

        if report is None:
            raise ServiceError(
                "This assessment has no report (still running or failed)."
            )

        if output_format == "json":
            return (
                json.dumps(report, indent=2),
                "application/json",
                f"{assessment_id}.json",
            )

        if output_format == "markdown":
            return (
                to_markdown(report),
                "text/markdown",
                f"{assessment_id}.md",
            )

        raise ServiceError("Report format must be 'json' or 'markdown'.")

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def dashboard_summary(self) -> dict[str, Any]:
        assessments = self.db.list_assessments(limit=1000)
        severity = self.db.count_findings_by("severity")
        validation = self.db.count_findings_by("validation_status")

        check_totals = {
            "pass": 0,
            "fail": 0,
            "inconclusive": 0,
            "error": 0,
            "skipped": 0,
        }
        for record in assessments:
            summary = self._summary_for(record["id"])
            if summary:
                for key, value in summary["status_counts"].items():
                    check_totals[key] = check_totals.get(key, 0) + int(value)

        return {
            "assessments_total": len(assessments),
            "assessments_by_status": self.db.count_assessments_by_status(),
            "findings_total": sum(severity.values()),
            "findings_by_severity": severity,
            "findings_by_validation": validation,
            "checks_by_status": check_totals,
            "recent_assessments": self.list_assessments()[:8],
            "recent_findings": self.query_findings(limit=8),
        }

    def dashboard_analytics(self) -> dict[str, Any]:
        assessments = self.db.list_assessments(limit=200)
        history: list[dict[str, Any]] = []
        module_coverage: dict[str, int] = {}

        for record in reversed(assessments):
            summary = self._summary_for(record["id"])
            history.append(
                {
                    "assessment_id": record["id"],
                    "created_at": record["created_at"],
                    "status": record["status"],
                    "target_name": record["target_name"],
                    "checks_executed": (
                        summary["checks_executed"] if summary else 0
                    ),
                    "findings_total": (
                        summary["findings_total"] if summary else 0
                    ),
                    "status_counts": (
                        summary["status_counts"] if summary else {}
                    ),
                }
            )
            for module in json.loads(record["modules"]):
                module_coverage[module] = module_coverage.get(module, 0) + 1

        return {
            "history": history,
            "module_coverage": module_coverage,
            "findings_by_category": self.db.count_findings_by("category"),
            "findings_by_confidence": self.db.count_findings_by("confidence"),
        }
