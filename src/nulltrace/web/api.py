"""FastAPI backend for the NullTrace AI web platform.

Security posture:

- Multi-user authentication with role-based access control. Until the
  first user is created the platform runs in **setup mode** (open, for
  local bootstrap); once any user exists, every /api route except the
  meta/health/auth-login routes requires a valid session.
- Roles (viewer < analyst < researcher < admin) gate endpoints by least
  privilege. Security-relevant actions are written to an audit log.
- API keys for assessment targets are never accepted, stored, or
  returned — only environment-variable *names* are handled.
- Session tokens are stored only as hashes; CORS is restricted to
  localhost dev origins. Still intended for local/trusted deployment —
  see docs/SECURITY_REVIEW.md for the pending external review.
"""

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from nulltrace import __version__
from nulltrace.web.auth import Role, role_at_least
from nulltrace.web.service import (
    AssessmentService,
    AuthError,
    NotFoundError,
    ServiceError,
)

DEFAULT_DB_PATH = Path("data/nulltrace.db")

_DEV_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]


@dataclass(frozen=True)
class Principal:
    name: str
    role: Role
    authenticated: bool


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="viewer", max_length=32)


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    base_url: str = Field(min_length=1, max_length=500)
    model: str = Field(min_length=1, max_length=200)
    api_key_env: str = Field(default="OPENAI_API_KEY", max_length=120)
    timeout: float = Field(default=30.0, gt=0, le=300)
    max_requests: int = Field(default=10, ge=1, le=500)
    allow_network: bool = False


class AssessmentCreate(BaseModel):
    target_id: str = Field(min_length=1, max_length=80)
    profile: str = Field(default="standard", max_length=40)
    modules: list[str] | None = None
    max_requests: int | None = Field(default=None, ge=1, le=500)
    timeout: float | None = Field(default=None, gt=0, le=300)
    allow_network: bool = False
    secure_variant: bool = False


class AssessmentDeleteBatch(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=100)


class FindingReview(BaseModel):
    validation_status: str = Field(min_length=1, max_length=40)
    note: str = Field(default="", max_length=2000)


_logger = logging.getLogger("nulltrace.web")


def _maybe_bootstrap_admin(service: AssessmentService) -> None:
    """Optionally create the first admin from environment secrets.

    Opt-in and non-destructive. Runs only when BOTH
    ``NULLTRACE_BOOTSTRAP_ADMIN_USERNAME`` and
    ``NULLTRACE_BOOTSTRAP_ADMIN_PASSWORD`` are set AND no users exist yet.
    This closes the open "setup mode" window at startup on platforms where
    an interactive shell (for ``nulltrace user-add``) is unavailable. It
    never overwrites an existing user, never exposes an endpoint, and —
    when the variables are unset — leaves behavior exactly as before. The
    password is read from a backend environment variable only and is never
    logged.
    """

    username = os.getenv("NULLTRACE_BOOTSTRAP_ADMIN_USERNAME", "").strip()
    password = os.getenv("NULLTRACE_BOOTSTRAP_ADMIN_PASSWORD", "")
    if not username or not password:
        return
    if not service.setup_mode():
        # Users already exist; never overwrite or reset them.
        return
    try:
        service.create_user(username, password, "admin")
    except ServiceError as exc:
        _logger.error("First-admin bootstrap skipped: %s", exc)
        return
    _logger.info(
        "Bootstrapped first admin '%s' from environment; setup mode closed.",
        username,
    )


def create_app(db_path: Path | None = None) -> FastAPI:
    service = AssessmentService(
        db_path or Path(os.getenv("NULLTRACE_DB_PATH", str(DEFAULT_DB_PATH)))
    )
    _maybe_bootstrap_admin(service)

    app = FastAPI(
        title="NullTrace AI",
        version=__version__,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_DEV_ORIGINS,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type", "X-API-Token", "X-Session-Token"],
    )

    def get_principal(request: Request) -> Principal:
        """Resolve the caller to a Principal, or raise 401.

        A valid session header always wins. Otherwise, in setup mode (no
        users yet) the caller is treated as a local admin so the platform
        can be bootstrapped; an optional ``NULLTRACE_API_TOKEN`` adds a
        shared-secret guard to that open window. Once any user exists,
        setup mode ends and a session is mandatory.
        """

        token = request.headers.get("X-Session-Token")
        if token:
            user = service.resolve_session(token)
            if user is not None:
                return Principal(
                    name=str(user["username"]),
                    role=Role(user["role"]),
                    authenticated=True,
                )

        if service.setup_mode():
            expected = os.getenv("NULLTRACE_API_TOKEN")
            if expected and request.headers.get("X-API-Token") != expected:
                raise HTTPException(status_code=401, detail="Invalid API token.")
            return Principal(name="setup", role=Role.ADMIN, authenticated=False)

        raise HTTPException(status_code=401, detail="Authentication required.")

    def require_role(minimum: Role) -> Callable[[Request], Principal]:
        def dependency(request: Request) -> Principal:
            principal = get_principal(request)
            if not role_at_least(principal.role, minimum):
                raise HTTPException(
                    status_code=403,
                    detail=f"This action requires at least the "
                    f"'{minimum.value}' role.",
                )
            return principal

        return dependency

    guarded = Depends(require_role(Role.VIEWER))
    PView = Annotated[Principal, Depends(require_role(Role.VIEWER))]
    PAnalyst = Annotated[Principal, Depends(require_role(Role.ANALYST))]
    PResearcher = Annotated[Principal, Depends(require_role(Role.RESEARCHER))]
    PAdmin = Annotated[Principal, Depends(require_role(Role.ADMIN))]

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    # ------------------------------------------------------------------
    # Meta
    # ------------------------------------------------------------------

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/version")
    def version() -> dict[str, str]:
        return {"project": "NullTrace AI", "version": __version__}

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    @app.get("/api/auth/status")
    def auth_status(request: Request) -> dict[str, Any]:
        token = request.headers.get("X-Session-Token")
        user = service.resolve_session(token) if token else None
        return {
            "setup_mode": service.setup_mode(),
            "authenticated": user is not None,
            "user": (
                {"username": user["username"], "role": user["role"]}
                if user
                else None
            ),
        }

    @app.post("/api/auth/login")
    def login(payload: LoginRequest, request: Request) -> dict[str, Any]:
        try:
            token = service.authenticate(payload.username, payload.password)
        except AuthError as exc:
            service.audit(
                payload.username, "login", f"from {client_ip(request)}", "fail"
            )
            raise HTTPException(status_code=401, detail=str(exc)) from exc

        service.audit(payload.username, "login", f"from {client_ip(request)}")
        user = service.db.get_user_by_name(payload.username.strip())
        assert user is not None
        return {"token": token, "role": user["role"], "username": user["username"]}

    @app.post("/api/auth/logout")
    def logout(request: Request) -> Response:
        token = request.headers.get("X-Session-Token")
        if token:
            user = service.resolve_session(token)
            service.logout(token)
            if user is not None:
                service.audit(str(user["username"]), "logout", "")
        return Response(status_code=204)

    @app.get("/api/auth/me")
    def me(principal: PView) -> dict[str, Any]:
        return {
            "username": principal.name,
            "role": principal.role.value,
            "authenticated": principal.authenticated,
        }

    # ------------------------------------------------------------------
    # User management (admin)
    # ------------------------------------------------------------------

    @app.get("/api/users")
    def list_users(principal: PAdmin) -> list[dict[str, Any]]:
        return service.list_users()

    @app.post("/api/users", status_code=201)
    def create_user(payload: UserCreate, request: Request) -> dict[str, Any]:
        # The very first user may be created in setup mode (no auth yet);
        # afterwards, only an admin may create users.
        if not service.setup_mode():
            require_role(Role.ADMIN)(request)
        actor = get_principal(request).name if not service.setup_mode() else "setup"
        try:
            user_id = service.create_user(
                payload.username, payload.password, payload.role
            )
        except ServiceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        service.audit(
            actor, "user.create",
            f"username={payload.username} role={payload.role}",
        )
        return {"id": user_id}

    @app.patch("/api/users/{user_id}/disable")
    def disable_user(
        user_id: int, principal: PAdmin, disabled: bool = True
    ) -> Response:
        try:
            service.set_user_disabled(user_id, disabled)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        service.audit(
            principal.name, "user.disable", f"user_id={user_id} disabled={disabled}"
        )
        return Response(status_code=204)

    @app.get("/api/audit")
    def audit_log(principal: PAdmin) -> list[dict[str, Any]]:
        return service.list_audit()

    # ------------------------------------------------------------------
    # Modules
    # ------------------------------------------------------------------

    @app.get("/api/modules", dependencies=[guarded])
    def modules() -> list[dict[str, Any]]:
        return service.list_modules()

    # ------------------------------------------------------------------
    # Demo Target Lab
    # ------------------------------------------------------------------

    @app.get("/api/demo-targets", dependencies=[guarded])
    def demo_targets() -> list[dict[str, Any]]:
        return service.list_demo_targets()

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    @app.get("/api/targets", dependencies=[guarded])
    def list_targets() -> list[dict[str, Any]]:
        return service.list_targets()

    @app.post("/api/targets", status_code=201)
    def create_target(payload: TargetCreate, principal: PResearcher) -> dict[str, Any]:
        try:
            target_id = service.create_target(
                name=payload.name,
                base_url=payload.base_url,
                model=payload.model,
                api_key_env=payload.api_key_env,
                timeout=payload.timeout,
                max_requests=payload.max_requests,
                allow_network=payload.allow_network,
            )
        except ServiceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        service.audit(
            principal.name, "target.create",
            f"name={payload.name} network_authorized={payload.allow_network}",
        )
        return {"id": target_id}

    @app.delete("/api/targets/{target_id}", status_code=204)
    def delete_target(target_id: int, principal: PResearcher) -> Response:
        try:
            service.delete_target(target_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        service.audit(principal.name, "target.delete", f"target_id={target_id}")
        return Response(status_code=204)

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    @app.get("/api/assessments", dependencies=[guarded])
    def list_assessments() -> list[dict[str, Any]]:
        return service.list_assessments()

    @app.post("/api/assessments", status_code=201)
    def create_assessment(
        payload: AssessmentCreate, principal: PResearcher
    ) -> dict[str, Any]:
        try:
            record = service.start_assessment(
                target_id=payload.target_id,
                profile=payload.profile,
                modules=payload.modules,
                max_requests=payload.max_requests,
                timeout=payload.timeout,
                allow_network=payload.allow_network,
                secure_variant=payload.secure_variant,
            )
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ServiceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        service.audit(
            principal.name, "assessment.create",
            f"id={record['id']} target={payload.target_id} "
            f"profile={payload.profile}",
        )
        return record

    @app.delete("/api/assessments/{assessment_id}", status_code=204)
    def delete_assessment(assessment_id: str, principal: PResearcher) -> Response:
        try:
            result = service.delete_assessments([assessment_id])
        except ServiceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if result["skipped_running"]:
            raise HTTPException(
                status_code=409,
                detail=(
                    "This assessment is still running and cannot be "
                    "deleted yet."
                ),
            )

        if result["not_found"]:
            raise HTTPException(
                status_code=404, detail="Assessment not found."
            )

        service.audit(principal.name, "assessment.delete", f"id={assessment_id}")
        return Response(status_code=204)

    @app.post("/api/assessments/delete-batch")
    def delete_assessments_batch(
        payload: AssessmentDeleteBatch, principal: PResearcher
    ) -> dict[str, Any]:
        try:
            result = service.delete_assessments(payload.ids)
        except ServiceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        service.audit(
            principal.name, "assessment.delete_batch",
            f"requested={len(payload.ids)} deleted={result['deleted_count']}",
        )
        return result

    @app.get("/api/assessments/{assessment_id}", dependencies=[guarded])
    def get_assessment(assessment_id: str) -> dict[str, Any]:
        try:
            return service.get_assessment(assessment_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get(
        "/api/assessments/{assessment_id}/findings", dependencies=[guarded]
    )
    def assessment_findings(assessment_id: str) -> list[dict[str, Any]]:
        try:
            service.get_assessment(assessment_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        return service.query_findings(assessment_id=assessment_id)

    @app.get("/api/assessments/{assessment_id}/report")
    def download_report(
        assessment_id: str,
        principal: PView,
        format: Annotated[str, Query(pattern="^(json|markdown)$")] = "json",
    ) -> Response:
        try:
            content, media_type, filename = service.render_report(
                assessment_id, format
            )
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ServiceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        service.audit(
            principal.name, "report.download",
            f"assessment={assessment_id} format={format}",
        )

        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    @app.get("/api/findings", dependencies=[guarded])
    def list_findings(
        severity: str | None = None,
        confidence: str | None = None,
        category: str | None = None,
        validation_status: str | None = None,
        assessment_id: str | None = None,
        search: str | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 200,
    ) -> list[dict[str, Any]]:
        return service.query_findings(
            severity=severity,
            confidence=confidence,
            category=category,
            validation_status=validation_status,
            assessment_id=assessment_id,
            search=search,
            limit=limit,
        )

    @app.get("/api/findings/{finding_id}", dependencies=[guarded])
    def get_finding(finding_id: str) -> dict[str, Any]:
        try:
            return service.get_finding(finding_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.patch("/api/findings/{finding_id}/review")
    def review_finding(
        finding_id: str, payload: FindingReview, principal: PAnalyst
    ) -> dict[str, Any]:
        try:
            result = service.review_finding(
                finding_id,
                validation_status=payload.validation_status,
                note=payload.note,
            )
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ServiceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        service.audit(
            principal.name, "finding.review",
            f"id={finding_id} status={payload.validation_status}",
        )
        return result

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    @app.get("/api/dashboard/summary", dependencies=[guarded])
    def dashboard_summary() -> dict[str, Any]:
        return service.dashboard_summary()

    @app.get("/api/dashboard/analytics", dependencies=[guarded])
    def dashboard_analytics() -> dict[str, Any]:
        return service.dashboard_analytics()

    # ------------------------------------------------------------------
    # Frontend (built SPA, if present)
    # ------------------------------------------------------------------

    dist = Path(
        os.getenv("NULLTRACE_FRONTEND_DIST", "frontend/dist")
    ).resolve()

    if dist.is_dir() and (dist / "index.html").is_file():
        app.mount(
            "/assets",
            StaticFiles(directory=dist / "assets"),
            name="assets",
        )

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str) -> FileResponse:
            if full_path.startswith("api/"):
                raise HTTPException(status_code=404, detail="Not found.")

            candidate = (dist / full_path).resolve()

            if (
                full_path
                and candidate.is_file()
                and candidate.is_relative_to(dist)
            ):
                return FileResponse(candidate)

            return FileResponse(dist / "index.html")

    return app
