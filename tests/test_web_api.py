"""API tests for the FastAPI backend (offline; mock targets only)."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nulltrace import __version__
from nulltrace.web.api import create_app


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    app = create_app(db_path=tmp_path / "test.db")
    return TestClient(app)


def _run_mock_assessment(
    client: TestClient, target: str = "demo-travel-agent", profile: str = "full"
) -> str:
    response = client.post(
        "/api/assessments",
        json={"target_id": target, "profile": profile},
    )
    assert response.status_code == 201, response.text
    data = response.json()
    assert data["status"] in {"completed", "incomplete"}
    assessment_id = data["id"]
    assert isinstance(assessment_id, str)
    return assessment_id


def test_health_and_version(client: TestClient) -> None:
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/api/version").json()["version"] == __version__


def test_modules_endpoint(client: TestClient) -> None:
    modules = client.get("/api/modules").json()

    names = {module["name"] for module in modules}
    assert "prompt_injection" in names
    assert all(module["implemented"] for module in modules)

    agent = next(m for m in modules if m["name"] == "agent_security")
    assert agent["check_count"] == 4


def test_builtin_targets_listed(client: TestClient) -> None:
    targets = client.get("/api/targets").json()
    ids = {target["id"] for target in targets}

    expected = {
        "demo-travel-agent",
        "demo-secure-support",
        "demo-enterprise-rag",
        "demo-crm-assistant",
        "demo-dev-copilot",
    }
    assert expected <= ids
    assert all(
        target["api_key_env"] is None
        for target in targets
        if target["builtin"]
    )


def test_create_target_validates_url(client: TestClient) -> None:
    response = client.post(
        "/api/targets",
        json={
            "name": "internal",
            "base_url": "https://169.254.169.254/v1",
            "model": "m",
        },
    )

    assert response.status_code == 400
    assert "rejected" in response.json()["detail"].lower()


def test_create_and_delete_target(client: TestClient) -> None:
    response = client.post(
        "/api/targets",
        json={
            "name": "staging",
            "base_url": "https://api.example.com/v1",
            "model": "test-model",
            "api_key_env": "STAGING_KEY",
        },
    )

    assert response.status_code == 201
    target_id = response.json()["id"]

    listed = client.get("/api/targets").json()
    stored = next(t for t in listed if t["id"] == target_id)
    assert stored["allow_network"] is False
    assert "api_key" not in stored  # only the env-var NAME is ever stored
    assert stored["api_key_env"] == "STAGING_KEY"

    assert client.delete(f"/api/targets/{target_id}").status_code == 204
    assert client.delete(f"/api/targets/{target_id}").status_code == 404


def test_network_assessment_requires_double_authorization(
    client: TestClient,
) -> None:
    created = client.post(
        "/api/targets",
        json={
            "name": "api-target",
            "base_url": "https://api.example.com/v1",
            "model": "test-model",
            "allow_network": False,
        },
    )
    target_id = created.json()["id"]

    response = client.post(
        "/api/assessments",
        json={"target_id": str(target_id), "allow_network": True},
    )

    assert response.status_code == 400
    assert "authoriz" in response.json()["detail"].lower()


def test_mock_assessment_end_to_end(client: TestClient) -> None:
    assessment_id = _run_mock_assessment(client)

    detail = client.get(f"/api/assessments/{assessment_id}").json()
    assert detail["report"]["assessment_id"] == assessment_id
    assert detail["report"]["synthetic_target"] is True
    assert detail["report"]["summary"]["findings_total"] > 0

    findings = client.get(
        f"/api/assessments/{assessment_id}/findings"
    ).json()
    assert findings
    assert all(f["validation_status"] == "pending_review" for f in findings)


def test_hardened_mock_produces_no_findings(client: TestClient) -> None:
    assessment_id = _run_mock_assessment(client, target="demo-secure-support")

    findings = client.get(
        f"/api/assessments/{assessment_id}/findings"
    ).json()
    assert findings == []


def test_findings_filters(client: TestClient) -> None:
    _run_mock_assessment(client)

    critical = client.get("/api/findings", params={"severity": "critical"}).json()
    assert critical
    assert all(f["severity"] == "critical" for f in critical)

    searched = client.get(
        "/api/findings", params={"search": "NT-TA"}
    ).json()
    assert searched
    assert all("NT-TA" in f["check_id"] for f in searched)


def test_finding_review_flow(client: TestClient) -> None:
    assessment_id = _run_mock_assessment(client)
    finding = client.get("/api/findings").json()[0]
    finding_id = finding["finding_id"]

    updated = client.patch(
        f"/api/findings/{finding_id}/review",
        json={"validation_status": "confirmed", "note": "Reproduced manually."},
    ).json()

    assert updated["validation_status"] == "confirmed"
    assert updated["review_note"] == "Reproduced manually."

    # Review state is reflected in the downloadable report.
    report = client.get(
        f"/api/assessments/{assessment_id}/report",
        params={"format": "json"},
    ).json()
    patched = next(
        f for f in report["findings"] if f["finding_id"] == finding_id
    )
    assert patched["validation_status"] == "confirmed"

    invalid = client.patch(
        f"/api/findings/{finding_id}/review",
        json={"validation_status": "definitely-real"},
    )
    assert invalid.status_code == 400


def test_markdown_report_download(client: TestClient) -> None:
    assessment_id = _run_mock_assessment(client)

    response = client.get(
        f"/api/assessments/{assessment_id}/report",
        params={"format": "markdown"},
    )

    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert "## Findings" in response.text


def test_dashboard_endpoints(client: TestClient) -> None:
    empty = client.get("/api/dashboard/summary").json()
    assert empty["assessments_total"] == 0
    assert empty["findings_total"] == 0

    _run_mock_assessment(client)
    _run_mock_assessment(client, target="demo-secure-support", profile="quick")

    summary = client.get("/api/dashboard/summary").json()
    assert summary["assessments_total"] == 2
    assert summary["findings_total"] > 0
    assert summary["recent_assessments"]

    analytics = client.get("/api/dashboard/analytics").json()
    assert len(analytics["history"]) == 2
    assert analytics["module_coverage"]["baseline"] == 2
    assert analytics["findings_by_category"]


def test_unknown_module_rejected(client: TestClient) -> None:
    response = client.post(
        "/api/assessments",
        json={"target_id": "demo-secure-support", "modules": ["bogus"]},
    )

    assert response.status_code == 400


def test_token_auth_when_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NULLTRACE_API_TOKEN", "local-secret")
    client = TestClient(create_app(db_path=tmp_path / "auth.db"))

    assert client.get("/api/modules").status_code == 401
    assert (
        client.get(
            "/api/modules", headers={"X-API-Token": "local-secret"}
        ).status_code
        == 200
    )
    # Health stays open for liveness checks.
    assert client.get("/api/health").status_code == 200


def test_bootstrap_admin_creates_first_admin_from_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NULLTRACE_BOOTSTRAP_ADMIN_USERNAME", "root")
    monkeypatch.setenv("NULLTRACE_BOOTSTRAP_ADMIN_PASSWORD", "supersecret1")
    client = TestClient(create_app(db_path=tmp_path / "boot.db"))

    # Setup mode is closed at startup; no implicit-admin window remains.
    status = client.get("/api/auth/status").json()
    assert status["setup_mode"] is False

    # The bootstrapped admin can log in with the provided credentials.
    login = client.post(
        "/api/auth/login",
        json={"username": "root", "password": "supersecret1"},
    )
    assert login.status_code == 200
    assert login.json()["role"] == "admin"


def test_bootstrap_admin_noop_without_env(tmp_path: Path) -> None:
    # No bootstrap env vars -> behavior is unchanged (open setup mode).
    client = TestClient(create_app(db_path=tmp_path / "nobob.db"))
    assert client.get("/api/auth/status").json()["setup_mode"] is True


def test_bootstrap_admin_does_not_overwrite_existing_users(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "existing.db"
    # Seed an existing admin the normal way.
    first = TestClient(create_app(db_path=db))
    first.post(
        "/api/users",
        json={"username": "owner", "password": "ownerpass1", "role": "admin"},
    )

    # A later start with bootstrap env vars must NOT create or overwrite.
    monkeypatch.setenv("NULLTRACE_BOOTSTRAP_ADMIN_USERNAME", "root")
    monkeypatch.setenv("NULLTRACE_BOOTSTRAP_ADMIN_PASSWORD", "supersecret1")
    second = TestClient(create_app(db_path=db))

    # The original user still works; the bootstrap identity was never added.
    assert (
        second.post(
            "/api/auth/login",
            json={"username": "owner", "password": "ownerpass1"},
        ).status_code
        == 200
    )
    assert (
        second.post(
            "/api/auth/login",
            json={"username": "root", "password": "supersecret1"},
        ).status_code
        == 401
    )


# ---------------------------------------------------------------------------
# Assessment history deletion
# ---------------------------------------------------------------------------


def test_delete_single_assessment_removes_findings_and_report(
    client: TestClient,
) -> None:
    assessment_id = _run_mock_assessment(client)
    keep_id = _run_mock_assessment(client, target="demo-crm-assistant")

    assert client.get("/api/findings", params={"assessment_id": assessment_id}).json()

    response = client.delete(f"/api/assessments/{assessment_id}")
    assert response.status_code == 204

    # Assessment, its findings, and its report are gone.
    assert client.get(f"/api/assessments/{assessment_id}").status_code == 404
    assert (
        client.get(
            "/api/findings", params={"assessment_id": assessment_id}
        ).json()
        == []
    )
    assert (
        client.get(f"/api/assessments/{assessment_id}/report").status_code
        == 404
    )

    # Unrelated assessments and their findings are preserved.
    assert client.get(f"/api/assessments/{keep_id}").status_code == 200
    assert client.get(
        "/api/findings", params={"assessment_id": keep_id}
    ).json()


def test_delete_single_assessment_unknown_id_is_404(client: TestClient) -> None:
    assert client.delete("/api/assessments/NTA-does-not-exist").status_code == 404


def test_bulk_delete_only_selected_ids(client: TestClient) -> None:
    ids = [
        _run_mock_assessment(client),
        _run_mock_assessment(client, target="demo-enterprise-rag"),
        _run_mock_assessment(client, target="demo-secure-support"),
    ]
    to_delete = ids[:2]

    response = client.post(
        "/api/assessments/delete-batch", json={"ids": to_delete}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["deleted_count"] == 2
    assert sorted(data["deleted"]) == sorted(to_delete)
    assert data["not_found"] == []
    assert data["skipped_running"] == []

    remaining = {a["id"] for a in client.get("/api/assessments").json()}
    assert remaining == {ids[2]}


def test_bulk_delete_reports_unknown_ids_without_failing_batch(
    client: TestClient,
) -> None:
    real_id = _run_mock_assessment(client)

    response = client.post(
        "/api/assessments/delete-batch",
        json={"ids": [real_id, "NTA-missing-01", real_id]},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["deleted"] == [real_id]  # duplicates collapsed
    assert data["deleted_count"] == 1
    assert data["not_found"] == ["NTA-missing-01"]


def test_bulk_delete_validates_payload(client: TestClient) -> None:
    assert (
        client.post("/api/assessments/delete-batch", json={"ids": []}).status_code
        == 422
    )
    too_many = [f"NTA-{i:03d}" for i in range(101)]
    assert (
        client.post(
            "/api/assessments/delete-batch", json={"ids": too_many}
        ).status_code
        == 422
    )


def test_delete_preserves_targets_and_configuration(client: TestClient) -> None:
    created = client.post(
        "/api/targets",
        json={
            "name": "kept-target",
            "base_url": "https://api.example.com/v1",
            "model": "test-model",
        },
    )
    target_id = created.json()["id"]
    assessment_id = _run_mock_assessment(client)

    assert client.delete(f"/api/assessments/{assessment_id}").status_code == 204

    ids = {t["id"] for t in client.get("/api/targets").json()}
    assert target_id in ids  # configured target untouched
    assert "demo-travel-agent" in ids  # built-in targets untouched
    assert len(client.get("/api/modules").json()) == 9


def test_dashboard_statistics_refresh_after_deletion(client: TestClient) -> None:
    first = _run_mock_assessment(client)
    second = _run_mock_assessment(client, target="demo-crm-assistant")

    before = client.get("/api/dashboard/summary").json()
    assert before["assessments_total"] == 2
    assert before["findings_total"] > 2

    assert client.delete(f"/api/assessments/{first}").status_code == 204

    after = client.get("/api/dashboard/summary").json()
    assert after["assessments_total"] == 1
    assert after["findings_total"] == 2  # only the CRM run's findings remain
    assert after["recent_assessments"][0]["id"] == second

    analytics = client.get("/api/dashboard/analytics").json()
    assert [point["assessment_id"] for point in analytics["history"]] == [second]


def test_running_assessment_cannot_be_deleted(tmp_path: Path) -> None:
    from nulltrace.web.service import AssessmentService

    service = AssessmentService(tmp_path / "running.db")
    service.db.create_assessment(
        "NTA-running-01",
        target_ref="target:1",
        target_name="t",
        mode="api",
        profile="quick",
        modules=["baseline"],
        status="running",
    )

    result = service.delete_assessments(["NTA-running-01"])

    assert result["deleted_count"] == 0
    assert result["skipped_running"] == ["NTA-running-01"]
    assert service.db.get_assessment("NTA-running-01") is not None
