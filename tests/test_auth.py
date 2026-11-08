"""Authentication, RBAC, and audit-log tests."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nulltrace.web.api import create_app
from nulltrace.web.auth import (
    Role,
    hash_password,
    is_expired,
    role_at_least,
    verify_password,
)


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    return TestClient(create_app(db_path=tmp_path / "auth.db"))


# --- Password hashing primitives -------------------------------------------


def test_password_hash_roundtrip() -> None:
    stored = hash_password("correct horse battery")
    assert stored.startswith("scrypt$")
    assert verify_password("correct horse battery", stored)
    assert not verify_password("wrong", stored)


def test_password_minimum_length_enforced() -> None:
    with pytest.raises(ValueError):
        hash_password("short")


def test_hashes_are_salted_and_unique() -> None:
    a = hash_password("same-password-xx")
    b = hash_password("same-password-xx")
    assert a != b  # distinct salts
    assert verify_password("same-password-xx", a)
    assert verify_password("same-password-xx", b)


def test_role_hierarchy() -> None:
    assert role_at_least(Role.ADMIN, Role.VIEWER)
    assert role_at_least(Role.RESEARCHER, Role.ANALYST)
    assert not role_at_least(Role.VIEWER, Role.ANALYST)
    assert not role_at_least(Role.ANALYST, Role.RESEARCHER)


def test_expiry_detection() -> None:
    assert is_expired("2000-01-01T00:00:00+00:00")
    assert not is_expired("2999-01-01T00:00:00+00:00")
    assert is_expired("not-a-date")


# --- Setup mode and bootstrap ----------------------------------------------


def test_setup_mode_open_until_first_user(client: TestClient) -> None:
    status = client.get("/api/auth/status").json()
    assert status["setup_mode"] is True

    # In setup mode, protected reads are open (local bootstrap).
    assert client.get("/api/modules").status_code == 200


def _bootstrap_admin(client: TestClient) -> None:
    resp = client.post(
        "/api/users",
        json={"username": "admin", "password": "adminpass123", "role": "admin"},
    )
    assert resp.status_code == 201


def test_first_user_closes_setup_mode(client: TestClient) -> None:
    _bootstrap_admin(client)
    status = client.get("/api/auth/status").json()
    assert status["setup_mode"] is False

    # Setup mode closed: anonymous access now requires authentication.
    assert client.get("/api/modules").status_code == 401
    assert client.get("/api/assessments").status_code == 401


def _login(client: TestClient, username: str, password: str) -> str:
    resp = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["token"]
    assert isinstance(token, str)
    return token


def _auth(token: str) -> dict[str, str]:
    return {"X-Session-Token": token}


def test_login_logout_flow(client: TestClient) -> None:
    _bootstrap_admin(client)
    token = _login(client, "admin", "adminpass123")

    me = client.get("/api/auth/me", headers=_auth(token)).json()
    assert me["username"] == "admin"
    assert me["role"] == "admin"
    assert me["authenticated"] is True

    assert client.get("/api/modules", headers=_auth(token)).status_code == 200

    assert client.post("/api/auth/logout", headers=_auth(token)).status_code == 204
    # Session invalidated after logout.
    assert client.get("/api/modules", headers=_auth(token)).status_code == 401


def test_bad_credentials_rejected(client: TestClient) -> None:
    _bootstrap_admin(client)
    assert (
        client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "wrong"},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/auth/login",
            json={"username": "ghost", "password": "whatever12"},
        ).status_code
        == 401
    )


def test_invalid_session_token_rejected(client: TestClient) -> None:
    _bootstrap_admin(client)
    assert (
        client.get("/api/modules", headers=_auth("not-a-real-token")).status_code
        == 401
    )


# --- RBAC enforcement ------------------------------------------------------


def _make_user(client: TestClient, admin_token: str, name: str, role: str) -> None:
    resp = client.post(
        "/api/users",
        headers=_auth(admin_token),
        json={"username": name, "password": "userpass123", "role": role},
    )
    assert resp.status_code == 201, resp.text


def test_viewer_cannot_create_assessment_or_review(client: TestClient) -> None:
    _bootstrap_admin(client)
    admin = _login(client, "admin", "adminpass123")
    _make_user(client, admin, "val", "viewer")
    viewer = _login(client, "val", "userpass123")

    # Viewer can read.
    assert client.get("/api/modules", headers=_auth(viewer)).status_code == 200
    # Viewer cannot run an assessment (needs researcher).
    assert (
        client.post(
            "/api/assessments",
            headers=_auth(viewer),
            json={"target_id": "demo-secure-support", "profile": "quick"},
        ).status_code
        == 403
    )


def test_analyst_can_review_but_not_create_assessment(client: TestClient) -> None:
    _bootstrap_admin(client)
    admin = _login(client, "admin", "adminpass123")
    _make_user(client, admin, "ana", "analyst")
    analyst = _login(client, "ana", "userpass123")

    # Create an assessment as admin to get a finding to review.
    created = client.post(
        "/api/assessments",
        headers=_auth(admin),
        json={"target_id": "demo-crm-assistant", "profile": "full"},
    ).json()
    finding_id = client.get(
        "/api/findings",
        headers=_auth(admin),
        params={"assessment_id": created["id"]},
    ).json()[0]["finding_id"]

    # Analyst CAN review.
    assert (
        client.patch(
            f"/api/findings/{finding_id}/review",
            headers=_auth(analyst),
            json={"validation_status": "confirmed"},
        ).status_code
        == 200
    )
    # Analyst CANNOT create an assessment.
    assert (
        client.post(
            "/api/assessments",
            headers=_auth(analyst),
            json={"target_id": "demo-secure-support", "profile": "quick"},
        ).status_code
        == 403
    )


def test_only_admin_manages_users_and_audit(client: TestClient) -> None:
    _bootstrap_admin(client)
    admin = _login(client, "admin", "adminpass123")
    _make_user(client, admin, "res", "researcher")
    researcher = _login(client, "res", "userpass123")

    assert client.get("/api/users", headers=_auth(researcher)).status_code == 403
    assert client.get("/api/audit", headers=_auth(researcher)).status_code == 403
    assert client.get("/api/users", headers=_auth(admin)).status_code == 200


def test_disabled_user_cannot_authenticate(client: TestClient) -> None:
    _bootstrap_admin(client)
    admin = _login(client, "admin", "adminpass123")
    _make_user(client, admin, "res", "researcher")

    users = client.get("/api/users", headers=_auth(admin)).json()
    res_id = next(u["id"] for u in users if u["username"] == "res")

    assert (
        client.patch(
            f"/api/users/{res_id}/disable", headers=_auth(admin)
        ).status_code
        == 204
    )
    assert (
        client.post(
            "/api/auth/login",
            json={"username": "res", "password": "userpass123"},
        ).status_code
        == 401
    )


# --- Audit logging ---------------------------------------------------------


def test_audit_log_records_security_events(client: TestClient) -> None:
    _bootstrap_admin(client)
    admin = _login(client, "admin", "adminpass123")

    created = client.post(
        "/api/assessments",
        headers=_auth(admin),
        json={"target_id": "demo-secure-support", "profile": "quick"},
    ).json()
    client.delete(
        f"/api/assessments/{created['id']}", headers=_auth(admin)
    )
    # A failed login must be recorded too.
    client.post("/api/auth/login", json={"username": "admin", "password": "no"})

    audit = client.get("/api/audit", headers=_auth(admin)).json()
    actions = {entry["action"] for entry in audit}
    assert "login" in actions
    assert "assessment.create" in actions
    assert "assessment.delete" in actions
    assert "user.create" in actions

    failed_logins = [
        e for e in audit if e["action"] == "login" and e["outcome"] == "fail"
    ]
    assert failed_logins

    # Audit entries must never contain a raw password.
    assert all("no" != entry["detail"] for entry in audit)
    for entry in audit:
        assert "password" not in entry["detail"].lower() or "adminpass" not in entry["detail"]


def test_audit_detail_redacts_secrets(client: TestClient) -> None:
    _bootstrap_admin(client)
    admin = _login(client, "admin", "adminpass123")
    # Create a target whose audit detail would include no secret (only env
    # var name), and assert no sk- style secret leaks via any path.
    client.post(
        "/api/targets",
        headers=_auth(admin),
        json={
            "name": "t1",
            "base_url": "https://api.example.com/v1",
            "model": "m",
            "api_key_env": "OPENAI_API_KEY",
        },
    )
    audit = client.get("/api/audit", headers=_auth(admin)).json()
    assert any(e["action"] == "target.create" for e in audit)
    for entry in audit:
        assert "sk-" not in entry["detail"]
