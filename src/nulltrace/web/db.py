"""SQLite persistence for the web platform.

Design notes:

- stdlib ``sqlite3`` with one short-lived connection per operation (WAL
  mode) keeps the layer dependency-free and safe across the API's worker
  threads.
- API keys are **never** stored; targets hold only the *name* of the
  environment variable that supplies the key at assessment time.
- The stored report JSON is the canonical assessment artifact. Human
  review updates patch both the findings table and the stored report so
  downloads always reflect review state.
"""

import json
import sqlite3
from pathlib import Path
from typing import Any

from nulltrace.core.models import utc_now_iso

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    base_url TEXT NOT NULL,
    model TEXT NOT NULL,
    api_key_env TEXT NOT NULL,
    timeout REAL NOT NULL,
    max_requests INTEGER NOT NULL,
    allow_network INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    target_ref TEXT NOT NULL,
    target_name TEXT NOT NULL,
    mode TEXT NOT NULL,
    profile TEXT NOT NULL,
    modules TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    error TEXT NOT NULL DEFAULT '',
    report_json TEXT,
    provider_label TEXT NOT NULL DEFAULT '',
    model_label TEXT NOT NULL DEFAULT '',
    security_profile TEXT NOT NULL DEFAULT '',
    variant TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    check_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    title TEXT NOT NULL,
    validation_status TEXT NOT NULL,
    review_note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    data_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_assessment
    ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity
    ON findings(severity);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL DEFAULT 'ok'
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""


class Database:
    """Thin SQLite wrapper; one connection per operation."""

    _ASSESSMENT_METADATA_COLUMNS = (
        "provider_label",
        "model_label",
        "security_profile",
        "variant",
    )

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            # Lightweight migration for databases created before the
            # demo-lab metadata columns existed.
            existing = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(assessments)")
            }
            for column in self._ASSESSMENT_METADATA_COLUMNS:
                if column not in existing:
                    conn.execute(
                        f"ALTER TABLE assessments ADD COLUMN {column} "
                        "TEXT NOT NULL DEFAULT ''"
                    )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    # ------------------------------------------------------------------
    # Targets
    # ------------------------------------------------------------------

    def create_target(
        self,
        name: str,
        type_: str,
        base_url: str,
        model: str,
        api_key_env: str,
        timeout: float,
        max_requests: int,
        allow_network: bool,
    ) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO targets
                    (name, type, base_url, model, api_key_env, timeout,
                     max_requests, allow_network, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    type_,
                    base_url,
                    model,
                    api_key_env,
                    timeout,
                    max_requests,
                    1 if allow_network else 0,
                    utc_now_iso(),
                ),
            )
            row_id = cursor.lastrowid
            assert row_id is not None
            return row_id

    def list_targets(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM targets ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_target(self, target_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM targets WHERE id = ?", (target_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def delete_target(self, target_id: int) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM targets WHERE id = ?", (target_id,)
            )
            return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(
        self,
        assessment_id: str,
        target_ref: str,
        target_name: str,
        mode: str,
        profile: str,
        modules: list[str],
        status: str,
        provider_label: str = "",
        model_label: str = "",
        security_profile: str = "",
        variant: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO assessments
                    (id, target_ref, target_name, mode, profile, modules,
                     status, created_at, provider_label, model_label,
                     security_profile, variant)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    target_ref,
                    target_name,
                    mode,
                    profile,
                    json.dumps(modules),
                    status,
                    utc_now_iso(),
                    provider_label,
                    model_label,
                    security_profile,
                    variant,
                ),
            )

    def finish_assessment(
        self,
        assessment_id: str,
        status: str,
        report: dict[str, Any] | None,
        error: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE assessments
                SET status = ?, completed_at = ?, error = ?, report_json = ?
                WHERE id = ?
                """,
                (
                    status,
                    utc_now_iso(),
                    error,
                    json.dumps(report) if report is not None else None,
                    assessment_id,
                ),
            )

    def list_assessments(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, target_ref, target_name, mode, profile, modules,
                       status, created_at, completed_at, error,
                       provider_label, model_label, security_profile, variant
                FROM assessments ORDER BY created_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def get_assessment_statuses(self, ids: list[str]) -> dict[str, str]:
        """Return {assessment_id: status} for the ids that exist."""

        if not ids:
            return {}

        placeholders = ",".join("?" for _ in ids)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT id, status FROM assessments WHERE id IN ({placeholders})",
                ids,
            ).fetchall()
        return {str(row["id"]): str(row["status"]) for row in rows}

    def delete_assessments(self, ids: list[str]) -> int:
        """Delete assessments by id; findings cascade via foreign key.

        Returns the number of assessment rows deleted. Targets and other
        tables are never touched.
        """

        if not ids:
            return 0

        placeholders = ",".join("?" for _ in ids)
        with self._connect() as conn:
            cursor = conn.execute(
                f"DELETE FROM assessments WHERE id IN ({placeholders})",
                ids,
            )
            return cursor.rowcount

    def update_report_json(
        self, assessment_id: str, report: dict[str, Any]
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE assessments SET report_json = ? WHERE id = ?",
                (json.dumps(report), assessment_id),
            )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def insert_findings(
        self, assessment_id: str, findings: list[dict[str, Any]]
    ) -> None:
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO findings
                    (finding_id, assessment_id, check_id, category, severity,
                     confidence, title, validation_status, created_at,
                     data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        finding["finding_id"],
                        assessment_id,
                        finding["check_id"],
                        finding["category"],
                        finding["severity"],
                        finding["confidence"],
                        finding["title"],
                        finding["validation_status"],
                        finding["timestamp"],
                        json.dumps(finding),
                    )
                    for finding in findings
                ],
            )

    def query_findings(
        self,
        severity: str | None = None,
        confidence: str | None = None,
        category: str | None = None,
        validation_status: str | None = None,
        assessment_id: str | None = None,
        search: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []

        for column, value in (
            ("severity", severity),
            ("confidence", confidence),
            ("category", category),
            ("validation_status", validation_status),
            ("assessment_id", assessment_id),
        ):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)

        if search:
            clauses.append("(title LIKE ? OR finding_id LIKE ? OR check_id LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM findings {where}
                ORDER BY created_at DESC LIMIT ?
                """,
                params,
            ).fetchall()
        return [dict(row) for row in rows]

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def update_finding_review(
        self, finding_id: str, validation_status: str, review_note: str
    ) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE findings
                SET validation_status = ?,
                    review_note = ?,
                    data_json = json_set(
                        json_set(data_json, '$.validation_status', ?),
                        '$.review_note', ?
                    )
                WHERE finding_id = ?
                """,
                (
                    validation_status,
                    review_note,
                    validation_status,
                    review_note,
                    finding_id,
                ),
            )
            return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Dashboard aggregates
    # ------------------------------------------------------------------

    def count_assessments_by_status(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM assessments GROUP BY status"
            ).fetchall()
        return {str(row["status"]): int(row["n"]) for row in rows}

    # ------------------------------------------------------------------
    # Users, sessions, audit log
    # ------------------------------------------------------------------

    def count_users(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
        return int(row["n"])

    def create_user(
        self, username: str, password_hash: str, role: str
    ) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users (username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (username, password_hash, role, utc_now_iso()),
            )
            row_id = cursor.lastrowid
            assert row_id is not None
            return row_id

    def get_user_by_name(self, username: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()
        return dict(row) if row is not None else None

    def get_user(self, user_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def list_users(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, username, role, created_at, disabled FROM users "
                "ORDER BY created_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def set_user_disabled(self, user_id: int, disabled: bool) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE users SET disabled = ? WHERE id = ?",
                (1 if disabled else 0, user_id),
            )
            return cursor.rowcount > 0

    def create_session(
        self, token_hash: str, user_id: int, expires_at: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (token_hash, user_id, utc_now_iso(), expires_at),
            )

    def get_session(self, token_hash: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)
            ).fetchone()
        return dict(row) if row is not None else None

    def delete_session(self, token_hash: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_hash,)
            )
            return cursor.rowcount > 0

    def purge_expired_sessions(self, now_iso: str) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE expires_at <= ?", (now_iso,)
            )
            return cursor.rowcount

    def append_audit(
        self, actor: str, action: str, detail: str, outcome: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (ts, actor, action, detail, outcome)
                VALUES (?, ?, ?, ?, ?)
                """,
                (utc_now_iso(), actor, action, detail, outcome),
            )

    def list_audit(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ts, actor, action, detail, outcome FROM audit_log "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def count_findings_by(self, column: str) -> dict[str, int]:
        if column not in {"severity", "confidence", "category", "validation_status"}:
            raise ValueError(f"Unsupported aggregate column: {column}")

        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {column} AS k, COUNT(*) AS n FROM findings GROUP BY {column}"
            ).fetchall()
        return {str(row["k"]): int(row["n"]) for row in rows}
