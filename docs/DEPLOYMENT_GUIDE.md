# Deployment Guide

NullTrace AI is designed for **local / trusted single-tenant**
deployment. Do not expose it to the public internet without the
hardening in `SECURITY_REVIEW.md` and an independent review.

## 1. Local development

Backend:

```bash
uv sync --extra dev
uv run nulltrace serve
```

Frontend (dev server with hot reload, proxies /api to :8787):

```bash
cd frontend && npm install && npm run dev   # http://localhost:5173
```

Or build the dashboard and let the backend serve it same-origin:

```bash
cd frontend && npm run build && cd ..
uv run nulltrace serve
# http://127.0.0.1:8787  (landing /, dashboard /app, API docs /api/docs)
```

## 2. First-run: enable authentication

Until the first user exists the dashboard is in **open setup mode**
(local bootstrap only). Create the first admin, which closes setup mode:

```bash
uv run nulltrace user-add --username admin --role admin
# password is prompted securely; or pass --password for automation
```

Roles: `viewer` < `analyst` < `researcher` < `admin`.
- viewer: read dashboards/findings/reports
- analyst: + review findings
- researcher: + run/delete assessments, manage targets
- admin: + manage users, view audit log

Admins create further users from the API (`POST /api/users`) or the CLI.

## 3. Docker (local/trusted)

```bash
cd frontend && npm ci && npm run build && cd ..   # build dashboard first
docker build -t nulltrace-ai .
docker volume create nt-data
docker run -d --name nulltrace -p 127.0.0.1:8787:8787 \
  -e NULLTRACE_DB_PATH=/data/nulltrace.db \
  -v nt-data:/data nulltrace-ai
# bootstrap the first admin inside the container:
docker exec -e NULLTRACE_DB_PATH=/data/nulltrace.db nulltrace \
  nulltrace user-add --username admin --role admin --password 'CHANGE-ME-long'
```

The image runs as a non-root user and persists its SQLite DB in the
`/data` volume. Publish only to `127.0.0.1` (or a private network behind
an authenticating reverse proxy).

## 4. Environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `NULLTRACE_DB_PATH` | SQLite database path | `data/nulltrace.db` |
| `NULLTRACE_FRONTEND_DIST` | Built dashboard directory | `frontend/dist` |
| `NULLTRACE_API_TOKEN` | Optional shared-secret guard for the open setup window (`X-API-Token`) | unset |
| `OPENAI_API_KEY` (or your target's env var) | Read by the backend at assessment time for API targets; never stored | unset |

Copy `.env.example` → `.env` (never commit `.env`). Target API keys live
only in the backend process environment and are referenced by env-var
name per target.

## 5. Production considerations (required before non-local use)

Implement, per `SECURITY_REVIEW.md` and `RELEASE_LEVELS.md`:
- Terminate TLS at an authenticating reverse proxy; restrict CORS to the
  real origin.
- Add rate limiting (login + API) and a restrictive CSP.
- Migrate persistence to PostgreSQL for multi-user load (the `Database`
  layer is intentionally thin; the schema is standard SQL). Back up the
  database file/volume regularly; `sqlite3 nulltrace.db ".backup out.db"`
  for SQLite.
- Obtain an independent security review.

## 6. Backup & restore (SQLite)

```bash
# backup (consistent, online)
sqlite3 data/nulltrace.db ".backup data/backup-$(date +%F).db"
# restore
cp data/backup-YYYY-MM-DD.db data/nulltrace.db
```

Reports written to `reports/` are plain JSON/Markdown artifacts and can
be archived directly.

## 7. CI/CD

`.github/workflows/ci.yml` runs: ruff, strict mypy, the full pytest
suite (incl. security-regression and auth tests), an internal-benchmark
gate (fails on any false positive/negative), frontend type-check +
production build, and a Docker build + container health smoke test.
