# Web platform guide

The web platform is a FastAPI backend plus a React dashboard around the
same assessment engine the CLI uses. **It is designed for local use.**

## Install & run

Backend (serves the API and, when built, the dashboard):

```bash
uv sync --extra dev          # or: pip install -e ".[dev]"
uv run nulltrace serve
```

Frontend (Node 20+):

```bash
cd frontend
npm install
npm run build                # output in frontend/dist, served by the backend
```

Open http://127.0.0.1:8787 — the landing page is `/`, the dashboard is
`/app`, interactive API docs are `/api/docs`.

Frontend development with hot reload (proxies `/api` to port 8787):

```bash
npm run dev                  # http://localhost:5173
```

## Architecture

```text
React SPA (frontend/)  ──fetch──▶  FastAPI (nulltrace.web.api)
                                      │
                                      ▼
                        AssessmentService (nulltrace.web.service)
                          │  runs assessments via core.runner (no
                          │  duplicated business logic)
                          ▼
                        SQLite (nulltrace.web.db — targets,
                        assessments, findings; WAL mode)
```

- Mock assessments run synchronously (instant, offline).
- API-mode assessments run in a background thread under their request
  budget; the UI polls the assessment until it leaves `running`.
- The stored report JSON is the canonical artifact; human review patches
  both the findings table and the stored report, so downloads always
  reflect review state.

## Security posture

- **Local-only by default.** Bind to 127.0.0.1. There is no multi-user
  authentication, so do not expose the port publicly. Setting
  `NULLTRACE_API_TOKEN` adds a shared-token header check
  (`X-API-Token`) as a minimal guard for shared machines.
- **API keys:** targets store only the *name* of the environment
  variable holding the key. The key is read by the backend process at
  assessment time, registered with the redaction engine, and never
  stored, logged, returned by any endpoint, or sent to the browser.
- **Network authorization is double-gated:** a target must be marked
  network-authorized at configuration time AND each run must set
  `allow_network`. Configuring a target never triggers a request.
- **CORS** allows only localhost Vite dev origins; the production build
  is served same-origin.
- **Downloads** are generated from database content; no user-supplied
  file paths are ever read. The SPA static file handler resolves paths
  and refuses anything outside the dist directory.
- **Input validation:** pydantic schemas bound every field; base URLs
  go through the same strict `validate_base_url` as the CLI (private,
  reserved, link-local addresses rejected; validation is offline).
- **Error disclosure:** assessment failures are stored redacted;
  stack traces are never returned to the client.

## Production deployment considerations (not yet supported)

Before any non-local deployment the following would be required and is
currently **not implemented**: real user authentication and sessions,
per-user authorization of targets/reports, CSRF protection for
cookie-based auth, TLS termination, rate limiting, and an audit log.
Until then, treat the dashboard as a single-operator local tool.

## Environment variables

See `.env.example`. Summary: `NULLTRACE_DB_PATH`,
`NULLTRACE_FRONTEND_DIST`, `NULLTRACE_API_TOKEN`, plus whichever API-key
variables your targets name.
