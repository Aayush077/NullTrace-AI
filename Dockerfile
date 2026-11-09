# NullTrace AI — container image (multi-stage).
#
# Stage 1 builds the React/Vite dashboard from source, so the built
# `frontend/dist` never has to be committed to Git. Stage 2 installs the
# Python package and copies the built dashboard into the path the app
# serves from (NULLTRACE_FRONTEND_DIST). Suitable for local/trusted use
# and for PaaS (e.g. Render) which injects $PORT.
#
#   docker build -t nulltrace-ai .
#   docker run --rm -p 8787:8787 -v nt:/data nulltrace-ai
#
# This image has NO authentication by default (setup mode). Create the
# first admin before exposing it beyond localhost:
#   docker run --rm -v nt:/data nulltrace-ai \
#     nulltrace user-add --username admin --role admin --db /data/nulltrace.db
# See docs/DEPLOYMENT_GUIDE.md.

# ---------------------------------------------------------------------------
# Stage 1 — build the dashboard (production Vite build -> frontend/dist)
# ---------------------------------------------------------------------------
FROM node:20-bookworm-slim AS frontend-build

WORKDIR /app/frontend

# Install dependencies from the lockfile first for better layer caching.
# `npm ci` needs devDependencies (tsc, vite, plugins) to run the build,
# so do not set NODE_ENV=production here.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

# Copy the rest of the frontend source and produce the production bundle
# at /app/frontend/dist (index.html + assets/). node_modules is excluded
# by .dockerignore, so the container's freshly installed deps are used.
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2 — Python runtime
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NULLTRACE_DB_PATH=/data/nulltrace.db \
    NULLTRACE_FRONTEND_DIST=/app/frontend/dist \
    PORT=8787

WORKDIR /app

# Install the package and its runtime dependencies from project metadata.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Built dashboard from the Node stage (no committed frontend/dist needed).
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

# Run as a non-root user; /data is a writable volume for the SQLite DB.
RUN useradd --create-home --uid 10001 nulltrace \
    && mkdir -p /data \
    && chown -R nulltrace:nulltrace /data /app
USER nulltrace
VOLUME ["/data"]

# $PORT is provided by the platform (Render) at runtime; 8787 locally.
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import os,urllib.request,sys; p=os.getenv('PORT','8787'); sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/api/health' % p).status==200 else 1)"

# Shell form so ${PORT} expands; bind to 0.0.0.0 for external reachability.
CMD ["sh", "-c", "exec uvicorn nulltrace.web.main:app --host 0.0.0.0 --port ${PORT:-8787}"]
