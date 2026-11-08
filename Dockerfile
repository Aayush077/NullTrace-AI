# NullTrace AI — local/trusted deployment image.
#
# Serves the FastAPI backend and the pre-built dashboard on 127.0.0.1.
# Build the frontend first (cd frontend && npm ci && npm run build) so
# frontend/dist exists, then: docker build -t nulltrace-ai .
#
# This image has NO authentication by default (setup mode). Create the
# first admin before exposing it beyond localhost:
#   docker run --rm -v nt:/data nulltrace-ai \
#     nulltrace user-add --username admin --role admin --db /data/nulltrace.db
# See docs/DEPLOYMENT_GUIDE.md.

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NULLTRACE_DB_PATH=/data/nulltrace.db \
    NULLTRACE_FRONTEND_DIST=/app/frontend/dist

WORKDIR /app

# Install the package and web extras from the project metadata.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

# Ship the pre-built dashboard (fail the build if it is missing).
COPY frontend/dist ./frontend/dist

# Run as a non-root user; /data is a writable volume for the SQLite DB.
RUN useradd --create-home --uid 10001 nulltrace \
    && mkdir -p /data && chown -R nulltrace:nulltrace /data /app
USER nulltrace
VOLUME ["/data"]

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8787/api/health').status==200 else 1)"

CMD ["uvicorn", "nulltrace.web.main:app", "--host", "0.0.0.0", "--port", "8787"]
