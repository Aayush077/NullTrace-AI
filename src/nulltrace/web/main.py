"""ASGI entry point: ``uvicorn nulltrace.web.main:app``.

Run locally (never expose publicly without authentication):

    uv run uvicorn nulltrace.web.main:app --host 127.0.0.1 --port 8787
"""

from nulltrace.web.api import create_app

app = create_app()
