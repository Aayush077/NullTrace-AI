"""Redaction of secrets in evidence, logs, and reports.

Two layers:

1. *Known secrets*: exact values registered for the assessment (for example
   the configured API key) are always replaced, wherever they appear.
2. *Pattern-based*: common credential formats are replaced even when the
   value is not known in advance, so accidentally echoed secrets never
   reach a report.

Redaction replaces, it never truncates evidence silently: the marker makes
clear that content was removed.
"""

import re
from collections.abc import Iterable

REDACTED = "[REDACTED]"

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    # OpenAI-style and generic "sk-" keys.
    re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}\b"),
    # Bearer tokens in headers or echoed text.
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}\b"),
    # key=value / key: value assignments for obviously secret names.
    re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|authorization)"
        r"(\s*[:=]\s*)([^\s\"']{6,})"
    ),
    # AWS access key IDs.
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # GitHub tokens.
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
)


def redact_text(text: str, known_secrets: Iterable[str] = ()) -> str:
    """Redact known secret values and common credential patterns."""

    result = text

    for secret in known_secrets:
        if secret and len(secret) >= 4:
            result = result.replace(secret, REDACTED)

    for pattern in _SECRET_PATTERNS[:2]:
        result = pattern.sub(REDACTED, result)

    result = _SECRET_PATTERNS[2].sub(rf"\1\2{REDACTED}", result)

    for pattern in _SECRET_PATTERNS[3:]:
        result = pattern.sub(REDACTED, result)

    return result
