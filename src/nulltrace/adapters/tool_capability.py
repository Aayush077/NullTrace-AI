"""Backwards-compatible re-export.

The capability interfaces moved to :mod:`nulltrace.adapters.capabilities`
when conversation and retrieval capabilities were added.  Import from there
in new code.
"""

from nulltrace.adapters.capabilities import ToolExecutionCapability

__all__ = ["ToolExecutionCapability"]
