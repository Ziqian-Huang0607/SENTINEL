"""Tool base types (agent-spec.md section 2).

A Tool wraps an async executor with a JSON-schema arg contract. ToolResult
carries the full structured data plus a compacted, sanitized `excerpt`
(<=600 chars) — the excerpt is the ONLY part of raw network output that ever
enters an LLM transcript.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from src.scope import Scope

EXCERPT_LIMIT = 600
BODY_LIMIT = 2048
BANNER_LIMIT = 1024

# Strip control chars (keep tab/newline) so raw bytes can't inject terminal
# escapes or prompt junk into transcripts.
_CONTROL_RE = re.compile(r"[^\x09\x0a\x20-\x7e]")


def sanitize(text: str, limit: int) -> str:
    """Remove non-printable characters and truncate to ``limit`` chars."""
    cleaned = _CONTROL_RE.sub(".", text)
    return cleaned[:limit]


@dataclass
class ToolResult:
    """The outcome of one tool execution."""

    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    excerpt: str = ""
    error: str = ""

    @classmethod
    def failure(cls, error: str) -> ToolResult:
        return cls(ok=False, error=error, excerpt=f"error: {error}")


@dataclass
class Tool:
    """One benign probe primitive the agent may call."""

    name: str
    description: str  # one line, shown in the tool menu
    args_schema: dict[str, Any]  # JSON Schema for args
    run: Callable[[dict[str, Any], Scope], Awaitable[ToolResult]]

    def menu_line(self) -> str:
        """Compact menu entry for the LLM prompt."""
        props = ",".join(self.args_schema.get("properties", {}).keys())
        return f"- {self.name}({props}): {self.description}"
