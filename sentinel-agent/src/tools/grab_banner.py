"""grab_banner — raw TCP banner grab (agent-spec.md section 2).

Connects, optionally sends a short payload, and reads up to 1KB of banner.
The banner is sanitized to printable characters before it can enter any
transcript.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from src.scope import Scope
from src.tools.base import BANNER_LIMIT, EXCERPT_LIMIT, Tool, ToolResult, sanitize

HARD_TIMEOUT = 5.0


async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
    """Connect to host:port, send payload, read and sanitize the banner."""
    host = str(args.get("host", ""))
    port = int(args.get("port", 0))
    scope.check(host)  # ScopeViolation propagates — never caught.
    payload = str(args.get("payload", "\r\n")).encode("utf-8", "replace")
    read_timeout = max(0.1, min(float(args.get("timeout", 3.0)), 4.5))

    async def _probe() -> bytes:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            if payload:
                writer.write(payload)
                await writer.drain()
            try:
                return await asyncio.wait_for(
                    reader.read(BANNER_LIMIT), timeout=read_timeout
                )
            except (asyncio.TimeoutError, TimeoutError):
                return b""  # service stayed silent: empty banner, not an error
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    try:
        raw = await asyncio.wait_for(_probe(), timeout=HARD_TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — spec: any network error -> failure
        return ToolResult.failure(str(exc) or type(exc).__name__)

    banner = sanitize(raw.decode("utf-8", "replace"), BANNER_LIMIT)
    data: dict[str, Any] = {"banner": banner}
    note = "banner" if banner else f"no banner within {read_timeout:.1f}s"
    excerpt = sanitize(f"{host}:{port} {note}: {banner!r}", EXCERPT_LIMIT)
    return ToolResult(ok=True, data=data, excerpt=excerpt)


TOOL = Tool(
    name="grab_banner",
    description="Raw TCP connect, send payload, read up to 1KB of banner.",
    args_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "port": {"type": "integer"},
            "payload": {"type": "string", "default": "\r\n"},
            "timeout": {"type": "number", "default": 3.0},
        },
        "required": ["host", "port"],
    },
    run=run,
)
