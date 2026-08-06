"""dns_reverse — PTR lookup for an in-scope host (agent-spec.md section 2).

Runs socket.gethostbyaddr in a thread with a hard 5s cap. A missing PTR
record is a normal empty result (ok=True), not a failure.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from src.scope import Scope
from src.tools.base import EXCERPT_LIMIT, Tool, ToolResult, sanitize

HARD_TIMEOUT = 5.0


async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
    """Reverse-resolve host to a list of hostnames (possibly empty)."""
    host = str(args.get("host", ""))
    scope.check(host)  # ScopeViolation propagates — never caught.
    try:
        primary, aliases, _addrs = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, host), timeout=HARD_TIMEOUT
        )
    except (TimeoutError, asyncio.TimeoutError):
        return ToolResult.failure(f"dns_reverse timed out after {HARD_TIMEOUT}s")
    except (socket.herror, socket.gaierror, OSError) as exc:
        # No PTR record / resolver refused: empty list, still ok.
        data: dict[str, Any] = {
            "hostnames": [],
            "note": sanitize(f"no PTR record: {exc}", 300),
        }
        excerpt = sanitize(f"PTR {host}: no hostnames ({exc})", EXCERPT_LIMIT)
        return ToolResult(ok=True, data=data, excerpt=excerpt)

    hostnames = list(dict.fromkeys([primary, *aliases]))
    hostnames = [sanitize(name, 300) for name in hostnames]
    data = {"hostnames": hostnames}
    excerpt = sanitize(
        f"PTR {host}: {', '.join(hostnames) if hostnames else 'no hostnames'}",
        EXCERPT_LIMIT,
    )
    return ToolResult(ok=True, data=data, excerpt=excerpt)


TOOL = Tool(
    name="dns_reverse",
    description="PTR reverse-DNS lookup for one in-scope host.",
    args_schema={
        "type": "object",
        "properties": {"host": {"type": "string"}},
        "required": ["host"],
    },
    run=run,
)
