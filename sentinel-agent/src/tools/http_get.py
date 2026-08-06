"""http_get — one benign HTTP GET per call (agent-spec.md section 2).

Fetches a single path and returns status, allowlisted headers, page title,
redirect target and a sanitized <=2KB body excerpt. No redirects are
followed, no credentials are sent.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from src.scope import Scope
from src.tools.base import BODY_LIMIT, EXCERPT_LIMIT, Tool, ToolResult, sanitize

HARD_TIMEOUT = 5.0
_HEADER_ALLOWLIST = ("server", "www-authenticate", "location", "content-type")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
    """Perform one GET against host:port/path and summarize the response."""
    host = str(args.get("host", ""))
    port = int(args.get("port", 0))
    scope.check(host)  # ScopeViolation propagates — never caught.
    path = str(args.get("path") or "/")
    if not path.startswith("/"):
        path = "/" + path
    use_tls = bool(args.get("tls", False))
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}{path}"
    try:
        # verify=False: internal tool probing self-signed device UIs.
        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=HARD_TIMEOUT
        ) as client:
            resp = await asyncio.wait_for(client.get(url), timeout=HARD_TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — spec: any network error -> failure
        return ToolResult.failure(str(exc) or type(exc).__name__)

    raw_headers = {k.lower(): v for k, v in resp.headers.items()}
    headers: dict[str, Any] = {
        name: sanitize(raw_headers[name], 200)
        for name in _HEADER_ALLOWLIST
        if name in raw_headers
    }
    headers["set-cookie"] = "set-cookie" in raw_headers

    body_text = resp.text
    body_excerpt = sanitize(body_text, BODY_LIMIT)
    title_match = _TITLE_RE.search(body_text)
    title = (
        sanitize(" ".join(title_match.group(1).split()), 200) if title_match else ""
    )
    redirect_location = (
        headers.get("location") if 300 <= resp.status_code < 400 else None
    )
    data: dict[str, Any] = {
        "status": resp.status_code,
        "server": headers.get("server", ""),
        "title": title,
        "headers": headers,
        "redirect_location": redirect_location,
        "body_excerpt": body_excerpt,
    }
    excerpt = sanitize(
        f"GET {path} -> HTTP {resp.status_code} server={data['server']!r} "
        f"title={title!r} redirect={redirect_location!r} "
        f"body={body_excerpt[:300]!r}",
        EXCERPT_LIMIT,
    )
    return ToolResult(ok=True, data=data, excerpt=excerpt)


TOOL = Tool(
    name="http_get",
    description="Fetch one HTTP(S) path and summarize status/headers/title.",
    args_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "port": {"type": "integer"},
            "path": {"type": "string", "default": "/"},
            "tls": {"type": "boolean", "default": False},
        },
        "required": ["host", "port"],
    },
    run=run,
)
