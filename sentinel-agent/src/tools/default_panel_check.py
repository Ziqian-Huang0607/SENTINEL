"""default_panel_check — known router/admin panel match (agent-spec.md s2).

Pure substring matching of already-fetched Server/title strings against
data/known_panels.json. NO network requests and NO credentials anywhere —
the signatures are banner strings only. The first panel whose pattern
matches wins; specific vendor panels are listed before the generic
"router admin" catch-all.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.scope import Scope
from src.tools.base import EXCERPT_LIMIT, Tool, ToolResult, sanitize

PANELS_PATH = Path(__file__).parents[2] / "data" / "known_panels.json"
_panels_cache: list[dict[str, Any]] | None = None


def load_panels() -> list[dict[str, Any]]:
    """Load (and cache) the known-panel signature list."""
    global _panels_cache
    if _panels_cache is None:
        document = json.loads(PANELS_PATH.read_text(encoding="utf-8"))
        _panels_cache = list(document.get("panels", []))
    return _panels_cache


def match_panel(server: str, title: str) -> tuple[dict[str, Any], str] | None:
    """Return (panel, evidence) for the first matching signature, or None."""
    haystacks = {"server": server.lower(), "title": title.lower()}
    for panel in load_panels():
        for field, text in haystacks.items():
            if not text:
                continue
            for pattern in panel.get(f"{field}_patterns", []):
                if pattern.lower() in text:
                    evidence = f"{field} contains {pattern!r}"
                    return panel, evidence
    return None


async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
    """Match server/title strings against known admin panel signatures."""
    host = str(args.get("host", ""))
    scope.check(host)  # ScopeViolation propagates — never caught.
    server = str(args.get("server", "") or "")
    title = str(args.get("title", "") or "")
    matched = match_panel(server, title)
    if matched is None:
        data: dict[str, Any] = {
            "matched_panel": None,
            "vendor_hint": None,
            "evidence": "no known panel signature matched",
        }
        excerpt = sanitize(
            f"panel check {host}: no known panel match "
            f"(server={server!r} title={title!r})",
            EXCERPT_LIMIT,
        )
        return ToolResult(ok=True, data=data, excerpt=excerpt)
    panel, evidence = matched
    data = {
        "matched_panel": panel["name"],
        "vendor_hint": panel["vendor"],
        "evidence": sanitize(evidence, 300),
    }
    excerpt = sanitize(
        f"panel check {host}: matched {panel['name']} vendor={panel['vendor']} "
        f"evidence={evidence}",
        EXCERPT_LIMIT,
    )
    return ToolResult(ok=True, data=data, excerpt=excerpt)


TOOL = Tool(
    name="default_panel_check",
    description="Match known router/admin panel from server/title strings (no requests).",
    args_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "port": {"type": "integer"},
            "server": {"type": "string", "default": ""},
            "title": {"type": "string", "default": ""},
        },
        "required": ["host", "port"],
    },
    run=run,
)
