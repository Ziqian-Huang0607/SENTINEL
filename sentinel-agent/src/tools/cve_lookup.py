"""cve_lookup — offline CVE seed matching (agent-spec.md section 2).

Reads data/cve_seed.json (a mirror of the scanner's embedded cve_cache
seed) and returns entries whose service matches case-insensitively and,
when a version is given, whose affected range contains it. Ranges follow
the scanner convention: start inclusive, end exclusive, a missing bound is
unbounded. Pure local lookup — no network.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.scope import Scope
from src.tools.base import EXCERPT_LIMIT, Tool, ToolResult, sanitize

SEED_PATH = Path(__file__).parents[2] / "data" / "cve_seed.json"
_seed_cache: dict[str, Any] | None = None


def load_seed() -> dict[str, Any]:
    """Load (and cache) the CVE seed JSON shipped with the package."""
    global _seed_cache
    if _seed_cache is None:
        _seed_cache = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    return _seed_cache


def _version_key(version: str) -> tuple[int, ...] | None:
    """Parse a dotted version string into comparable ints; None if unusable."""
    parts: list[int] = []
    for token in re.split(r"[.\-+_~]", version.strip()):
        match = re.match(r"\d+", token)
        if not match:
            if parts:
                break
            return None
        parts.append(int(match.group()))
    return tuple(parts) if parts else None


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    """Compare two version tuples, padding the shorter with zeros."""
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _in_range(entry: dict[str, Any], version: str) -> bool:
    """True when version falls inside the entry's [start, end) range."""
    key = _version_key(version)
    if key is None:
        return True  # unparseable version: keep the candidate (defensive)
    start = entry.get("version_start")
    end = entry.get("version_end")
    below_start = start is not None and _compare(
        key, _version_key(str(start)) or ()
    ) < 0
    above_end = end is not None and _compare(key, _version_key(str(end)) or ()) >= 0
    return not (below_start or above_end)


async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
    """Match service (+optional version) against the CVE seed."""
    del scope  # offline lookup: no host, nothing to scope-check
    service = str(args.get("service", "")).strip()
    version = str(args.get("version", "")).strip()
    matches: list[dict[str, Any]] = []
    for entry in load_seed().get("entries", []):
        if str(entry.get("service", "")).lower() != service.lower():
            continue
        if version and not _in_range(entry, version):
            continue
        matches.append(
            {
                "cve": entry["cve"],
                "cvss": entry["cvss"],
                "epss": entry["epss"],
                "kev": entry["kev"],
                "summary": sanitize(str(entry["summary"]), 300),
            }
        )
    data: dict[str, Any] = {"matches": matches}
    listing = ", ".join(
        f"{m['cve']} (cvss {m['cvss']}{', KEV' if m['kev'] else ''})" for m in matches
    )
    excerpt = sanitize(
        f"CVE lookup {service} {version or '(any version)'}: "
        f"{len(matches)} match(es){': ' + listing if listing else ''}",
        EXCERPT_LIMIT,
    )
    return ToolResult(ok=True, data=data, excerpt=excerpt)


TOOL = Tool(
    name="cve_lookup",
    description="Offline CVE seed lookup for a service and version.",
    args_schema={
        "type": "object",
        "properties": {
            "service": {"type": "string"},
            "version": {"type": "string", "default": ""},
        },
        "required": ["service"],
    },
    run=run,
)
