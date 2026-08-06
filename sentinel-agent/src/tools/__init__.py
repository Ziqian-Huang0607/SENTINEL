"""TOOL_REGISTRY — the nine benign probe primitives (agent-spec.md section 2).

Every tool is scope-guarded, hard-capped at 5s, and returns a ToolResult
whose sanitized <=600-char excerpt is the only network output that may
enter an LLM transcript.
"""

from __future__ import annotations

from src.tools import (
    cve_lookup,
    default_panel_check,
    dns_reverse,
    grab_banner,
    http_get,
    ipp_enumerate,
    mdns_browse,
    smb_probe,
    tls_hello,
)
from src.tools.base import Tool, ToolResult

_TOOL_MODULES = (
    http_get,
    grab_banner,
    tls_hello,
    ipp_enumerate,
    mdns_browse,
    smb_probe,
    dns_reverse,
    cve_lookup,
    default_panel_check,
)

TOOL_REGISTRY: dict[str, Tool] = {
    module.TOOL.name: module.TOOL for module in _TOOL_MODULES
}

__all__ = ["TOOL_REGISTRY", "Tool", "ToolResult"]
