"""Tests for the semantic unknown-service identification sub-task."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from src.models import CLASS_SEVERITY, TargetBrief
from src.scope import Scope
from src.service_id import identify_unknown_service
from src.tools.base import Tool, ToolResult

BASE_URL = "http://localhost:11434"
HOST = "192.168.1.9"
PORT = 9999


def stub_tool(name: str, excerpt: str, data: dict[str, Any] | None = None) -> Tool:
    """A canned-excerpt probe stub."""

    async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
        if "host" in args:
            scope.check(str(args["host"]))
        return ToolResult(ok=True, data=data or {}, excerpt=excerpt)

    return Tool(
        name=name,
        description=f"stub {name}",
        args_schema={"properties": {"host": {"type": "string"}}},
        run=run,
    )


def make_registry() -> dict[str, Tool]:
    """The three identification probes with canned excerpts."""
    return {
        "grab_banner": stub_tool(
            "grab_banner", "banner: IPP/2.0 (CUPS)", {"banner": "IPP/2.0 (CUPS)"}
        ),
        "http_get": stub_tool(
            "http_get", "GET / -> 200; Server: CUPS/2.4",
            {"status": 200, "server": "CUPS/2.4"},
        ),
        "tls_hello": stub_tool("tls_hello", "tls: False", {"tls": False}),
    }


def make_brief() -> TargetBrief:
    """An unknown-service brief for one port."""
    return TargetBrief(host=HOST, ports=[PORT], trigger="unknown_service", hints={})


def ollama_response(payload: Any) -> httpx.Response:
    """Wrap a payload (dict -> JSON string, str -> raw) as an Ollama reply."""
    text = payload if isinstance(payload, str) else json.dumps(payload)
    return httpx.Response(200, json={"response": text})


@pytest.mark.asyncio
async def test_identify_unknown_service_returns_grounded_finding() -> None:
    """A clean model answer -> SERVICE-IDENT finding citing probe evidence."""
    from src.model_client import OllamaClient

    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            return_value=ollama_response(
                {"service": "ipp", "version_guess": "CUPS 2.4", "confidence": 0.8}
            )
        )
        finding = await identify_unknown_service(
            make_brief(),
            make_registry(),
            OllamaClient(ollama_url=BASE_URL),
            Scope({HOST}),
        )
    assert finding is not None
    assert finding.finding_class == "SERVICE-IDENT"
    assert finding.severity == CLASS_SEVERITY["SERVICE-IDENT"] == 2.0
    assert finding.host == HOST
    assert finding.port == PORT
    assert finding.confidence == pytest.approx(0.8)
    assert "ipp" in finding.title
    assert "CUPS 2.4" in finding.detail
    # Grounding: at least one real probe evidence id (three probes ran).
    assert finding.evidence == ["E1", "E2", "E3"]


@pytest.mark.asyncio
async def test_identify_unknown_service_garbage_model_returns_none() -> None:
    """Model garbage -> None (never a hallucinated identification)."""
    from src.model_client import OllamaClient

    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            return_value=ollama_response("this is definitely not JSON")
        )
        finding = await identify_unknown_service(
            make_brief(),
            make_registry(),
            OllamaClient(ollama_url=BASE_URL),
            Scope({HOST}),
        )
    assert finding is None


@pytest.mark.asyncio
async def test_identify_unknown_service_null_service_returns_none() -> None:
    """A null service answer -> None (unidentified is a valid outcome)."""
    from src.model_client import OllamaClient

    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            return_value=ollama_response(
                {"service": None, "version_guess": None, "confidence": 0.1}
            )
        )
        finding = await identify_unknown_service(
            make_brief(),
            make_registry(),
            OllamaClient(ollama_url=BASE_URL),
            Scope({HOST}),
        )
    assert finding is None
