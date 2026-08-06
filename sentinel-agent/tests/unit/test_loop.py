"""Tests for the agent loop and deterministic target selection (spec 3+7).

Ollama is scripted via respx; tools are test-local stubs (never the real
TOOL_REGISTRY — the loop resolves tools via dependency injection only).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from src.loop import investigate_target, select_targets
from src.models import CLASS_SEVERITY, TargetBrief
from src.scope import Scope
from src.tools.base import Tool, ToolResult

BASE_URL = "http://localhost:11434"
HOST = "192.168.1.5"
PORT = 8080


def make_stub_tool(
    name: str,
    result: ToolResult | None = None,
    calls: list[dict[str, Any]] | None = None,
) -> Tool:
    """Build a recording stub Tool with a canned result.

    The stub enforces scope exactly like a real tool: it raises
    ScopeViolation (via Scope.check) for out-of-scope hosts.
    """

    async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
        if "host" in args:
            scope.check(str(args["host"]))
        if calls is not None:
            calls.append(dict(args))
        return result or ToolResult(
            ok=True, data={"status": 200}, excerpt=f"{name} ok"
        )

    return Tool(
        name=name,
        description=f"stub {name}",
        args_schema={"properties": {"host": {"type": "string"}}},
        run=run,
    )


def make_brief(**overrides: Any) -> TargetBrief:
    """A single-target brief for the loop tests."""
    values: dict[str, Any] = {
        "host": HOST,
        "ports": [PORT],
        "trigger": "unauth_posture",
        "hints": {"posture_ids": ["POSTURE-UNAUTH-WEB"]},
    }
    values.update(overrides)
    return TargetBrief(**values)


def ollama_reply(payload: dict[str, Any]) -> httpx.Response:
    """Wrap one scripted turn in an Ollama generate response."""
    return httpx.Response(200, json={"response": json.dumps(payload)})


def action_turn(tool: str = "http_get", args: dict[str, Any] | None = None) -> dict:
    """A valid action turn per the section-3 wire format."""
    return {
        "thought": "probe the target",
        "action": {"tool": tool, "args": args or {"host": HOST, "port": PORT}},
    }


def final_turn(
    findings: list[dict[str, Any]] | None = None, summary: str = "done"
) -> dict:
    """A valid final turn per the section-3 wire format."""
    return {
        "thought": "conclude",
        "final": {
            "summary": summary,
            "findings": findings or [],
            "confidence": 0.8,
        },
    }


def grounded_finding(**overrides: Any) -> dict[str, Any]:
    """A finding citing E1; severity deliberately wrong (must be overridden)."""
    finding: dict[str, Any] = {
        "id": "WHATEVER-THE-MODEL-SAID",
        "finding_class": "DEFAULT-PANEL",
        "host": HOST,
        "port": PORT,
        "severity": 9.9,
        "title": "Known admin panel exposed",
        "detail": "GET / shows an admin login page.",
        "evidence": ["E1"],
        "confidence": 0.85,
    }
    finding.update(overrides)
    return finding


@pytest.mark.asyncio
async def test_loop_action_then_grounded_final_concludes(tmp_path: Path) -> None:
    """Scripted action -> final: tool runs, evidence ids, severity override."""
    calls: list[dict[str, Any]] = []
    registry = {
        "http_get": make_stub_tool(
            "http_get",
            ToolResult(
                ok=True,
                data={"status": 200, "server": "nginx/1.18", "title": "Admin"},
                excerpt="GET / -> 200; Server: nginx/1.18; title: Admin",
            ),
            calls,
        )
    }
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            side_effect=[
                ollama_reply(action_turn()),
                ollama_reply(final_turn([grounded_finding()])),
            ]
        )
        from src.model_client import OllamaClient

        investigation = await investigate_target(
            make_brief(),
            registry,
            OllamaClient(ollama_url=BASE_URL),
            Scope({HOST}),
            transcript_dir=tmp_path,
        )
    assert investigation.status == "concluded"
    assert investigation.turns == 2
    # The tool executed exactly once, in order, with the model's args.
    assert calls == [{"host": HOST, "port": PORT}]
    # Severity overridden to the class constant, never the LLM value.
    assert len(investigation.findings) == 1
    finding = investigation.findings[0]
    assert finding.severity == CLASS_SEVERITY["DEFAULT-PANEL"] == 7.0
    assert finding.evidence == ["E1"]
    assert finding.id == "AGENT-DEFAULT-PANEL-1"
    # Transcript was persisted with the evidence ref.
    assert investigation.transcript_path.endswith(f"{HOST}_{PORT}.json")
    record = json.loads(Path(investigation.transcript_path).read_text())
    assert [ref["id"] for ref in record["evidence"]] == ["E1"]
    assert record["evidence"][0]["tool"] == "http_get"
    assert record["turns"][0]["evidence_ids"] == ["E1"]
    assert record["status"] == "concluded"


@pytest.mark.asyncio
async def test_loop_grounding_rejects_unknown_evidence() -> None:
    """A final citing E99 is a protocol violation: retry, then inconclusive."""
    registry = {"http_get": make_stub_tool("http_get")}
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            side_effect=[
                ollama_reply(action_turn()),
                ollama_reply(final_turn([grounded_finding(evidence=["E99"])])),
                ollama_reply(final_turn([grounded_finding(evidence=["E99"])])),
            ]
        )
        from src.model_client import OllamaClient

        investigation = await investigate_target(
            make_brief(),
            registry,
            OllamaClient(ollama_url=BASE_URL),
            Scope({HOST}),
        )
    assert investigation.status == "inconclusive"
    assert investigation.turns == 3


@pytest.mark.asyncio
async def test_loop_garbage_json_twice_is_inconclusive() -> None:
    """Two unparseable replies -> retry once, then inconclusive."""
    registry = {"http_get": make_stub_tool("http_get")}
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            side_effect=[
                httpx.Response(200, json={"response": "not json at all"}),
                httpx.Response(200, json={"response": "still not json"}),
            ]
        )
        from src.model_client import OllamaClient

        investigation = await investigate_target(
            make_brief(),
            registry,
            OllamaClient(ollama_url=BASE_URL),
            Scope({HOST}),
        )
    assert investigation.status == "inconclusive"
    assert investigation.turns == 2


@pytest.mark.asyncio
async def test_loop_budget_exhaustion() -> None:
    """max_steps=2 with always-action turns -> budget_exhausted."""
    calls: list[dict[str, Any]] = []
    registry = {"http_get": make_stub_tool("http_get", calls=calls)}
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            side_effect=[
                ollama_reply(action_turn()),
                ollama_reply(action_turn()),
                ollama_reply(action_turn()),  # must never be consumed
            ]
        )
        from src.model_client import OllamaClient

        investigation = await investigate_target(
            make_brief(),
            registry,
            OllamaClient(ollama_url=BASE_URL),
            Scope({HOST}),
            max_steps=2,
        )
    assert investigation.status == "budget_exhausted"
    assert investigation.turns == 2
    assert len(calls) == 2
    assert investigation.findings == []


@pytest.mark.asyncio
async def test_loop_filters_offensive_phrasing() -> None:
    """Offensive phrasing in final title/detail/summary is replaced."""
    registry = {"http_get": make_stub_tool("http_get")}
    nasty = final_turn(
        [grounded_finding(
            title="Attacker could exploit this panel to gain access",
            detail="From here one could pivot to attack other hosts",
        )],
        summary="Found a way to escalate privileges on the device",
    )
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            side_effect=[ollama_reply(action_turn()), ollama_reply(nasty)]
        )
        from src.model_client import OllamaClient

        investigation = await investigate_target(
            make_brief(),
            registry,
            OllamaClient(ollama_url=BASE_URL),
            Scope({HOST}),
        )
    assert investigation.status == "concluded"
    finding = investigation.findings[0]
    assert "[removed: non-defensive phrasing]" in finding.title
    assert "[removed: non-defensive phrasing]" in finding.detail
    assert "[removed: non-defensive phrasing]" in investigation.summary
    assert "exploit" not in finding.title.lower()
    assert "pivot to attack" not in finding.detail.lower()


@pytest.mark.asyncio
async def test_loop_scope_violation_recorded_as_failed_turn(
    tmp_path: Path,
) -> None:
    """An out-of-scope action is a failed turn, not a crash or a bypass."""
    calls: list[dict[str, Any]] = []
    registry = {"http_get": make_stub_tool("http_get", calls=calls)}
    out_of_scope = action_turn(args={"host": "10.9.9.9", "port": PORT})
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            side_effect=[
                ollama_reply(out_of_scope),
                ollama_reply(final_turn([], summary="nothing in scope")),
            ]
        )
        from src.model_client import OllamaClient

        investigation = await investigate_target(
            make_brief(),
            registry,
            OllamaClient(ollama_url=BASE_URL),
            Scope({HOST}),
            transcript_dir=tmp_path,
        )
    # The stub tool never ran successfully (scope raised first).
    assert calls == []
    assert investigation.status == "concluded"
    record = json.loads(Path(investigation.transcript_path).read_text())
    failed_turn = record["turns"][0]
    assert failed_turn["error"] == "out of scope"
    assert failed_turn["evidence_ids"] == []


def test_select_targets_order_and_grouping() -> None:
    """Gateway first, then unauth, unknown, CVE; ports grouped per host."""
    scan = {
        "hosts": [
            {"ip": "192.168.1.7", "hostname": None, "ports": [
                {"port": 6379, "protocol": "tcp", "state": "open",
                 "service": "redis", "version": "6.2.7"},
            ]},
            {"ip": "192.168.1.9", "hostname": None, "ports": [
                {"port": 9999, "protocol": "tcp", "state": "open",
                 "service": None, "version": None},
                {"port": 8888, "protocol": "tcp", "state": "open",
                 "service": "", "version": None},
            ]},
            {"ip": "192.168.1.5", "hostname": None, "ports": [
                {"port": 8080, "protocol": "tcp", "state": "open",
                 "service": "http", "version": "nginx 1.18"},
            ]},
            {"ip": "192.168.1.1", "hostname": "gw", "ports": [
                {"port": 443, "protocol": "tcp", "state": "open",
                 "service": "https", "version": "nginx 1.18"},
            ]},
            {"ip": "192.168.1.50", "hostname": None, "ports": []},
        ],
        "posture_findings": [
            {"id": "POSTURE-UNAUTH-WEB-GATEWAY", "host": "192.168.1.1",
             "port": 443, "severity": 7.5, "title": "gw", "evidence": "..."},
            {"id": "POSTURE-UNAUTH-WEB", "host": "192.168.1.5", "port": 8080,
             "severity": 6.5, "title": "web", "evidence": "..."},
        ],
        "vulnerabilities": [
            {"cve_id": "CVE-2022-0543", "cvss": 10.0, "epss": 0.9,
             "host": "192.168.1.7", "port": 6379, "summary": "redis",
             "kev": True},
        ],
    }
    briefs = select_targets(scan)
    assert [(b.trigger, b.host) for b in briefs] == [
        ("gateway", "192.168.1.1"),
        ("unauth_posture", "192.168.1.5"),
        ("unknown_service", "192.168.1.9"),
        ("cve", "192.168.1.7"),
    ]
    # Ports grouped per host; the uninteresting host is skipped entirely.
    assert briefs[2].ports == [8888, 9999]
    assert briefs[0].hints["posture_ids"] == ["POSTURE-UNAUTH-WEB-GATEWAY"]
    assert briefs[3].hints["cve_ids"] == ["CVE-2022-0543"]
    assert briefs[2].hints["services"] == {}
    assert all(b.host != "192.168.1.50" for b in briefs)
