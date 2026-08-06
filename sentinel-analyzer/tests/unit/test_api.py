"""End-to-end API tests with the FastAPI TestClient."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from src import main
from src.fallback_analyzer import analyze_fallback
from src.llm_client import LLMError, OllamaClient
from src.models import AnalysisOutput, AnalyzerMode, ScanInput


async def _probe_false(*args: Any, **kwargs: Any) -> bool:
    """Fake Ollama probe: service unavailable (forces fallback mode)."""
    return False


async def _probe_true(*args: Any, **kwargs: Any) -> bool:
    """Fake Ollama probe: service available (forces llm mode)."""
    return True


def test_health_forced_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """GET /health reports ok + fallback when Ollama is unreachable."""
    monkeypatch.setattr(main, "probe_ollama", _probe_false)
    with TestClient(main.app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "mode": "fallback",
        "epss_version": "v4",
    }


def test_analyze_forced_fallback_end_to_end(
    monkeypatch: pytest.MonkeyPatch, scan_payload: dict
) -> None:
    """POST /analyze in fallback mode returns a contract-valid analysis."""
    monkeypatch.setattr(main, "probe_ollama", _probe_false)
    with TestClient(main.app) as client:
        response = client.post("/analyze", json=scan_payload)
    assert response.status_code == 200
    out = AnalysisOutput.model_validate(response.json())
    assert out.analyzer_mode is AnalyzerMode.fallback
    assert out.risk_score == 8.97
    assert out.attack_chains
    for tier in ("daily", "authority", "hacker", "military"):
        assert getattr(out.remediation, tier)


def test_analyze_schema_violation_returns_422(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid ScanInput bodies are rejected with HTTP 422."""
    monkeypatch.setattr(main, "probe_ollama", _probe_false)
    with TestClient(main.app) as client:
        response = client.post(
            "/analyze", json={"scan_id": "x", "tier": "platinum"}
        )
        assert response.status_code == 422

        response = client.post("/analyze", json={"not": "a scan"})
        assert response.status_code == 422


def test_health_and_analyze_llm_mode_success(
    monkeypatch: pytest.MonkeyPatch, scan_payload: dict
) -> None:
    """With Ollama up and a valid LLM reply, mode and output are llm."""
    monkeypatch.setattr(main, "probe_ollama", _probe_true)

    async def fake_analyze(
        self: OllamaClient, scan: ScanInput, candidates: list
    ) -> AnalysisOutput:
        return AnalysisOutput(
            attack_chains=[],
            risk_score=8.97,
            observations=["llm analysis"],
            analyzer_mode=AnalyzerMode.llm,
        )

    monkeypatch.setattr(OllamaClient, "analyze", fake_analyze)
    with TestClient(main.app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json() == {
            "status": "ok",
            "mode": "llm",
            "epss_version": "v4",
        }

        response = client.post("/analyze", json=scan_payload)
    assert response.status_code == 200
    body = response.json()
    assert body["analyzer_mode"] == "llm"
    assert body["observations"] == ["llm analysis"]


def test_analyze_llm_failure_falls_back_per_request(
    monkeypatch: pytest.MonkeyPatch, scan_payload: dict
) -> None:
    """Any LLM error mid-request downgrades that request to fallback."""
    monkeypatch.setattr(main, "probe_ollama", _probe_true)

    async def boom(
        self: OllamaClient, scan: ScanInput, candidates: list
    ) -> AnalysisOutput:
        raise LLMError("simulated LLM timeout")

    monkeypatch.setattr(OllamaClient, "analyze", boom)
    with TestClient(main.app) as client:
        assert client.get("/health").json()["mode"] == "llm"
        response = client.post("/analyze", json=scan_payload)
    assert response.status_code == 200
    assert response.json()["analyzer_mode"] == "fallback"


def test_report_forwards_to_reports_service(
    monkeypatch: pytest.MonkeyPatch, scan_payload: dict
) -> None:
    """POST /report forwards to REPORTS_URL and returns its JSON."""
    monkeypatch.setattr(main, "probe_ollama", _probe_false)
    monkeypatch.setenv("REPORTS_URL", "http://reports.test")
    analysis = analyze_fallback(ScanInput.model_validate(scan_payload))
    body = {
        "scan": scan_payload,
        "analysis": analysis.model_dump(mode="json"),
        "formats": ["pdf", "json"],
    }
    files = {"pdf": "/out/report.pdf", "json": "/out/report.json"}
    with respx.mock(base_url="http://reports.test") as router:
        route = router.post("/report").mock(
            return_value=httpx.Response(200, json={"files": files})
        )
        with TestClient(main.app) as client:
            response = client.post("/report", json=body)

    assert response.status_code == 200
    assert response.json() == {"files": files}
    assert route.called
    forwarded = json.loads(route.calls[0].request.content)
    assert forwarded["scan"]["scan_id"] == scan_payload["scan_id"]
    assert forwarded["analysis"]["analyzer_mode"] == "fallback"
    assert forwarded["formats"] == ["pdf", "json"]


def test_report_forwards_agent_document_verbatim(
    monkeypatch: pytest.MonkeyPatch, scan_payload: dict
) -> None:
    """R9: the optional agent document survives the analyzer hop untouched."""
    monkeypatch.setattr(main, "probe_ollama", _probe_false)
    monkeypatch.setenv("REPORTS_URL", "http://reports.test")
    analysis = analyze_fallback(ScanInput.model_validate(scan_payload))
    agent = {
        "agent_version": "0.1.0",
        "scan_id": scan_payload["scan_id"],
        "model": "playbook",
        "investigations": [{"host": "127.0.0.1", "status": "concluded"}],
        "findings": [],
        "drift": [{"kind": "NEW_PORT", "host": "127.0.0.1", "port": 8888}],
    }
    body = {
        "scan": scan_payload,
        "analysis": analysis.model_dump(mode="json"),
        "formats": ["json"],
        "agent": agent,
    }
    with respx.mock(base_url="http://reports.test") as router:
        route = router.post("/report").mock(
            return_value=httpx.Response(200, json={"files": {}})
        )
        with TestClient(main.app) as client:
            response = client.post("/report", json=body)

    assert response.status_code == 200
    forwarded = json.loads(route.calls[0].request.content)
    assert forwarded["agent"] == agent


def test_report_reports_service_down_gives_502(
    monkeypatch: pytest.MonkeyPatch, scan_payload: dict
) -> None:
    """A reports-service failure surfaces as HTTP 502."""
    monkeypatch.setattr(main, "probe_ollama", _probe_false)
    monkeypatch.setenv("REPORTS_URL", "http://reports.test")
    analysis = analyze_fallback(ScanInput.model_validate(scan_payload))
    body = {
        "scan": scan_payload,
        "analysis": analysis.model_dump(mode="json"),
        "formats": ["sarif"],
    }
    with respx.mock(base_url="http://reports.test") as router:
        router.post("/report").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        with TestClient(main.app) as client:
            response = client.post("/report", json=body)
    assert response.status_code == 502
