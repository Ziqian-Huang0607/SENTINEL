"""SENTINEL analyzer FastAPI service (port 8710).

Endpoints (SPEC: Analyzer REST API):

- ``GET /health`` -> ``{"status": "ok", "mode": "llm|fallback",
  "epss_version": "v4"}``
- ``POST /analyze`` body = ScanInput -> AnalysisOutput (422 on schema
  violation); every request falls back to the rule-based engine on any LLM
  error, timeout or invalid JSON.
- ``POST /report`` body = {"scan", "analysis", "formats"} -> forwards to
  the reports service (``REPORTS_URL``, default http://localhost:8711) and
  returns its JSON.

At startup the service probes Ollama ``/api/tags`` with a 3s timeout to
auto-detect the mode (llm when reachable, fallback otherwise).
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request

from src.attack_chain import extract_candidate_chains
from src.fallback_analyzer import analyze_fallback
from src.llm_client import (
    PROBE_TIMEOUT_SECONDS,
    LLMError,
    OllamaClient,
    probe_ollama,
)
from src.models import (
    EPSS_VERSION,
    AnalysisOutput,
    AnalyzerMode,
    HealthResponse,
    ReportRequest,
    ReportResponse,
    ScanInput,
)

logger = logging.getLogger("sentinel-analyzer")

DEFAULT_REPORTS_URL = "http://localhost:8711"
REPORTS_TIMEOUT_SECONDS = 60.0


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Probe Ollama at startup to auto-detect llm vs fallback mode."""
    client = OllamaClient()
    app.state.llm_client = client
    available = await probe_ollama(client.base_url, timeout=PROBE_TIMEOUT_SECONDS)
    app.state.mode = AnalyzerMode.llm if available else AnalyzerMode.fallback
    logger.info(
        "sentinel-analyzer startup: ollama %s at %s -> mode=%s",
        "detected" if available else "unreachable",
        client.base_url,
        app.state.mode.value,
    )
    yield


app = FastAPI(title="sentinel-analyzer", version="1.0.0", lifespan=lifespan)


def _current_mode(request: Request) -> AnalyzerMode:
    """Mode detected at startup (fallback if lifespan did not run)."""
    return getattr(request.app.state, "mode", AnalyzerMode.fallback)


@app.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Liveness probe reporting the active analyzer mode and EPSS vintage."""
    return HealthResponse(
        status="ok", mode=_current_mode(request), epss_version=EPSS_VERSION
    )


@app.post("/analyze", response_model=AnalysisOutput)
async def analyze(scan: ScanInput, request: Request) -> AnalysisOutput:
    """Analyze a scan; LLM when available, rule-based fallback otherwise."""
    if _current_mode(request) is AnalyzerMode.llm:
        client: OllamaClient = request.app.state.llm_client
        try:
            candidates = extract_candidate_chains(scan)
            return await client.analyze(scan, candidates)
        except LLMError as exc:
            logger.warning(
                "LLM analysis failed (%s); falling back to rule-based engine",
                exc,
            )
    return analyze_fallback(scan)


@app.post("/report", response_model=ReportResponse)
async def report(report_request: ReportRequest) -> ReportResponse:
    """Forward the report job to the reports service and return its JSON."""
    reports_url = os.environ.get("REPORTS_URL", DEFAULT_REPORTS_URL).rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=REPORTS_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{reports_url}/report",
                json=report_request.model_dump(mode="json"),
            )
            response.raise_for_status()
            return ReportResponse.model_validate(response.json())
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502, detail=f"reports service error: {exc}"
        ) from exc
