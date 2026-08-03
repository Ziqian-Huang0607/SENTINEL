"""Tests for the async Ollama client with mocked HTTP (respx)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from src.llm_client import (
    GENERATE_OPTIONS,
    LLM_SEED,
    SYSTEM_PROMPT,
    LLMError,
    OllamaClient,
    parse_analysis,
    probe_ollama,
    strip_code_fences,
)
from src.models import AnalysisOutput, AnalyzerMode, ScanInput

BASE_URL = "http://localhost:11434"


def _valid_analysis_payload() -> dict:
    """A contract-valid AnalysisOutput JSON document."""
    return {
        "attack_chains": [
            {
                "path": ["192.168.1.45:6379"],
                "description": "Unauthenticated Redis allows direct data access.",
                "mitre_technique": "T1190",
                "confidence": 0.9,
                "impact": 0.92,
                "priority": 1,
            }
        ],
        "remediation": {
            "daily": ["Enable Redis AUTH within 30 days."],
            "authority": ["Restrict port 6379 to app subnets within 7 days."],
            "hacker": ["Rotate exposed keys within 24 hours."],
            "military": ["Airgap the data store immediately."],
        },
        "risk_score": 8.97,
        "observations": ["LLM analysis of 3 hosts."],
        "analyzer_mode": "llm",
    }


@pytest.mark.asyncio
async def test_analyze_success(scan: ScanInput) -> None:
    """A valid strict-JSON LLM reply is parsed into AnalysisOutput."""
    with respx.mock(base_url=BASE_URL) as router:
        route = router.post("/api/generate").mock(
            return_value=httpx.Response(
                200, json={"response": json.dumps(_valid_analysis_payload())}
            )
        )
        client = OllamaClient(base_url=BASE_URL)
        result = await client.analyze(scan, [])

    assert isinstance(result, AnalysisOutput)
    assert result.analyzer_mode is AnalyzerMode.llm
    assert result.risk_score == 8.97
    assert result.attack_chains[0].mitre_technique == "T1190"

    assert route.called
    body = json.loads(route.calls[0].request.content)
    assert body["model"] == "llama3.1:8b"
    assert body["stream"] is False
    assert body["system"] == SYSTEM_PROMPT
    assert body["options"] == GENERATE_OPTIONS
    assert scan.scan_id in body["prompt"]


@pytest.mark.asyncio
async def test_generate_request_pins_seed(scan: ScanInput) -> None:
    """Determinism: every /api/generate request body carries seed 0."""
    assert LLM_SEED == 0
    assert GENERATE_OPTIONS["seed"] == LLM_SEED
    with respx.mock(base_url=BASE_URL) as router:
        route = router.post("/api/generate").mock(
            return_value=httpx.Response(
                200, json={"response": json.dumps(_valid_analysis_payload())}
            )
        )
        client = OllamaClient(base_url=BASE_URL)
        await client.analyze(scan, [])
    body = json.loads(route.calls[0].request.content)
    assert body["options"]["seed"] == 0


@pytest.mark.asyncio
async def test_raw_archive_written_on_success(
    scan: ScanInput, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A successful raw LLM response is archived as {scan_id}_{ts}.raw.json."""
    monkeypatch.setenv("SENTINEL_RAW_ARCHIVE_DIR", str(tmp_path))
    raw_text = json.dumps(_valid_analysis_payload())
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            return_value=httpx.Response(200, json={"response": raw_text})
        )
        client = OllamaClient(base_url=BASE_URL)
        await client.analyze(scan, [])

    archives = list(tmp_path.glob("*.raw.json"))
    assert len(archives) == 1
    assert archives[0].name.startswith(f"{scan.scan_id}_")
    record = json.loads(archives[0].read_text())
    assert record["scan_id"] == scan.scan_id
    assert record["model"] == "llama3.1:8b"
    assert record["options"] == GENERATE_OPTIONS
    assert record["raw_text"] == raw_text
    assert record["ok"] is True
    assert record["error"] is None
    assert isinstance(record["ts"], int)


@pytest.mark.asyncio
async def test_raw_archive_written_on_parse_failure(
    scan: ScanInput, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unparseable raw responses are archived with ok=False and the error."""
    monkeypatch.setenv("SENTINEL_RAW_ARCHIVE_DIR", str(tmp_path))
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            return_value=httpx.Response(200, json={"response": "not json"})
        )
        client = OllamaClient(base_url=BASE_URL)
        with pytest.raises(LLMError):
            await client.analyze(scan, [])

    archives = list(tmp_path.glob("*.raw.json"))
    assert len(archives) >= 1
    for path in archives:
        record = json.loads(path.read_text())
        assert record["raw_text"] == "not json"
        assert record["ok"] is False
        assert record["error"]


def test_fallback_path_writes_no_archive(
    scan: ScanInput, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The rule-based fallback never calls the LLM, so archives nothing."""
    from src.fallback_analyzer import analyze_fallback

    monkeypatch.setenv("SENTINEL_RAW_ARCHIVE_DIR", str(tmp_path))
    analyze_fallback(scan)
    assert list(tmp_path.glob("*.raw.json")) == []


@pytest.mark.asyncio
async def test_analyze_success_with_code_fences(scan: ScanInput) -> None:
    """Code-fenced LLM JSON is stripped and parsed successfully."""
    fenced = f"```json\n{json.dumps(_valid_analysis_payload())}\n```"
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            return_value=httpx.Response(200, json={"response": fenced})
        )
        client = OllamaClient(base_url=BASE_URL)
        result = await client.analyze(scan, [])
    assert result.analyzer_mode is AnalyzerMode.llm


@pytest.mark.asyncio
async def test_analyze_garbage_json_retries_then_raises(scan: ScanInput) -> None:
    """Garbage JSON triggers exactly one schema-reminder retry, then LLMError."""
    with respx.mock(base_url=BASE_URL) as router:
        route = router.post("/api/generate").mock(
            return_value=httpx.Response(200, json={"response": "not json at all"})
        )
        client = OllamaClient(base_url=BASE_URL)
        with pytest.raises(LLMError):
            await client.analyze(scan, [])

    assert len(route.calls) == 2  # initial attempt + one retry
    retry_body = json.loads(route.calls[1].request.content)
    assert "SCHEMA REMINDER" in retry_body["prompt"]


@pytest.mark.asyncio
async def test_analyze_schema_violation_retries_then_raises(
    scan: ScanInput,
) -> None:
    """Valid JSON that violates the schema also ends in LLMError."""
    bad = _valid_analysis_payload()
    bad["attack_chains"][0]["confidence"] = 9.9
    with respx.mock(base_url=BASE_URL) as router:
        route = router.post("/api/generate").mock(
            return_value=httpx.Response(200, json={"response": json.dumps(bad)})
        )
        client = OllamaClient(base_url=BASE_URL)
        with pytest.raises(LLMError):
            await client.analyze(scan, [])
    assert len(route.calls) == 2


@pytest.mark.asyncio
async def test_analyze_timeout_raises_llm_error(scan: ScanInput) -> None:
    """A transport timeout surfaces as LLMError so callers can fall back."""
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            side_effect=httpx.ConnectTimeout("simulated timeout")
        )
        client = OllamaClient(base_url=BASE_URL)
        with pytest.raises(LLMError):
            await client.analyze(scan, [])


@pytest.mark.asyncio
async def test_analyze_http_error_raises_llm_error(scan: ScanInput) -> None:
    """A 500 from Ollama surfaces as LLMError."""
    with respx.mock(base_url=BASE_URL) as router:
        router.post("/api/generate").mock(
            return_value=httpx.Response(500, json={"error": "model missing"})
        )
        client = OllamaClient(base_url=BASE_URL)
        with pytest.raises(LLMError):
            await client.analyze(scan, [])


@pytest.mark.asyncio
async def test_probe_ollama_detects_up_and_down() -> None:
    """Startup probe maps /api/tags reachability to a boolean."""
    with respx.mock(base_url=BASE_URL) as router:
        router.get("/api/tags").mock(
            return_value=httpx.Response(200, json={"models": []})
        )
        assert await probe_ollama(BASE_URL) is True

    with respx.mock(base_url=BASE_URL) as router:
        router.get("/api/tags").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        assert await probe_ollama(BASE_URL) is False


def test_parse_analysis_forces_llm_mode() -> None:
    """Even if the LLM says 'fallback', the mode is pinned to llm."""
    payload = _valid_analysis_payload()
    payload["analyzer_mode"] = "fallback"
    result = parse_analysis(json.dumps(payload))
    assert result.analyzer_mode is AnalyzerMode.llm


def test_parse_analysis_rejects_garbage() -> None:
    """Non-JSON text raises LLMError."""
    with pytest.raises(LLMError):
        parse_analysis("definitely not json")


def test_strip_code_fences() -> None:
    """Fence stripping handles json/plain fences and leaves plain JSON."""
    assert strip_code_fences("```json\n{}\n```") == "{}"
    assert strip_code_fences("```\n{}\n```") == "{}"
    assert strip_code_fences("{}") == "{}"


def test_pin_deterministic_risk_overrides_model_score(scan):
    """The deterministic formula always wins over the model's narrative score."""
    from src.fallback_analyzer import recompute_risk_score
    from src.llm_client import pin_deterministic_risk
    from src.models import AnalysisOutput

    bogus = AnalysisOutput(
        attack_chains=[],
        remediation={"daily": [], "authority": [], "hacker": [], "military": []},
        risk_score=0.01,
        observations=[],
        analyzer_mode="llm",
    )
    pinned = pin_deterministic_risk(bogus, scan)
    expected = round(max(recompute_risk_score(scan), scan.risk_score), 2)
    assert pinned.risk_score == expected
    assert expected > 0.01  # fixture is non-trivial, so the pin must raise it
    assert pinned.analyzer_mode == "llm"
