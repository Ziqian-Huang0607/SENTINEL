"""API contract tests against a live SENTINEL analyzer (see conftest.py).

Covers:
  * GET /health  — shape {"status": "ok", "mode": "llm|fallback"}
  * POST /analyze — 200 + full AnalysisOutput schema on a valid ScanInput
  * POST /analyze — 422 on schema-violating garbage
  * POST /report  — end-to-end json + sarif (+ pdf when the reports service
    is running on :8711; the pdf assertions skip cleanly otherwise)

Run with: pytest test/integration/test_api.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

httpx = pytest.importorskip("httpx", reason="httpx required for integration tests")

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test"))  # makes `contracts` importable

from contracts import AnalysisOutput

REQUEST_TIMEOUT_S = 30.0
# /analyze latency depends on the analyzer mode: the rule-based fallback
# answers in milliseconds, while Llama 3.1 8B on laptop hardware takes
# minutes per inference. Probe /health and pick the budget accordingly.
FALLBACK_ANALYZE_TIMEOUT_S = 60.0
LLM_ANALYZE_TIMEOUT_S = 900.0
REPORT_TIMEOUT_S = 300.0  # PDF rendering can be slow on first run


def _analyze_timeout(analyzer_server: str) -> float:
    mode = httpx.get(f"{analyzer_server}/health", timeout=REQUEST_TIMEOUT_S).json().get("mode")
    return LLM_ANALYZE_TIMEOUT_S if mode == "llm" else FALLBACK_ANALYZE_TIMEOUT_S


def test_health_shape(analyzer_server: str) -> None:
    resp = httpx.get(f"{analyzer_server}/health", timeout=REQUEST_TIMEOUT_S)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["mode"] in ("llm", "fallback"), f"unexpected mode: {body!r}"


def test_analyze_valid_scan_returns_schema(analyzer_server: str, synthetic_scan: dict) -> None:
    resp = httpx.post(
        f"{analyzer_server}/analyze", json=synthetic_scan, timeout=_analyze_timeout(analyzer_server)
    )
    assert resp.status_code == 200, resp.text
    analysis = AnalysisOutput.model_validate(resp.json())  # raises on schema drift
    assert analysis.risk_score == pytest.approx(7.92, abs=0.011)


def test_analyze_garbage_is_422(analyzer_server: str) -> None:
    resp = httpx.post(
        f"{analyzer_server}/analyze",
        json={"definitely": "not a scan"},
        timeout=REQUEST_TIMEOUT_S,
    )
    assert resp.status_code == 422, f"expected 422, got {resp.status_code}: {resp.text}"


def _check_merged_report(doc: dict) -> None:
    """Accept nested {"scan": ..., "analysis": ...} or a merged document."""
    keys = set(doc)
    nested = {"scan", "analysis"} <= keys
    merged = {"scan_id", "attack_chains"} <= keys
    assert nested or merged, f"report JSON contains neither scan+analysis keys: {sorted(keys)}"


def test_report_end_to_end(
    analyzer_server: str,
    reports_available: bool,
    synthetic_scan: dict,
) -> None:
    analysis = httpx.post(
        f"{analyzer_server}/analyze", json=synthetic_scan, timeout=_analyze_timeout(analyzer_server)
    ).json()
    formats = ["json", "sarif"] + (["pdf"] if reports_available else [])
    resp = httpx.post(
        f"{analyzer_server}/report",
        json={"scan": synthetic_scan, "analysis": analysis, "formats": formats},
        timeout=REPORT_TIMEOUT_S,
    )
    if resp.status_code != 200 and not reports_available:
        pytest.skip("reports service not running on :8711 — analyzer cannot generate reports")
    assert resp.status_code == 200, f"/report -> {resp.status_code}: {resp.text}"
    files = resp.json().get("files", {})
    assert "json" in files, f"no json report in {files}"
    assert "sarif" in files, f"no sarif report in {files}"

    json_path = Path(files["json"])
    assert json_path.is_file(), f"missing {json_path}"
    _check_merged_report(json.loads(json_path.read_text()))

    sarif_path = Path(files["sarif"])
    assert sarif_path.is_file(), f"missing {sarif_path}"
    sarif = json.loads(sarif_path.read_text())
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert sarif["runs"], "SARIF has no runs"
    driver = sarif["runs"][0]["tool"]["driver"]
    assert "name" in driver
    assert isinstance(sarif["runs"][0].get("results", []), list)

    if reports_available:
        assert "pdf" in files, f"no pdf report in {files}"
        pdf_path = Path(files["pdf"])
        assert pdf_path.is_file(), f"missing {pdf_path}"
        blob = pdf_path.read_bytes()
        assert blob.startswith(b"%PDF"), "pdf report does not start with %PDF"
        assert len(blob) > 20 * 1024, f"pdf report suspiciously small: {len(blob)} bytes"
    else:
        print("SKIP: reports service not running on :8711 — pdf assertions skipped")
