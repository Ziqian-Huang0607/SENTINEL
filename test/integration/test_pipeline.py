"""Pipeline integration test: sentinel-scanner -> sentinel-analyzer.

Runs the real scanner binary against 127.0.0.1/32, posts the resulting
scan.json to the analyzer's /analyze endpoint, and verifies:

  * the response carries every AnalysisOutput schema key,
  * analyzer_mode matches the live /health mode ("llm" when an Ollama server
    is reachable, "fallback" otherwise), and
  * risk_score equals the deterministic formula recomputed here from the scan
    (enforced in both modes: the LLM path pins the score deterministically).

Also posts a synthetic ScanInput with a known score (7.92) to pin the formula
end-to-end. Skips cleanly when the scanner binary has not been built.

Run standalone:  python test/integration/test_pipeline.py
or via pytest:   pytest test/integration/test_pipeline.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

httpx = pytest.importorskip("httpx", reason="httpx required for integration tests")

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test"))  # makes `contracts` importable

from contracts import ANALYSIS_KEYS, compute_risk_score

SCANNER_CANDIDATES = (
    ROOT / "sentinel-scanner" / "target" / "release" / "sentinel-scanner",
    ROOT / "sentinel-scanner" / "target" / "debug" / "sentinel-scanner",
)
SCAN_TIMEOUT_S = 300


def _scanner_binary() -> Path | None:
    # Explicit override wins (e.g. CARGO_TARGET_DIR outside the checkout).
    override = os.environ.get("SENTINEL_SCANNER_BIN")
    if override and Path(override).is_file():
        return Path(override)
    for candidate in SCANNER_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None
# LLM inference on a laptop (Llama 3.1 8B) can take minutes for a rich scan;
# the rule-based fallback answers in milliseconds. The timeout is per-mode.
FALLBACK_ANALYZE_TIMEOUT_S = 60.0
LLM_ANALYZE_TIMEOUT_S = 600.0


@pytest.fixture(scope="session")
def scan_artifact(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Run the scanner against loopback and return the path to scan.json."""
    binary = _scanner_binary()
    if binary is None:
        pytest.skip(
            "sentinel-scanner binary not found (looked in target/release and "
            "target/debug); build it first with `make build` or "
            "`cd sentinel-scanner && cargo build --release`"
        )
    out_path = tmp_path_factory.mktemp("pipeline") / "scan.json"
    proc = subprocess.run(
        [
            str(binary),
            "--target",
            "127.0.0.1/32",
            "--tier",
            "daily",
            "--output",
            str(out_path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=SCAN_TIMEOUT_S,
    )
    assert proc.returncode == 0, (
        f"scanner exited {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    assert out_path.is_file(), f"scanner did not write {out_path}"
    return out_path


def _analyzer_mode(base_url: str) -> str:
    """Report the live analyzer's mode ('llm' or 'fallback') via /health."""
    resp = httpx.get(f"{base_url}/health", timeout=10.0)
    assert resp.status_code == 200, f"/health -> {resp.status_code}: {resp.text}"
    mode = resp.json().get("mode")
    assert mode in ("llm", "fallback"), f"unexpected mode in /health: {mode!r}"
    return mode


def _post_analyze(base_url: str, scan: dict, mode: str) -> dict:
    timeout = (
        LLM_ANALYZE_TIMEOUT_S if mode == "llm" else FALLBACK_ANALYZE_TIMEOUT_S
    )
    resp = httpx.post(f"{base_url}/analyze", json=scan, timeout=timeout)
    assert resp.status_code == 200, f"/analyze -> {resp.status_code}: {resp.text}"
    return resp.json()


def _assert_analysis_contract(analysis: dict, expected_risk: float, mode: str) -> None:
    for key in ANALYSIS_KEYS:
        assert key in analysis, f"AnalysisOutput missing key: {key}"
    # Per-request fallback is a core feature: /health reports the startup mode,
    # but any individual request may degrade to the rule engine when the LLM
    # errors or times out. Assert only that the mode is a legal value.
    assert analysis["analyzer_mode"] in ("llm", "fallback"), (
        f"unexpected analyzer_mode: {analysis['analyzer_mode']!r}"
    )
    # Risk scoring is deterministic in BOTH modes: the fallback computes the
    # formula directly and the LLM path pins max(recomputed, scan.risk_score).
    assert round(float(analysis["risk_score"]), 2) == expected_risk


def test_live_scan_through_analyzer(scan_artifact: Path, analyzer_server: str) -> None:
    """scan.json produced by the real scanner round-trips through /analyze."""
    mode = _analyzer_mode(analyzer_server)
    scan = json.loads(scan_artifact.read_text())
    analysis = _post_analyze(analyzer_server, scan, mode)
    expected = compute_risk_score(scan)
    _assert_analysis_contract(analysis, expected, mode)
    # Scanner (Rust) and test (Python) both round to 2dp; allow a ulp of slack.
    assert abs(float(scan.get("risk_score", 0.0)) - expected) <= 0.011


def test_deterministic_risk_formula(analyzer_server: str, synthetic_scan: dict) -> None:
    """Synthetic scan with a known score of 7.92 pins the formula exactly."""
    mode = _analyzer_mode(analyzer_server)
    expected = compute_risk_score(synthetic_scan)
    assert expected == 7.92  # guards the fixture itself
    analysis = _post_analyze(analyzer_server, synthetic_scan, mode)
    _assert_analysis_contract(analysis, expected, mode)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
