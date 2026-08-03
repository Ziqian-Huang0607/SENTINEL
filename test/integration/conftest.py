"""Shared fixtures for the SENTINEL integration suites.

The `analyzer_server` fixture reuses an already-running analyzer on :8710
(e.g. one started by `docker compose up -d analyzer reports`) or, when the
port is free, starts a local uvicorn subprocess in forced-fallback mode:

  * SENTINEL_FORCE_FALLBACK=1 is exported (honored by the analyzer if
    supported), and
  * OLLAMA_URL is pointed at a dead port so the analyzer's auto-detection
    falls back to the deterministic rule-based engine either way.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

httpx = pytest.importorskip("httpx", reason="httpx required for integration tests")

ROOT = Path(__file__).resolve().parents[2]
ANALYZER_DIR = ROOT / "sentinel-analyzer"
sys.path.insert(0, str(ROOT / "test"))  # makes `contracts` importable

from contracts import sample_scan  # noqa: E402

ANALYZER_PORT = 8710
REPORTS_PORT = 8711
HEALTH_TIMEOUT_S = 90.0


def _analyzer_app_import() -> str:
    """Resolve the FastAPI ASGI import string for the analyzer checkout."""
    if (ANALYZER_DIR / "main.py").is_file():
        return "main:app"
    if (ANALYZER_DIR / "app" / "main.py").is_file():
        return "app.main:app"
    pytest.skip(f"cannot locate FastAPI app under {ANALYZER_DIR} (expected main.py or app/main.py)")
    raise AssertionError("unreachable")


def _healthy(url: str) -> bool:
    try:
        return httpx.get(url, timeout=2.0).status_code == 200
    except httpx.HTTPError:
        return False


def _wait_for_health(url: str, proc: subprocess.Popen | None, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc is not None and proc.poll() is not None:
            return False  # server process died
        if _healthy(url):
            return True
        time.sleep(0.5)
    return False


@pytest.fixture(scope="session")
def analyzer_server() -> Iterator[str]:
    """Base URL of a live analyzer (reused on :8710 or started locally)."""
    base_url = f"http://127.0.0.1:{ANALYZER_PORT}"
    if _healthy(f"{base_url}/health"):
        yield base_url  # provided externally (e.g. docker compose)
        return

    env = os.environ.copy()
    env["SENTINEL_FORCE_FALLBACK"] = "1"
    env["OLLAMA_URL"] = "http://127.0.0.1:9"  # dead port -> deterministic fallback
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            _analyzer_app_import(),
            "--host",
            "127.0.0.1",
            "--port",
            str(ANALYZER_PORT),
        ],
        cwd=ANALYZER_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        if not _wait_for_health(f"{base_url}/health", proc, HEALTH_TIMEOUT_S):
            output = ""
            if proc.stdout is not None:
                try:
                    output = proc.stdout.read() or ""
                except OSError:
                    output = ""
            pytest.fail(f"analyzer failed to start on :{ANALYZER_PORT}\n--- output ---\n{output}")
        yield base_url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="session")
def reports_available() -> bool:
    """True when the reports service answers on :8711."""
    return _healthy(f"http://127.0.0.1:{REPORTS_PORT}/health")


@pytest.fixture(scope="session")
def synthetic_scan() -> dict:
    """Fully valid ScanInput payload with a known deterministic risk score."""
    return sample_scan()
