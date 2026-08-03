#!/usr/bin/env python3
"""Hardware gate: a small llama3.1:8b analysis must complete within budget.

Sends one fixed, small analysis prompt to the local Ollama server and times
the full completion; FAILs if it exceeds --max-seconds (default 60, sized for
an 8GB M1 MacBook Air).

CI-safe: exits 0 with "SKIP" when ollama is not installed, the server cannot
be started, or the model has not been pulled.

Usage: python test/hardware/test_inference.py [--max-seconds 60] [--model llama3.1:8b]
Also collectable by pytest (uses the default budget).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
import urllib.request

DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_MAX_SECONDS = 60.0
PROMPT = (
    "You are a senior threat analyst. Given this finding — redis 6.2.7 "
    "exposed on 192.168.1.45:6379 with a -NOAUTH banner, CVSS 9.8 — reply "
    "with exactly one sentence naming the top remediation action."
)
TIMEOUT_S = 300.0


class SkipHardware(Exception):
    """Raised when the hardware gate cannot run on this machine."""


def _server_up(url: str, timeout: float = 3.0) -> bool:
    try:
        with urllib.request.urlopen(f"{url}/api/tags", timeout=timeout):
            return True
    except OSError:
        return False


def _model_available(url: str, model: str) -> bool:
    try:
        with urllib.request.urlopen(f"{url}/api/tags", timeout=5.0) as resp:
            tags = json.loads(resp.read())
    except (OSError, json.JSONDecodeError):
        return False
    names = {m.get("name", "") for m in tags.get("models", [])}
    return model in names or f"{model}:latest" in names


def ensure_ollama(url: str, model: str) -> None:
    """Verify ollama is installed, the server answers, and the model is pulled."""
    if shutil.which("ollama") is None:
        raise SkipHardware("ollama not installed (install: brew install ollama)")
    if not _server_up(url):
        try:
            subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise SkipHardware(f"could not start `ollama serve`: {exc}") from exc
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline and not _server_up(url):
            time.sleep(0.5)
        if not _server_up(url):
            raise SkipHardware(f"ollama server not reachable at {url}")
    if not _model_available(url, model):
        raise SkipHardware(f"model {model} not pulled (run: ollama pull {model})")


def time_completion_seconds(url: str, model: str) -> float:
    """Send the fixed prompt once and return wall-clock seconds to completion."""
    ensure_ollama(url, model)
    payload = json.dumps(
        {"model": model, "prompt": PROMPT, "stream": False, "options": {"num_predict": 128}}
    ).encode()
    req = urllib.request.Request(
        f"{url}/api/generate", data=payload, headers={"Content-Type": "application/json"}
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            resp.read()
    except (OSError, TimeoutError) as exc:
        raise SkipHardware(f"generation request failed: {exc}") from exc
    return time.monotonic() - started


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-seconds", type=float, default=DEFAULT_MAX_SECONDS,
                        help="completion time budget in seconds (default: 60)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="ollama model tag")
    parser.add_argument("--url", default="http://localhost:11434", help="ollama base URL")
    args = parser.parse_args()

    try:
        elapsed = time_completion_seconds(args.url, args.model)
    except SkipHardware as exc:
        print(f"SKIP: {exc}")
        return 0

    print(f"llama analysis completed in {elapsed:.1f}s (budget {args.max_seconds:.0f}s)")
    if elapsed > args.max_seconds:
        print(f"FAIL: inference took {elapsed:.1f}s, slower than {args.max_seconds:.0f}s budget")
        return 1
    print("PASS: inference budget respected")
    return 0


# --- pytest entry point (default budget) -------------------------------------

def test_inference_budget() -> None:
    import pytest

    try:
        elapsed = time_completion_seconds("http://localhost:11434", DEFAULT_MODEL)
    except SkipHardware as exc:
        pytest.skip(str(exc))
    assert elapsed <= DEFAULT_MAX_SECONDS, (
        f"inference took {elapsed:.1f}s, slower than {DEFAULT_MAX_SECONDS:.0f}s"
    )


if __name__ == "__main__":
    sys.exit(main())
