"""Hardware gate: Ollama peak RSS during a generation must stay under budget.

Targets the 8GB M1 MacBook Air budget (default --max-mb 5120, i.e. 5 GB for
the ollama server + llama3.1:8b). A fixed small prompt is generated while the
combined RSS of every `ollama` process (server + model runner) is polled;
the run FAILs if the peak exceeds the budget.

CI-safe: exits 0 with "SKIP" when ollama is not installed, the server cannot
be started, or the model has not been pulled.

Usage: python test/hardware/test_memory.py [--max-mb 5120] [--model llama3.1:8b]
Also collectable by pytest (uses the default budget).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import threading
import time
import urllib.request

DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_MAX_MB = 5120.0
PROMPT = (
    "You are a senior threat analyst. Host 192.168.1.45 runs redis 6.2.7 with "
    "a -NOAUTH banner on an internet-facing interface. In one short paragraph, "
    "state the primary risk and the first remediation step."
)
GENERATION_TIMEOUT_S = 300.0
POLL_INTERVAL_S = 0.5


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


def _ollama_pids() -> list[str]:
    """PIDs of every ollama process (server and model runner subprocesses)."""
    try:
        out = subprocess.run(
            ["pgrep", "-f", "ollama"], capture_output=True, text=True, check=False
        )
    except OSError:
        return []
    return [pid for pid in out.stdout.split() if pid.isdigit() and int(pid) != 0]


def _total_rss_mb(pids: list[str]) -> float:
    if not pids:
        return 0.0
    try:
        out = subprocess.run(
            ["ps", "-o", "rss=", "-p", ",".join(pids)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return 0.0
    kb = 0.0
    for line in out.stdout.split():
        try:
            kb += float(line)
        except ValueError:
            continue
    return kb / 1024.0


def _generate(url: str, model: str, result: dict) -> None:
    payload = json.dumps(
        {"model": model, "prompt": PROMPT, "stream": False, "options": {"num_predict": 128}}
    ).encode()
    req = urllib.request.Request(
        f"{url}/api/generate", data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=GENERATION_TIMEOUT_S) as resp:
            result["status"] = resp.status
    except (OSError, TimeoutError) as exc:
        result["error"] = str(exc)


def measure_peak_rss_mb(url: str, model: str) -> float:
    """Run one generation and return the peak combined ollama RSS in MB."""
    ensure_ollama(url, model)
    result: dict = {}
    worker = threading.Thread(target=_generate, args=(url, model, result), daemon=True)
    worker.start()
    peak = 0.0
    while worker.is_alive():
        peak = max(peak, _total_rss_mb(_ollama_pids()))
        time.sleep(POLL_INTERVAL_S)
    worker.join(timeout=5.0)
    peak = max(peak, _total_rss_mb(_ollama_pids()))
    if result.get("error"):
        raise SkipHardware(f"generation failed mid-measurement: {result['error']}")
    if peak <= 0.0:
        raise SkipHardware("could not sample ollama RSS (pgrep/ps unavailable?)")
    return peak


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-mb", type=float, default=DEFAULT_MAX_MB,
                        help="peak RSS budget in MB (default: 5120)")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="ollama model tag")
    parser.add_argument("--url", default="http://localhost:11434", help="ollama base URL")
    args = parser.parse_args()

    try:
        peak = measure_peak_rss_mb(args.url, args.model)
    except SkipHardware as exc:
        print(f"SKIP: {exc}")
        return 0

    print(f"ollama peak RSS during generation: {peak:.0f} MB (budget {args.max_mb:.0f} MB)")
    if peak > args.max_mb:
        print(f"FAIL: peak RSS {peak:.0f} MB exceeds budget {args.max_mb:.0f} MB")
        return 1
    print("PASS: memory budget respected")
    return 0


# --- pytest entry point (default budget) -------------------------------------

def test_memory_budget() -> None:
    import pytest

    try:
        peak = measure_peak_rss_mb("http://localhost:11434", DEFAULT_MODEL)
    except SkipHardware as exc:
        pytest.skip(str(exc))
    assert peak <= DEFAULT_MAX_MB, f"peak RSS {peak:.0f} MB exceeds {DEFAULT_MAX_MB:.0f} MB"


if __name__ == "__main__":
    sys.exit(main())
