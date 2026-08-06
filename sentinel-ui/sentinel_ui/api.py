"""HTTP client for the sentinel-analyzer REST API and scanner invocation.

Wraps the three analyzer endpoints (``GET /health``, ``POST /analyze``,
``POST /report``) with timeouts, typed errors and pydantic validation, and
provides a subprocess helper that drives the sentinel-scanner binary.
This module is Qt-free; threading lives in :mod:`sentinel_ui.workers`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import httpx
from pydantic import ValidationError

from .models import (
    AgentReport,
    AnalysisOutput,
    HealthStatus,
    ReportResponse,
    ScanInput,
    Tier,
)

HEALTH_TIMEOUT = 5.0
ANALYZE_TIMEOUT = 180.0
REPORT_TIMEOUT = 120.0
SCANNER_TIMEOUT = 600.0
AGENT_TIMEOUT = 900.0


class AnalyzerError(Exception):
    """Base class for analyzer communication failures."""


class AnalyzerUnavailableError(AnalyzerError):
    """The analyzer service could not be reached."""


class AnalyzerValidationError(AnalyzerError):
    """The analyzer rejected the payload (HTTP 422 schema violation)."""


class AnalyzerResponseError(AnalyzerError):
    """The analyzer returned an unexpected status or malformed body."""


class ScannerError(Exception):
    """The scanner binary failed to produce a scan document."""


class AgentError(Exception):
    """The sentinel-agent subprocess failed to produce an agent report."""


class AnalyzerClient:
    """Synchronous client for the analyzer REST contract on port 8710."""

    def __init__(self, base_url: str, timeout: float = HEALTH_TIMEOUT) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout

    def health(self) -> HealthStatus:
        """Query ``GET /health`` and return the parsed status payload."""
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.get(f"{self._base_url}/health")
                response.raise_for_status()
                return HealthStatus.model_validate(response.json())
        except httpx.TransportError as exc:
            raise AnalyzerUnavailableError(f"analyzer unreachable: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            raise AnalyzerResponseError(f"health check failed: HTTP {status_code}") from exc
        except (ValidationError, json.JSONDecodeError) as exc:
            raise AnalyzerResponseError(f"malformed health payload: {exc}") from exc

    def analyze(self, scan: ScanInput, timeout: float = ANALYZE_TIMEOUT) -> AnalysisOutput:
        """Submit a scan to ``POST /analyze`` and return the analysis."""
        return self._post(
            "/analyze",
            scan.model_dump(mode="json"),
            AnalysisOutput,
            timeout,
        )

    def report(
        self,
        scan: ScanInput,
        analysis: AnalysisOutput,
        formats: list[str],
        agent: AgentReport | None = None,
        timeout: float = REPORT_TIMEOUT,
    ) -> dict[str, str]:
        """Request report artifacts from ``POST /report``.

        Returns a mapping of format name (``pdf``/``json``/``sarif``) to the
        absolute path of the generated file on the analyzer host. When an
        agent report is supplied it is forwarded verbatim so every format
        gains the Agent Investigation section.
        """
        payload: dict[str, object] = {
            "scan": scan.model_dump(mode="json"),
            "analysis": analysis.model_dump(mode="json"),
            "formats": formats,
        }
        if agent is not None:
            payload["agent"] = agent.model_dump(mode="json")
        response = self._post("/report", payload, ReportResponse, timeout)
        return dict(response.files)

    def _post[T](
        self,
        path: str,
        payload: dict[str, object],
        model: type[T],
        timeout: float,
    ) -> T:
        """POST ``payload`` to ``path`` and validate the body as ``model``."""
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(f"{self._base_url}{path}", json=payload)
                if response.status_code == 422:
                    raise AnalyzerValidationError(
                        f"schema violation on {path}: {response.text}"
                    )
                response.raise_for_status()
                return model.model_validate(response.json())
        except AnalyzerValidationError:
            raise
        except httpx.TransportError as exc:
            raise AnalyzerUnavailableError(f"analyzer unreachable: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise AnalyzerResponseError(
                f"{path} failed: HTTP {exc.response.status_code}"
            ) from exc
        except (ValidationError, json.JSONDecodeError) as exc:
            raise AnalyzerResponseError(f"malformed response from {path}: {exc}") from exc


def build_scan_command(
    binary: str,
    target: str,
    tier: Tier,
    output_path: Path,
    concurrency: int = 200,
    ports_preset: str = "top-1000",
    analyzer_url: str | None = None,
    allow_public: bool = False,
) -> list[str]:
    """Assemble the sentinel-scanner CLI invocation per the SPEC contract."""
    command = [
        binary,
        "--target",
        target,
        "--tier",
        tier.value,
        "--output",
        str(output_path),
        "--concurrency",
        str(concurrency),
        "--ports",
        ports_preset,
    ]
    if analyzer_url:
        command.extend(["--analyzer-url", analyzer_url])
    if allow_public:
        command.append("--allow-public")
    return command


def run_scan(
    binary: str,
    target: str,
    tier: Tier,
    work_dir: Path,
    concurrency: int = 200,
    ports_preset: str = "top-1000",
    analyzer_url: str | None = None,
    allow_public: bool = False,
    on_output: Callable[[str], None] | None = None,
) -> ScanInput:
    """Run the scanner binary and parse the resulting ``scan.json``.

    ``on_output`` receives scanner stdout/stderr lines as they arrive so the
    UI can stream progress without blocking. Raises :class:`ScannerError` on
    non-zero exit or when the output document is missing or invalid.
    """
    if not binary:
        raise ScannerError("no scanner binary configured")
    binary_path = Path(binary)
    if not binary_path.is_file():
        raise ScannerError(f"scanner binary not found: {binary}")

    work_dir.mkdir(parents=True, exist_ok=True)
    output_path = work_dir / "scan.json"
    command = build_scan_command(
        binary,
        target,
        tier,
        output_path,
        concurrency=concurrency,
        ports_preset=ports_preset,
        analyzer_url=analyzer_url,
        allow_public=allow_public,
    )
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as exc:
        raise ScannerError(f"failed to launch scanner: {exc}") from exc

    assert process.stdout is not None  # stdout is piped above
    try:
        for line in process.stdout:
            if on_output is not None:
                on_output(line.rstrip())
        return_code = process.wait(timeout=SCANNER_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise ScannerError("scanner exceeded time limit") from exc

    if return_code != 0:
        raise ScannerError(f"scanner exited with code {return_code}")
    if not output_path.is_file():
        raise ScannerError(f"scanner produced no output at {output_path}")

    try:
        return ScanInput.model_validate_json(output_path.read_text(encoding="utf-8"))
    except (ValidationError, OSError) as exc:
        raise ScannerError(f"invalid scan document: {exc}") from exc


def default_agent_dir() -> Path:
    """Repo-layout default: ``<repo>/sentinel-agent`` next to ``sentinel-ui``."""
    return Path(__file__).resolve().parents[2] / "sentinel-agent"


def build_agent_command(
    agent_dir: Path,
    target: str,
    tier: Tier,
    scan_file: Path,
    out_path: Path,
    transcripts_dir: Path,
    scanner_binary: str = "",
    python_exe: str | None = None,
) -> list[str]:
    """Assemble the sentinel-agent CLI invocation (``python -m src``).

    The GUI's scope dialog already gated the run, so the subprocess runs with
    ``--yes``; the agent's audit log records the attempt with the ``--yes``
    method, same as CI. ``--scan-file`` reuses the GUI's own scan.json so the
    target is never scanned twice.
    """
    command = [
        python_exe or sys.executable,
        "-m",
        "src",
        "--target",
        target,
        "--tier",
        tier.value,
        "--scan-file",
        str(scan_file),
        "--out",
        str(out_path),
        "--transcripts-dir",
        str(transcripts_dir),
        "--yes",
    ]
    if scanner_binary:
        command.extend(["--scanner", scanner_binary])
    return command


def run_agent(
    agent_dir: Path,
    target: str,
    tier: Tier,
    scan_file: Path,
    work_dir: Path,
    scanner_binary: str = "",
    on_output: Callable[[str], None] | None = None,
) -> AgentReport:
    """Run sentinel-agent against an existing scan and parse its report.

    Raises :class:`AgentError` when the package is missing, the subprocess
    fails, or the report document is absent or invalid.
    """
    agent_dir = Path(agent_dir)
    if not (agent_dir / "src" / "__main__.py").is_file():
        raise AgentError(f"sentinel-agent package not found at {agent_dir}")
    if not Path(scan_file).is_file():
        raise AgentError(f"scan document not found: {scan_file}")

    work_dir.mkdir(parents=True, exist_ok=True)
    out_path = work_dir / "agent_report.json"
    transcripts_dir = work_dir / "agent_transcripts"
    command = build_agent_command(
        agent_dir,
        target,
        tier,
        Path(scan_file),
        out_path,
        transcripts_dir,
        scanner_binary=scanner_binary,
    )
    try:
        process = subprocess.Popen(
            command,
            cwd=str(agent_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError as exc:
        raise AgentError(f"failed to launch sentinel-agent: {exc}") from exc

    assert process.stdout is not None  # stdout is piped above
    try:
        for line in process.stdout:
            if on_output is not None:
                on_output(line.rstrip())
        return_code = process.wait(timeout=AGENT_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise AgentError("sentinel-agent exceeded time limit") from exc

    if return_code != 0:
        raise AgentError(f"sentinel-agent exited with code {return_code}")
    if not out_path.is_file():
        raise AgentError(f"sentinel-agent produced no report at {out_path}")
    try:
        return AgentReport.model_validate_json(out_path.read_text(encoding="utf-8"))
    except (ValidationError, OSError) as exc:
        raise AgentError(f"invalid agent report: {exc}") from exc
