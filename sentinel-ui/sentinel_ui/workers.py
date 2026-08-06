"""QThread workers that keep blocking I/O off the UI thread.

Each worker performs one pipeline step (health probe, scan, analyze, report)
and reports back through Qt signals, so the ops-center UI never blocks on
network or subprocess work.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread, Signal

from .api import (
    AgentError,
    AnalyzerClient,
    AnalyzerError,
    ScannerError,
    default_agent_dir,
    run_agent,
    run_scan,
)
from .models import AgentReport, AnalysisOutput, HealthStatus, ScanInput, ScanRequest


class HealthWorker(QThread):
    """Probe the analyzer ``GET /health`` endpoint."""

    succeeded = Signal(object)  # HealthStatus
    failed = Signal(str)

    def __init__(self, analyzer_url: str, parent: object | None = None) -> None:
        super().__init__(parent)
        self._analyzer_url = analyzer_url

    def run(self) -> None:
        """Execute the health probe and emit the outcome."""
        try:
            status: HealthStatus = AnalyzerClient(self._analyzer_url).health()
        except AnalyzerError as exc:
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(status)


class ScanWorker(QThread):
    """Run the scanner binary and load the resulting scan document."""

    progressed = Signal(str)
    succeeded = Signal(object)  # ScanInput
    failed = Signal(str)

    def __init__(
        self,
        request: ScanRequest,
        work_dir: Path,
        parent: object | None = None,
    ) -> None:
        super().__init__(parent)
        self._request = request
        self._work_dir = work_dir

    def run(self) -> None:
        """Execute the scanner subprocess and emit the parsed scan."""
        try:
            scan: ScanInput = run_scan(
                binary=self._request.scanner_binary,
                target=self._request.target,
                tier=self._request.tier,
                work_dir=self._work_dir,
                concurrency=self._request.concurrency,
                ports_preset=self._request.ports_preset,
                analyzer_url=self._request.analyzer_url,
                allow_public=self._request.allow_public,
                on_output=self.progressed.emit,
            )
        except ScannerError as exc:
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(scan)


class AnalyzeWorker(QThread):
    """Submit a scan document to the analyzer ``POST /analyze`` endpoint."""

    succeeded = Signal(object)  # AnalysisOutput
    failed = Signal(str)

    def __init__(
        self,
        analyzer_url: str,
        scan: ScanInput,
        parent: object | None = None,
    ) -> None:
        super().__init__(parent)
        self._analyzer_url = analyzer_url
        self._scan = scan

    def run(self) -> None:
        """POST the scan and emit the validated analysis."""
        try:
            analysis: AnalysisOutput = AnalyzerClient(self._analyzer_url).analyze(self._scan)
        except AnalyzerError as exc:
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(analysis)


class AgentWorker(QThread):
    """Run sentinel-agent against the current scan document."""

    progressed = Signal(str)
    succeeded = Signal(object)  # AgentReport
    failed = Signal(str)

    def __init__(
        self,
        request: ScanRequest,
        scan_file: Path,
        work_dir: Path,
        parent: object | None = None,
    ) -> None:
        super().__init__(parent)
        self._request = request
        self._scan_file = scan_file
        self._work_dir = work_dir

    def run(self) -> None:
        """Execute the agent subprocess and emit the parsed agent report."""
        try:
            report: AgentReport = run_agent(
                agent_dir=Path(self._request.agent_dir)
                if self._request.agent_dir
                else default_agent_dir(),
                target=self._request.target,
                tier=self._request.tier,
                scan_file=self._scan_file,
                work_dir=self._work_dir,
                scanner_binary=self._request.scanner_binary,
                on_output=self.progressed.emit,
            )
        except AgentError as exc:
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(report)


class ReportWorker(QThread):
    """Request report artifacts from the analyzer ``POST /report`` endpoint."""

    succeeded = Signal(object)  # dict[str, str]
    failed = Signal(str)

    def __init__(
        self,
        analyzer_url: str,
        scan: ScanInput,
        analysis: AnalysisOutput,
        formats: list[str],
        agent: AgentReport | None = None,
        parent: object | None = None,
    ) -> None:
        super().__init__(parent)
        self._analyzer_url = analyzer_url
        self._scan = scan
        self._analysis = analysis
        self._formats = formats
        self._agent = agent

    def run(self) -> None:
        """POST the report request and emit the format-to-path mapping."""
        try:
            files = AnalyzerClient(self._analyzer_url).report(
                self._scan, self._analysis, self._formats, agent=self._agent
            )
        except AnalyzerError as exc:
            self.failed.emit(str(exc))
            return
        self.succeeded.emit(files)
