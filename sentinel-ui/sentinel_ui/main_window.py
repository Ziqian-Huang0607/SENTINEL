"""Main window: sidebar navigation, stacked pages and worker orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .models import APP_NAME, AnalysisOutput, HealthStatus, ScanInput, ScanRequest
from .views.dashboard import STATUS_CAPTIONS, DashboardView
from .views.new_scan import NewScanView
from .views.reports import ReportsView
from .views.results import ResultsView
from .workers import AnalyzeWorker, HealthWorker, ReportWorker, ScanWorker

NAV_ITEMS = ("Dashboard", "New Scan", "Results", "Reports")


class MainWindow(QMainWindow):
    """SENTINEL ops-center shell wiring views to background workers."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1100, 700)

        self._scan: ScanInput | None = None
        self._analysis: AnalysisOutput | None = None
        self._last_request: ScanRequest | None = None
        self._workers: list[object] = []

        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_sidebar())
        self._pages = QStackedWidget()
        self._dashboard = DashboardView()
        self._new_scan = NewScanView()
        self._results = ResultsView()
        self._reports = ReportsView()
        for page in (self._dashboard, self._new_scan, self._results, self._reports):
            self._pages.addWidget(page)
        root.addWidget(self._pages, 1)
        self.setCentralWidget(central)

        self._status_mode = QLabel("Analyzer: offline")
        self.statusBar().addPermanentWidget(self._status_mode)
        self.statusBar().showMessage("Ready")

        self._new_scan.scan_requested.connect(self._start_scan)
        self._reports.report_requested.connect(self._start_report)

        QTimer.singleShot(0, self._probe_analyzer)

    def _build_sidebar(self) -> QFrame:
        """Create the left navigation rail with exclusive page buttons."""
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(200)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 24, 0, 0)
        layout.setSpacing(2)

        self._nav_group = QButtonGroup(sidebar)
        self._nav_group.setExclusive(True)
        for index, name in enumerate(NAV_ITEMS):
            button = QToolButton()
            button.setObjectName("navButton")
            button.setText(name)
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, i=index: self._pages.setCurrentIndex(i))
            self._nav_group.addButton(button, index)
            layout.addWidget(button)
        layout.addStretch(1)
        self._nav_group.button(0).setChecked(True)
        return sidebar

    def _track_worker(self, worker: object) -> None:
        """Keep a worker alive until it finishes, then release it."""
        self._workers.append(worker)
        worker.finished.connect(lambda: self._release_worker(worker))
        worker.start()

    def _release_worker(self, worker: object) -> None:
        """Drop and schedule a finished worker for deletion."""
        if worker in self._workers:
            self._workers.remove(worker)
        worker.deleteLater()

    def _probe_analyzer(self) -> None:
        """Refresh the analyzer status indicator via GET /health."""
        url = (
            self._last_request.analyzer_url
            if self._last_request is not None
            else self._new_scan.default_analyzer_url()
        )
        worker = HealthWorker(url, self)
        worker.succeeded.connect(self._on_health)
        worker.failed.connect(self._on_health_failed)
        self._track_worker(worker)

    def _on_health(self, status: HealthStatus) -> None:
        """Apply a successful health probe to dashboard and status bar."""
        self._dashboard.set_analyzer_status(status.mode.value)
        self._status_mode.setText(f"Analyzer: {STATUS_CAPTIONS[status.mode.value]}")

    def _on_health_failed(self, message: str) -> None:
        """Mark the analyzer offline when the probe fails."""
        self._dashboard.set_analyzer_status("offline")
        self._status_mode.setText("Analyzer: offline")
        self.statusBar().showMessage(message, 5000)

    def _start_scan(self, request: ScanRequest) -> None:
        """Launch the scanner worker for a confirmed scan request."""
        self._last_request = request
        self._new_scan.set_scanning(True)
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        work_dir = Path.home() / ".sentinel" / "scans" / stamp
        worker = ScanWorker(request, work_dir, self)
        worker.progressed.connect(
            lambda line: self.statusBar().showMessage(line, 3000)
        )
        worker.succeeded.connect(self._on_scan_finished)
        worker.failed.connect(self._on_scan_failed)
        self.statusBar().showMessage(f"Scanning {request.target} …")
        self._track_worker(worker)

    def _on_scan_finished(self, scan: ScanInput) -> None:
        """Store the scan and immediately submit it for analysis."""
        self._scan = scan
        self._analysis = None
        self._dashboard.update_state(scan, None)
        self._results.set_data(scan, None)
        self.statusBar().showMessage("Scan complete — analyzing …")
        request = self._last_request
        analyzer_url = request.analyzer_url if request is not None else ""
        worker = AnalyzeWorker(analyzer_url, scan, self)
        worker.succeeded.connect(self._on_analysis_finished)
        worker.failed.connect(self._on_analysis_failed)
        self._track_worker(worker)

    def _on_scan_failed(self, message: str) -> None:
        """Report a scanner failure and re-enable the launch controls."""
        self._new_scan.set_scanning(False)
        self.statusBar().showMessage("Scan failed", 5000)
        QMessageBox.warning(self, "Scan Failed", message)

    def _on_analysis_finished(self, analysis: AnalysisOutput) -> None:
        """Apply the analysis to all views and move to the results page."""
        self._analysis = analysis
        self._new_scan.set_scanning(False)
        self._dashboard.update_state(self._scan, analysis)
        self._results.set_data(self._scan, analysis)
        self._reports.set_report_ready(True)
        self._dashboard.set_analyzer_status(analysis.analyzer_mode.value)
        self._status_mode.setText(
            f"Analyzer: {STATUS_CAPTIONS[analysis.analyzer_mode.value]}"
        )
        self._pages.setCurrentWidget(self._results)
        self._nav_group.button(2).setChecked(True)
        self.statusBar().showMessage("Analysis complete", 5000)

    def _on_analysis_failed(self, message: str) -> None:
        """Report an analyzer failure; scan results remain available."""
        self._new_scan.set_scanning(False)
        self.statusBar().showMessage("Analysis failed", 5000)
        QMessageBox.warning(self, "Analysis Failed", message)

    def _start_report(self, formats: list[str]) -> None:
        """Request report artifacts for the current scan and analysis."""
        if self._scan is None or self._analysis is None:
            self._reports.show_error("No scan results yet.")
            return
        self._reports.set_generating(True)
        analyzer_url = (
            self._last_request.analyzer_url if self._last_request is not None else ""
        )
        worker = ReportWorker(analyzer_url, self._scan, self._analysis, formats, self)
        worker.succeeded.connect(self._on_report_finished)
        worker.failed.connect(self._reports.show_error)
        self._track_worker(worker)

    def _on_report_finished(self, files: dict[str, str]) -> None:
        """List the artifacts returned by the analyzer."""
        self._reports.add_files(files)
        self.statusBar().showMessage("Reports generated", 5000)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802 - Qt override
        """Stop background workers before the window closes."""
        for worker in list(self._workers):
            worker.terminate()
        for worker in list(self._workers):
            worker.wait(3000)
        super().closeEvent(event)
