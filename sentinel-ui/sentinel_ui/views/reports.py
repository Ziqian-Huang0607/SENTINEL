"""Reports view: generate PDF/JSON/SARIF artifacts and open saved files."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QStackedLayout,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

REPORT_FORMATS = ("pdf", "json", "sarif")
NO_REPORTS_TEXT = "No reports generated yet."
NO_SCAN_TEXT = "No scan results yet."


class ReportsView(QWidget):
    """Report generation form plus a list of saved artifacts."""

    report_requested = Signal(list)  # list[str] of formats

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        heading = QLabel("Reports")
        heading.setObjectName("heading")
        layout.addWidget(heading)

        card = QFrame()
        card.setObjectName("card")
        form = QFormLayout(card)
        formats_row = QHBoxLayout()
        self._format_checks: dict[str, QCheckBox] = {}
        for fmt in REPORT_FORMATS:
            check = QCheckBox(fmt.upper())
            check.setChecked(fmt == "json")
            self._format_checks[fmt] = check
            formats_row.addWidget(check)
        formats_row.addStretch(1)
        form.addRow("Formats", formats_row)

        self._generate_button = QPushButton("Generate Reports")
        self._generate_button.setObjectName("primaryButton")
        self._generate_button.setEnabled(False)
        self._generate_button.clicked.connect(self._on_generate)
        form.addRow("", self._generate_button)

        self._status_label = QLabel(NO_SCAN_TEXT)
        self._status_label.setObjectName("muted")
        form.addRow("", self._status_label)
        layout.addWidget(card)

        self._stack = QStackedLayout()
        empty = QLabel(NO_REPORTS_TEXT)
        empty.setObjectName("emptyState")
        self._stack.addWidget(empty)

        self._files_table = QTableWidget(0, 3)
        self._files_table.setHorizontalHeaderLabels(["Format", "Path", ""])
        self._files_table.horizontalHeader().setStretchLastSection(True)
        self._files_table.verticalHeader().setVisible(False)
        self._files_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._stack.addWidget(self._files_table)
        layout.addLayout(self._stack, 1)

    def _on_generate(self) -> None:
        """Emit the requested formats for report generation."""
        formats = [fmt for fmt, check in self._format_checks.items() if check.isChecked()]
        if formats:
            self.report_requested.emit(formats)

    def set_report_ready(self, ready: bool) -> None:
        """Enable generation only when a scan and analysis are available."""
        self._generate_button.setEnabled(ready)
        self._status_label.setText("" if ready else NO_SCAN_TEXT)

    def set_generating(self, generating: bool) -> None:
        """Disable the button while the analyzer builds the artifacts."""
        self._generate_button.setEnabled(not generating)
        self._status_label.setText("Generating reports…" if generating else "")

    def add_files(self, files: dict[str, str]) -> None:
        """Append generated artifacts to the saved-files list."""
        for fmt, path in files.items():
            row = self._files_table.rowCount()
            self._files_table.insertRow(row)
            self._files_table.setItem(row, 0, QTableWidgetItem(fmt.upper()))
            self._files_table.setItem(row, 1, QTableWidgetItem(path))
            open_button = QPushButton("Open")
            open_button.clicked.connect(
                lambda checked=False, p=path: self._open_file(p)
            )
            self._files_table.setCellWidget(row, 2, open_button)
        if files:
            self._stack.setCurrentIndex(1)
            self._status_label.setText("Reports saved.")

    def show_error(self, message: str) -> None:
        """Surface a generation failure next to the controls."""
        self._generate_button.setEnabled(True)
        self._status_label.setText(message)

    def _open_file(self, path: str) -> None:
        """Open a saved artifact with the desktop default handler."""
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(path))))
