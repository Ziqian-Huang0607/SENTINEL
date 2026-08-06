"""Agent view: AI investigation findings, per-target detail, drift and transcripts."""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QListWidget,
    QPlainTextEdit,
    QSplitter,
    QStackedLayout,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..models import AgentReport
from .results import NumericTableItem

NO_RESULTS_TEXT = "No agent investigation yet. Enable it on the New Scan page."


class AgentView(QWidget):
    """Renders an :class:`AgentReport`: status card + findings/investigations/drift tabs."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)

        heading = QLabel("Agent Investigation")
        heading.setObjectName("heading")
        outer.addWidget(heading)

        self._stack = QStackedLayout()
        outer.addLayout(self._stack, 1)

        empty = QLabel(NO_RESULTS_TEXT)
        empty.setObjectName("emptyState")
        empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._stack.addWidget(empty)

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(12)

        self._status_card = QFrame()
        self._status_card.setObjectName("card")
        card_layout = QVBoxLayout(self._status_card)
        self._model_label = QLabel()
        self._model_label.setObjectName("subheading")
        card_layout.addWidget(self._model_label)
        self._stats_label = QLabel()
        self._stats_label.setObjectName("muted")
        card_layout.addWidget(self._stats_label)
        self._observations_list = QListWidget()
        self._observations_list.setMaximumHeight(90)
        card_layout.addWidget(self._observations_list)
        body_layout.addWidget(self._status_card)

        self._tabs = QTabWidget()
        self._findings_table = self._build_findings_table()
        self._tabs.addTab(self._findings_table, "Findings")

        investigations_split = QSplitter(Qt.Orientation.Vertical)
        self._investigations_table = self._build_investigations_table()
        investigations_split.addWidget(self._investigations_table)
        self._transcript_view = QPlainTextEdit()
        self._transcript_view.setReadOnly(True)
        self._transcript_view.setPlaceholderText(
            "Select an investigation to inspect its evidence transcript."
        )
        investigations_split.addWidget(self._transcript_view)
        investigations_split.setSizes([300, 200])
        self._tabs.addTab(investigations_split, "Investigations")

        self._drift_table = self._build_drift_table()
        self._tabs.addTab(self._drift_table, "Drift")
        body_layout.addWidget(self._tabs, 1)

        self._stack.addWidget(body)

    def _build_findings_table(self) -> QTableWidget:
        """Create the findings table (one row per grounded agent finding)."""
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(
            ["Finding", "Class", "Severity", "Endpoint", "Title", "Evidence"]
        )
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSortingEnabled(True)
        return table

    def _build_investigations_table(self) -> QTableWidget:
        """Create the per-target investigations table."""
        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["Target", "Trigger", "Status", "Turns", "Summary"])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSortingEnabled(True)
        table.itemSelectionChanged.connect(self._on_investigation_selected)
        return table

    def _build_drift_table(self) -> QTableWidget:
        """Create the memory drift table."""
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["Change", "Endpoint", "Before", "After"])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSortingEnabled(True)
        return table

    def set_data(self, agent: AgentReport | None) -> None:
        """Populate the view; ``None`` restores the empty state."""
        self._stack.setCurrentIndex(1 if agent is not None else 0)
        if agent is None:
            return

        self._model_label.setText(f"Model: {agent.model}  ·  risk {agent.risk_score:.2f} / 10.00")
        by_class: dict[str, int] = {}
        for finding in agent.findings:
            by_class[finding.finding_class] = by_class.get(finding.finding_class, 0) + 1
        classes = ", ".join(f"{k}×{v}" for k, v in sorted(by_class.items())) or "none"
        self._stats_label.setText(
            f"{len(agent.investigations)} target(s) investigated · "
            f"{len(agent.findings)} finding(s) ({classes}) · "
            f"{len(agent.drift)} drift event(s)"
        )
        self._observations_list.clear()
        self._observations_list.addItems(agent.observations)
        self._observations_list.setVisible(bool(agent.observations))

        findings = self._findings_table
        findings.setSortingEnabled(False)
        findings.setRowCount(len(agent.findings))
        for row, finding in enumerate(agent.findings):
            cells = (
                QTableWidgetItem(finding.id),
                QTableWidgetItem(finding.finding_class),
                NumericTableItem(f"{finding.severity:.1f}"),
                QTableWidgetItem(finding.endpoint()),
                QTableWidgetItem(finding.title),
                QTableWidgetItem(finding.evidence_ids()),
            )
            for column, cell in enumerate(cells):
                findings.setItem(row, column, cell)
        findings.setSortingEnabled(True)

        investigations = self._investigations_table
        investigations.setSortingEnabled(False)
        investigations.setRowCount(len(agent.investigations))
        for row, inv in enumerate(agent.investigations):
            target = f"{inv.host}:{','.join(str(p) for p in inv.ports)}"
            cells = (
                QTableWidgetItem(target),
                QTableWidgetItem(inv.trigger),
                QTableWidgetItem(inv.status),
                NumericTableItem(str(inv.turns)),
                QTableWidgetItem(inv.summary),
            )
            for column, cell in enumerate(cells):
                investigations.setItem(row, column, cell)
            if inv.transcript_path:
                investigations.item(row, 0).setData(
                    Qt.ItemDataRole.UserRole, inv.transcript_path
                )
        investigations.setSortingEnabled(True)
        self._transcript_view.clear()

        drift = self._drift_table
        drift.setSortingEnabled(False)
        drift.setRowCount(len(agent.drift))
        for row, event in enumerate(agent.drift):
            cells = (
                QTableWidgetItem(event.kind),
                QTableWidgetItem(event.endpoint()),
                QTableWidgetItem(event.before),
                QTableWidgetItem(event.after),
            )
            for column, cell in enumerate(cells):
                drift.setItem(row, column, cell)
        drift.setSortingEnabled(True)

    def _on_investigation_selected(self) -> None:
        """Load the selected investigation's transcript into the details pane."""
        items = self._investigations_table.selectedItems()
        if not items:
            return
        path_text = items[0].data(Qt.ItemDataRole.UserRole)
        if not path_text:
            self._transcript_view.setPlainText("No transcript recorded for this investigation.")
            return
        path = Path(path_text)
        if not path.is_absolute():
            path = Path.cwd() / path
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            self._transcript_view.setPlainText(json.dumps(payload, indent=2))
        except (OSError, json.JSONDecodeError) as exc:
            self._transcript_view.setPlainText(f"Transcript unavailable: {exc}")
