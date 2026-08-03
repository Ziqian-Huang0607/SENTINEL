"""Results view: hosts, vulnerabilities, attack chains and remediation tabs."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QStackedLayout,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..models import AnalysisOutput, AttackChain, ScanInput, Tier
from ..validators import cvss_severity

NO_RESULTS_TEXT = "No scan results yet."

SEVERITY_COLORS = {
    "critical": QColor("#EF4444"),
    "high": QColor("#F59E0B"),
    "medium": QColor("#38BDF8"),
    "low": QColor("#34D399"),
    "none": QColor("#1F2937"),
}


class NumericTableItem(QTableWidgetItem):
    """Table item that sorts numerically instead of lexicographically."""

    def __lt__(self, other: QTableWidgetItem) -> bool:
        """Compare cell contents as floats, falling back to text."""
        try:
            return float(self.text()) < float(other.text())
        except ValueError:
            return super().__lt__(other)


class AttackChainCard(QFrame):
    """Card rendering one attack chain with metrics and priority badge."""

    def __init__(self, chain: AttackChain, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        top = QHBoxLayout()
        badge = QLabel(f"P{chain.priority}")
        badge.setObjectName("priorityBadge")
        badge.setProperty("level", str(min(chain.priority, 3)))
        top.addWidget(badge)

        technique = QLabel(chain.mitre_technique or "MITRE ATT&CK")
        technique.setObjectName("subheading")
        top.addWidget(technique)

        path = QLabel("  →  ".join(chain.path))
        path.setObjectName("muted")
        top.addWidget(path, 1)
        layout.addLayout(top)

        if chain.description:
            description = QLabel(chain.description)
            description.setWordWrap(True)
            layout.addWidget(description)

        bars = QHBoxLayout()
        for caption, value, bar_name in (
            ("Confidence", chain.confidence, "confidenceBar"),
            ("Impact", chain.impact, "impactBar"),
        ):
            label = QLabel(f"{caption} {value:.0%}")
            label.setObjectName("muted")
            bars.addWidget(label)
            bar = QProgressBar()
            bar.setObjectName(bar_name)
            bar.setRange(0, 100)
            bar.setValue(round(value * 100))
            bar.setTextVisible(False)
            bars.addWidget(bar, 1)
        layout.addLayout(bars)


class ResultsView(QWidget):
    """Tabbed inspection of the current scan and analysis documents."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 24, 24, 24)

        heading = QLabel("Results")
        heading.setObjectName("heading")
        outer.addWidget(heading)

        self._stack = QStackedLayout()
        outer.addLayout(self._stack, 1)

        empty = QLabel(NO_RESULTS_TEXT)
        empty.setObjectName("emptyState")
        empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._stack.addWidget(empty)

        self._tabs = QTabWidget()
        self._hosts_table = self._build_hosts_table()
        self._vuln_table = self._build_vuln_table()
        self._chains_list = QListWidget()
        self._remediation_tabs = self._build_remediation_tabs()
        self._tabs.addTab(self._hosts_table, "Hosts")
        self._tabs.addTab(self._vuln_table, "Vulnerabilities")
        self._tabs.addTab(self._chains_list, "Attack Chains")
        self._tabs.addTab(self._remediation_tabs, "Remediation")
        self._stack.addWidget(self._tabs)

    def _build_hosts_table(self) -> QTableWidget:
        """Create the hosts table with the SPEC column set."""
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(
            ["IP", "Hostname", "OS", "Trust Zone", "Criticality", "Open Ports"]
        )
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSortingEnabled(True)
        return table

    def _build_vuln_table(self) -> QTableWidget:
        """Create the vulnerabilities table with sortable metrics."""
        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["CVE", "CVSS", "EPSS", "Host:Port", "Severity"])
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSortingEnabled(True)
        return table

    def _build_remediation_tabs(self) -> QTabWidget:
        """Create one checklist sub-tab per security tier."""
        tabs = QTabWidget()
        self._remediation_lists: dict[Tier, QListWidget] = {}
        for tier in Tier:
            checklist = QListWidget()
            self._remediation_lists[tier] = checklist
            tabs.addTab(checklist, tier.value.capitalize())
        return tabs

    def set_data(
        self,
        scan: ScanInput | None,
        analysis: AnalysisOutput | None,
    ) -> None:
        """Populate every tab; ``None`` restores the empty state."""
        self._stack.setCurrentIndex(1 if scan is not None else 0)
        if scan is None:
            return
        self._populate_hosts(scan)
        self._populate_vulnerabilities(scan)
        self._populate_chains(analysis)
        self._populate_remediation(scan, analysis)

    def _populate_hosts(self, scan: ScanInput) -> None:
        """Fill the hosts table from the scan document."""
        table = self._hosts_table
        table.setSortingEnabled(False)
        table.setRowCount(len(scan.hosts))
        for row, host in enumerate(scan.hosts):
            open_ports = ", ".join(str(p.port) for p in host.open_ports())
            cells = (
                QTableWidgetItem(host.ip),
                QTableWidgetItem(host.hostname),
                QTableWidgetItem(host.os_guess),
                QTableWidgetItem(host.trust_zone.value),
                QTableWidgetItem(host.criticality.value),
                QTableWidgetItem(open_ports),
            )
            for column, cell in enumerate(cells):
                table.setItem(row, column, cell)
        table.setSortingEnabled(True)

    def _populate_vulnerabilities(self, scan: ScanInput) -> None:
        """Fill the vulnerabilities table with color-coded severities."""
        table = self._vuln_table
        table.setSortingEnabled(False)
        table.setRowCount(len(scan.vulnerabilities))
        for row, vuln in enumerate(scan.vulnerabilities):
            severity = cvss_severity(vuln.cvss)
            severity_item = QTableWidgetItem(severity.upper())
            severity_item.setBackground(SEVERITY_COLORS[severity])
            severity_item.setForeground(QColor("#0A0E14"))
            cells = (
                QTableWidgetItem(vuln.cve_id),
                NumericTableItem(f"{vuln.cvss:.1f}"),
                NumericTableItem(f"{vuln.epss:.2f}"),
                QTableWidgetItem(f"{vuln.host}:{vuln.port}"),
                severity_item,
            )
            for column, cell in enumerate(cells):
                table.setItem(row, column, cell)
        table.setSortingEnabled(True)

    def _populate_chains(self, analysis: AnalysisOutput | None) -> None:
        """Render attack chain cards into the chains list."""
        self._chains_list.clear()
        if analysis is None:
            return
        for chain in sorted(analysis.attack_chains, key=lambda c: c.priority):
            item = QListWidgetItem(self._chains_list)
            card = AttackChainCard(chain)
            item.setSizeHint(card.sizeHint())
            self._chains_list.addItem(item)
            self._chains_list.setItemWidget(item, card)

    def _populate_remediation(
        self,
        scan: ScanInput,
        analysis: AnalysisOutput | None,
    ) -> None:
        """Rebuild tier checklists from the analysis remediation library."""
        for tier, checklist in self._remediation_lists.items():
            checklist.clear()
            controls = analysis.remediation.for_tier(tier) if analysis is not None else []
            for control in controls:
                item = QListWidgetItem(control)
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Unchecked)
                checklist.addItem(item)
        if analysis is not None:
            index = list(Tier).index(scan.tier)
            self._remediation_tabs.setCurrentIndex(index)
