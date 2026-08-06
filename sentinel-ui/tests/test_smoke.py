"""Offscreen smoke tests for the SENTINEL desktop GUI.

Pure-logic tests (validators, contract models) always run. Qt tests are
skipped gracefully when PySide6 is not importable in the environment.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    import PySide6  # noqa: F401

    HAS_PYSIDE = True
except ImportError:
    HAS_PYSIDE = False

requires_pyside = pytest.mark.skipif(not HAS_PYSIDE, reason="PySide6 not available")

from sentinel_ui.models import AgentReport, AnalysisOutput, ScanInput, Tier
from sentinel_ui.validators import validate_confirm, validate_target

SPEC_SCAN = {
    "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "target": "192.168.1.0/24",
    "tier": "daily",
    "started_at": "2025-01-01T10:00:00Z",
    "finished_at": "2025-01-01T10:00:52Z",
    "hosts": [
        {
            "ip": "192.168.1.45",
            "hostname": "db01",
            "mac": "aa:bb:cc:dd:ee:ff",
            "os_guess": "Linux 5.x",
            "trust_zone": "internal",
            "criticality": "dc",
            "ports": [
                {
                    "port": 6379,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "redis",
                    "version": "6.2.7",
                    "banner": "-NOAUTH",
                }
            ],
        }
    ],
    "vulnerabilities": [
        {
            "cve_id": "CVE-2024-21667",
            "cvss": 9.8,
            "epss": 0.85,
            "host": "192.168.1.45",
            "port": 6379,
            "summary": "Unauthenticated Redis instance exposed.",
        }
    ],
    "risk_score": 8.97,
}

SPEC_ANALYSIS = {
    "attack_chains": [
        {
            "path": ["192.168.1.45:6379"],
            "description": "Unauthenticated Redis allows data theft and lateral movement.",
            "mitre_technique": "T1110",
            "confidence": 0.85,
            "impact": 0.92,
            "priority": 1,
        }
    ],
    "remediation": {
        "daily": ["Require Redis authentication."],
        "authority": ["Segment Redis into a restricted VLAN."],
        "hacker": ["Enable TLS and rotate credentials."],
        "military": ["Airgap the data tier."],
    },
    "risk_score": 8.97,
    "observations": ["Single exposed data store."],
    "analyzer_mode": "fallback",
}

SPEC_AGENT = {
    "agent_version": "0.1.0",
    "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "target": "192.168.1.0/24",
    "tier": "daily",
    "started_at": "2025-01-01T10:01:00Z",
    "finished_at": "2025-01-01T10:02:30Z",
    "model": "ollama:llama3.1:8b",
    "investigations": [
        {
            "host": "192.168.1.1",
            "ports": [80],
            "trigger": "gateway",
            "status": "concluded",
            "turns": 4,
            "summary": "Router admin interface answered with a TP-Link login page.",
            "findings": [],
            "transcript_path": "/tmp/agent_transcripts/192.168.1.1_80.json",
        }
    ],
    "findings": [
        {
            "id": "AGENT-DEFAULT-PANEL-1",
            "finding_class": "DEFAULT-PANEL",
            "host": "192.168.1.1",
            "port": 80,
            "severity": 7.0,
            "title": "Default administrative panel exposed",
            "detail": "TP-Link login page answered GET / with 200.",
            "evidence": [
                {
                    "id": "E1",
                    "tool": "http_get",
                    "args": {"port": 80},
                    "excerpt": "...",
                    "ts": "2025-01-01T10:01:10Z",
                },
                {
                    "id": "E3",
                    "tool": "default_panel_check",
                    "args": {},
                    "excerpt": "...",
                    "ts": "2025-01-01T10:01:40Z",
                },
            ],
            "confidence": 0.9,
        }
    ],
    "drift": [
        {
            "kind": "NEW_PORT",
            "host": "192.168.1.45",
            "port": 6379,
            "before": "",
            "after": "open/redis",
            "ts": "2025-01-01T10:02:00Z",
        }
    ],
    "risk_score": 4.9,
    "observations": ["Ollama unavailable; deterministic playbook ran."],
}


# ---------- Pure validation logic (no Qt required) ----------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("CONFIRM", True),
        ("confirm", False),
        ("Confirm", False),
        (" CONFIRM", False),
        ("CONFIRM ", False),
        ("CONFIRM!", False),
        ("", False),
    ],
)
def test_validate_confirm(text: str, expected: bool) -> None:
    """The scope gate accepts only the exact phrase CONFIRM."""
    assert validate_confirm(text) is expected


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.168.1.0/24", True),
        ("10.0.0.0/8", True),
        ("192.168.1.45", True),
        ("2001:db8::/64", True),
        ("192.168.1.0/33", False),
        ("999.1.1.1", False),
        ("192.168.1.0/24/extra", False),
        ("not-a-network", False),
        ("", False),
    ],
)
def test_validate_target(target: str, expected: bool) -> None:
    """Targets must parse as a CIDR range or single IP address."""
    assert validate_target(target) is expected


def test_models_accept_spec_contract() -> None:
    """The pydantic models round-trip the SPEC example documents."""
    scan = ScanInput.model_validate(SPEC_SCAN)
    assert scan.hosts[0].open_ports()[0].port == 6379
    assert scan.tier is Tier.DAILY
    analysis = AnalysisOutput.model_validate(SPEC_ANALYSIS)
    assert analysis.attack_chains[0].mitre_technique == "T1110"
    assert analysis.remediation.for_tier(Tier.HACKER) == ["Enable TLS and rotate credentials."]


def test_agent_models_accept_spec_contract() -> None:
    """The agent models round-trip an agent_report.json document."""
    agent = AgentReport.model_validate(SPEC_AGENT)
    assert agent.model == "ollama:llama3.1:8b"
    finding = agent.findings[0]
    assert finding.finding_class == "DEFAULT-PANEL"
    assert finding.endpoint() == "192.168.1.1:80"
    assert finding.evidence_ids() == "E1, E3"
    assert agent.drift[0].endpoint() == "192.168.1.45:6379"


def test_build_agent_command_uses_scan_file() -> None:
    """The agent invocation reuses the GUI's scan.json and runs gated (--yes)."""
    from pathlib import Path

    from sentinel_ui.api import build_agent_command

    command = build_agent_command(
        Path("/repo/sentinel-agent"),
        "192.168.1.0/24",
        Tier.DAILY,
        Path("/work/scan.json"),
        Path("/work/agent_report.json"),
        Path("/work/agent_transcripts"),
        scanner_binary="/bin/sentinel-scanner",
        python_exe="/usr/bin/python3",
    )
    assert command[:3] == ["/usr/bin/python3", "-m", "src"]
    assert "--scan-file" in command
    assert command[command.index("--scan-file") + 1] == "/work/scan.json"
    assert "--yes" in command
    assert "--scanner" in command


def test_report_request_includes_agent_document() -> None:
    """AnalyzerClient.report forwards the agent doc verbatim when present."""
    import httpx
    import respx

    from sentinel_ui.api import AnalyzerClient

    scan = ScanInput.model_validate(SPEC_SCAN)
    analysis = AnalysisOutput.model_validate(SPEC_ANALYSIS)
    agent = AgentReport.model_validate(SPEC_AGENT)

    with respx.mock(base_url="http://analyzer.test") as router:
        route = router.post("/report").mock(
            return_value=httpx.Response(200, json={"files": {"json": "/out/r.json"}})
        )
        files = AnalyzerClient("http://analyzer.test").report(
            scan, analysis, ["json"], agent=agent
        )

    assert files == {"json": "/out/r.json"}
    import json as _json

    forwarded = _json.loads(route.calls[0].request.content)
    assert forwarded["agent"]["scan_id"] == agent.scan_id
    assert forwarded["agent"]["findings"][0]["id"] == "AGENT-DEFAULT-PANEL-1"


def test_report_request_omits_agent_when_absent() -> None:
    """Without an agent report the /report body has no agent key at all."""
    import httpx
    import respx

    from sentinel_ui.api import AnalyzerClient

    scan = ScanInput.model_validate(SPEC_SCAN)
    analysis = AnalysisOutput.model_validate(SPEC_ANALYSIS)

    with respx.mock(base_url="http://analyzer.test") as router:
        route = router.post("/report").mock(
            return_value=httpx.Response(200, json={"files": {}})
        )
        AnalyzerClient("http://analyzer.test").report(scan, analysis, ["json"])

    import json as _json

    assert "agent" not in _json.loads(route.calls[0].request.content)


# ---------- Qt smoke tests (skipped without PySide6) ----------


@pytest.fixture(scope="module")
def qapp():
    """Provide a single offscreen QApplication for all Qt tests."""
    from sentinel_ui.app import create_application

    app = create_application([])
    yield app


@requires_pyside
def test_application_instantiates(qapp) -> None:
    """The QApplication is created with identity, theme and icon."""
    assert qapp.applicationName() == "SENTINEL"
    assert qapp.styleSheet()
    assert not qapp.windowIcon().isNull()


@requires_pyside
def test_main_window_shows(qapp) -> None:
    """The main window shows with sidebar navigation and five pages."""
    from sentinel_ui.main_window import NAV_ITEMS, MainWindow

    window = MainWindow()
    window.show()
    assert window.isVisible()
    assert window.windowTitle() == "SENTINEL"
    assert NAV_ITEMS == ("Dashboard", "New Scan", "Results", "Agent", "Reports")
    assert window._pages.count() == 5
    window.close()


@requires_pyside
def test_all_views_construct(qapp) -> None:
    """Every view widget constructs and exposes its empty state."""
    from sentinel_ui.views.agent import AgentView
    from sentinel_ui.views.dashboard import DashboardView
    from sentinel_ui.views.new_scan import NewScanView
    from sentinel_ui.views.reports import ReportsView
    from sentinel_ui.views.results import ResultsView

    for view in (DashboardView(), NewScanView(), ResultsView(), AgentView(), ReportsView()):
        assert view is not None


@requires_pyside
def test_agent_view_populates(qapp) -> None:
    """The Agent view renders findings, investigations and drift from a report."""
    from sentinel_ui.views.agent import AgentView

    view = AgentView()
    view.set_data(AgentReport.model_validate(SPEC_AGENT))
    assert view._stack.currentIndex() == 1
    assert view._findings_table.rowCount() == 1
    assert view._investigations_table.rowCount() == 1
    assert view._drift_table.rowCount() == 1
    assert "DEFAULT-PANEL" in view._stats_label.text()
    assert view._observations_list.count() == 1
    view.set_data(None)
    assert view._stack.currentIndex() == 0


@requires_pyside
def test_new_scan_has_agent_checkbox(qapp) -> None:
    """The New Scan form offers the agent investigation toggle (default on)."""
    from PySide6.QtCore import QSettings

    from sentinel_ui.views.new_scan import NewScanView

    QSettings().remove("agent/enabled")  # isolate from persisted operator choice
    view = NewScanView()
    assert view._agent_check is not None
    assert view._agent_check.isChecked()


@requires_pyside
def test_confirm_dialog_gate(qapp) -> None:
    """The scope dialog keeps Launch disabled until an exact CONFIRM."""
    from PySide6.QtWidgets import QDialogButtonBox

    from sentinel_ui.models import Tier
    from sentinel_ui.views.new_scan import ScopeConfirmDialog

    dialog = ScopeConfirmDialog("192.168.1.0/24", Tier.DAILY)
    ok = dialog.findChild(QDialogButtonBox).button(QDialogButtonBox.StandardButton.Ok)
    assert not ok.isEnabled()
    dialog._input.setText("confirm")
    assert not ok.isEnabled()
    dialog._input.setText("CONFIRM")
    assert ok.isEnabled()
    dialog._input.setText("CONFIRM ")
    assert not ok.isEnabled()


@requires_pyside
def test_confirm_dialog_accepts_plain_string_tier(qapp) -> None:
    """Regression: QComboBox user data can return a plain str for a StrEnum
    (PySide6 QVariant round-trip on macOS). The dialog must normalize it
    instead of crashing on ``tier.value``."""
    from PySide6.QtWidgets import QLabel

    from sentinel_ui.views.new_scan import ScopeConfirmDialog

    dialog = ScopeConfirmDialog("192.168.1.0/24", "daily")  # str, not Tier
    labels = dialog.findChildren(QLabel)
    assert any("DAILY" in label.text() for label in labels)


@requires_pyside
def test_views_accept_spec_data(qapp) -> None:
    """Dashboard and results populate from the SPEC contract documents."""
    from sentinel_ui.views.dashboard import DashboardView
    from sentinel_ui.views.results import ResultsView

    scan = ScanInput.model_validate(SPEC_SCAN)
    analysis = AnalysisOutput.model_validate(SPEC_ANALYSIS)

    dashboard = DashboardView()
    dashboard.update_state(scan, analysis)
    dashboard.set_analyzer_status("llm")

    results = ResultsView()
    results.set_data(scan, analysis)
    assert results._hosts_table.rowCount() == 1
    assert results._vuln_table.rowCount() == 1
    assert results._chains_list.count() == 1
