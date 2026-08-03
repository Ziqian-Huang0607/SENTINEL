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

from sentinel_ui.models import AnalysisOutput, ScanInput, Tier
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
    """The main window shows with sidebar navigation and four pages."""
    from sentinel_ui.main_window import MainWindow

    window = MainWindow()
    window.show()
    assert window.isVisible()
    assert window.windowTitle() == "SENTINEL"
    window.close()


@requires_pyside
def test_all_views_construct(qapp) -> None:
    """Every view widget constructs and exposes its empty state."""
    from sentinel_ui.views.dashboard import DashboardView
    from sentinel_ui.views.new_scan import NewScanView
    from sentinel_ui.views.reports import ReportsView
    from sentinel_ui.views.results import ResultsView

    for view in (DashboardView(), NewScanView(), ResultsView(), ReportsView()):
        assert view is not None


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
