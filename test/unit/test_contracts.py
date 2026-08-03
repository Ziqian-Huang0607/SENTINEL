"""Pure-unit tests for the shared SENTINEL contracts and risk formula.

Fast, no services required. Run with: pytest test/unit -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # test/ directory

from contracts import (  # noqa: E402
    CRITICALITY_WEIGHTS,
    EXPOSURE_WEIGHTS,
    AnalysisOutput,
    ScanInput,
    compute_risk_score,
    per_vuln_risk,
    round2,
    sample_analysis,
    sample_scan,
)


def test_formula_weights_sum_to_one() -> None:
    """0.25 + 0.35 + 0.25 + 0.15 must stay 1.0 so a maxed-out vuln scores 10."""
    assert per_vuln_risk(10.0, 1.0, 1.0, 1.0) == pytest.approx(10.0)


def test_per_vuln_risk_kev_floor() -> None:
    """KEV-flagged findings are floored at 9.0; unflagged ones are not."""
    # Raw: 4.0*0.25 + 0.1*10*0.35 + 0.4*10*0.25 + 0.4*10*0.15
    #    = 1.0 + 0.35 + 1.0 + 0.6 = 2.95
    assert per_vuln_risk(4.0, 0.1, 0.4, 0.4) == pytest.approx(2.95)
    assert per_vuln_risk(4.0, 0.1, 0.4, 0.4, kev=True) == pytest.approx(9.0)
    assert per_vuln_risk(4.0, 0.1, 0.4, 0.4, kev=False) == pytest.approx(2.95)


def test_exposure_weights_match_spec() -> None:
    assert EXPOSURE_WEIGHTS == {
        "internet": 1.0,
        "dmz": 0.7,
        "internal": 0.4,
        "mgmt": 0.1,
        "airgap": 0.0,
    }


def test_criticality_weights_match_spec() -> None:
    assert CRITICALITY_WEIGHTS == {"dc": 1.0, "app": 0.7, "workstation": 0.4, "iot": 0.1}


def test_sample_scan_is_valid_and_scores_792() -> None:
    scan = sample_scan()
    ScanInput.model_validate(scan)
    assert compute_risk_score(scan) == 7.92  # max of {7.92, 5.60, 5.52}


def test_risk_rounding_matches_scanner_at_7025_boundary() -> None:
    """Regression: oracle must agree with the scanner's half-up round2.

    cvss 9.8, epss 0.85 on an internal (0.4) / workstation (0.4) host:
      9.8*0.25 + 0.85*10*0.35 + 0.4*10*0.25 + 0.4*10*0.15
      = 2.45 + 2.975 + 1.0 + 0.6 = 7.025 -> 7.03
    Python's banker's round() gives 7.02; the scanner binary emits 7.03.
    (The old-weight 4.805 boundary inputs 8.1/0.53/mgmt/workstation now
    yield 2.025 + 1.855 + 0.25 + 0.6 = 4.73, no longer a half boundary.)
    """
    assert per_vuln_risk(9.8, 0.85, 0.4, 0.4) == pytest.approx(7.025)
    assert round2(7.025) == 7.03
    scan = sample_scan()
    scan["hosts"] = [
        {"ip": "192.0.2.60", "trust_zone": "internal", "criticality": "workstation"}
    ]
    scan["vulnerabilities"] = [
        {
            "cve_id": "CVE-2024-31851",
            "cvss": 9.8,
            "epss": 0.85,
            "host": "192.0.2.60",
            "port": 443,
            "summary": "Boundary-rounding fixture (7.025 raw).",
        }
    ]
    assert compute_risk_score(scan) == 7.03


def test_score_ignores_vulns_without_known_host() -> None:
    scan = sample_scan()
    scan["vulnerabilities"] = [
        {
            "cve_id": "CVE-2024-0001",
            "cvss": 10.0,
            "epss": 1.0,
            "host": "203.0.113.99",  # not in hosts[]
            "port": 1,
            "summary": "orphan finding",
        }
    ]
    assert compute_risk_score(scan) == 0.0


def test_empty_scan_scores_zero() -> None:
    scan = sample_scan()
    scan["hosts"] = []
    scan["vulnerabilities"] = []
    scan["risk_score"] = 0.0
    assert compute_risk_score(scan) == 0.0


def test_sample_analysis_is_valid() -> None:
    analysis = AnalysisOutput.model_validate(sample_analysis())
    assert analysis.analyzer_mode == "fallback"
    assert analysis.risk_score == 7.92
    assert set(analysis.remediation.model_dump()) == {"daily", "authority", "hacker", "military"}


def test_analysis_requires_analyzer_mode() -> None:
    payload = sample_analysis()
    del payload["analyzer_mode"]
    with pytest.raises(ValidationError):
        AnalysisOutput.model_validate(payload)


def test_scan_rejects_bad_cve_and_bad_tier() -> None:
    scan = sample_scan()
    scan["vulnerabilities"][0]["cve_id"] = "not-a-cve"
    with pytest.raises(ValidationError):
        ScanInput.model_validate(scan)
    scan = sample_scan()
    scan["tier"] = "weekly"
    with pytest.raises(ValidationError):
        ScanInput.model_validate(scan)
