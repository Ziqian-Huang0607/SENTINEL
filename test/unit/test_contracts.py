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
    PostureFinding,
    ScanInput,
    compute_risk_score,
    per_posture_risk,
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


def test_pre_r8_scan_documents_still_validate() -> None:
    """R8 fields are additive: a scan.json without them defaults to empty."""
    scan = ScanInput.model_validate(sample_scan())
    assert scan.posture_findings == []
    assert scan.cve_db.version == ""
    assert scan.cve_db.signatures == 0
    assert compute_risk_score(scan) == 7.92  # legacy pin unchanged


def test_posture_finding_scores_through_formula_with_epss_zero() -> None:
    """R8: an exposure without a CVE still scores — never a silent 0.00.

    Unauthenticated web (severity 6.5) on a loopback mgmt/ws host:
      6.5*0.25 + 0 + 0.1*10*0.25 + 0.4*10*0.15 = 1.625 + 0.25 + 0.6 = 2.48
    Gateway-class exposure (7.5) on a dmz/dc host:
      7.5*0.25 + 0 + 0.7*10*0.25 + 1.0*10*0.15 = 1.875 + 1.75 + 1.5 = 5.13
    """
    assert per_posture_risk(6.5, 0.1, 0.4) == pytest.approx(2.475)
    assert round2(per_posture_risk(6.5, 0.1, 0.4)) == 2.48
    assert per_posture_risk(7.5, 0.7, 1.0) == pytest.approx(5.125)
    assert round2(per_posture_risk(7.5, 0.7, 1.0)) == 5.13


def test_posture_findings_lift_scan_score_above_cve_only() -> None:
    """A posture finding outscoring every CVE must drive the scan score."""
    scan = sample_scan()
    scan["posture_findings"] = [
        {
            "id": "POSTURE-UNAUTH-WEB-GATEWAY",
            "host": "192.0.2.45",  # internet/dc -> 7.5*0.25+2.5+1.5 = 5.875
            "port": 80,
            "severity": 7.5,
            "title": "Unauthenticated web interface on a probable gateway",
            "evidence": "GET / -> 200; Server: nginx/1.18.0",
        }
    ]
    assert compute_risk_score(scan) == 7.92  # CVE pin still dominates here
    scan["vulnerabilities"] = []
    assert compute_risk_score(scan) == 5.88  # posture alone, round2(5.875)


def test_posture_finding_on_unknown_host_contributes_nothing() -> None:
    scan = sample_scan()
    scan["vulnerabilities"] = []
    scan["posture_findings"] = [
        {
            "id": "POSTURE-UNAUTH-WEB",
            "host": "203.0.113.99",  # not in hosts[]
            "port": 8080,
            "severity": 6.5,
        }
    ]
    assert compute_risk_score(scan) == 0.0


def test_posture_finding_rejects_bad_id_and_severity() -> None:
    with pytest.raises(ValidationError):
        PostureFinding.model_validate(
            {"id": "unauth-web", "host": "192.0.2.1", "port": 80, "severity": 6.5}
        )
    with pytest.raises(ValidationError):
        PostureFinding.model_validate(
            {"id": "POSTURE-UNAUTH-WEB", "host": "192.0.2.1", "port": 80, "severity": 11.0}
        )


def test_analysis_output_passes_posture_findings_through() -> None:
    analysis = sample_analysis()
    analysis["posture_findings"] = [
        {
            "id": "POSTURE-UNAUTH-IPP",
            "host": "192.0.2.45",
            "port": 631,
            "severity": 6.5,
            "title": "Unauthenticated IPP print service",
        }
    ]
    parsed = AnalysisOutput.model_validate(analysis)
    assert parsed.posture_findings[0].id == "POSTURE-UNAUTH-IPP"


def test_scan_rejects_bad_cve_and_bad_tier() -> None:
    scan = sample_scan()
    scan["vulnerabilities"][0]["cve_id"] = "not-a-cve"
    with pytest.raises(ValidationError):
        ScanInput.model_validate(scan)
    scan = sample_scan()
    scan["tier"] = "weekly"
    with pytest.raises(ValidationError):
        ScanInput.model_validate(scan)
