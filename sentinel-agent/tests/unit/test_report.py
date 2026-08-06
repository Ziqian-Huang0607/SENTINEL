"""Risk formula + report assembly tests (agent-spec.md sections 4 and 9).

Reference arithmetic mirrors test/contracts.py so the agent layer scores
identically to the scanner, analyzer, and oracle.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from src.models import AgentFinding, DriftEvent
from src.report import (
    CRITICALITY_WEIGHTS,
    EXPOSURE_WEIGHTS,
    assemble_report,
    compute_risk_score,
    per_finding_risk,
    round2,
)


def _scan(hosts, vulns=(), posture=()) -> dict:
    return {
        "scan_id": "3f6c8b4e-2c1a-4e5b-9a7d-0f1e2d3c4b5a",
        "target": "127.0.0.1/32",
        "tier": "daily",
        "hosts": hosts,
        "vulnerabilities": list(vulns),
        "posture_findings": list(posture),
        "risk_score": 0.0,
    }


def _finding(finding_class: str, host: str, port: int = 80, **kw) -> AgentFinding:
    return AgentFinding(
        id=f"AGENT-{finding_class}-1",
        finding_class=finding_class,
        host=host,
        port=port,
        severity=9.9,  # LLM-supplied noise; must be ignored in favor of class
        title=kw.pop("title", "t"),
        evidence=["E1"],
        confidence=0.8,
        **kw,
    )


def test_weights_match_spec() -> None:
    assert EXPOSURE_WEIGHTS == {
        "internet": 1.0, "dmz": 0.7, "internal": 0.4, "mgmt": 0.1, "airgap": 0.0
    }
    assert CRITICALITY_WEIGHTS == {"dc": 1.0, "app": 0.7, "workstation": 0.4, "iot": 0.1}


def test_formula_reference_values() -> None:
    # posture 6.5 on mgmt/ws = 1.625 + 0.25 + 0.6 = 2.475 -> 2.48
    assert per_finding_risk(6.5, 0.0, 0.1, 0.4) == pytest.approx(2.475)
    assert round2(2.475) == 2.48
    # gateway 7.5 on dmz/dc = 1.875 + 1.75 + 1.5 = 5.125 -> 5.13
    assert per_finding_risk(7.5, 0.0, 0.7, 1.0) == pytest.approx(5.125)
    assert round2(5.125) == 5.13
    # KEV floor applies to CVE findings only
    assert per_finding_risk(4.0, 0.1, 0.4, 0.4, kev=True) == pytest.approx(9.0)


def test_agent_finding_severity_comes_from_class_not_llm() -> None:
    finding = _finding("DEFAULT-PANEL", "192.168.1.1")
    assert finding.severity_for_class() == 7.0  # not the 9.9 the LLM supplied


def test_agent_findings_score_through_formula_with_epss_zero() -> None:
    """DEFAULT-PANEL (7.0) on internet/dc: 1.75 + 2.5 + 1.5 = 5.75."""
    scan = _scan(
        hosts=[{"ip": "192.168.1.1", "trust_zone": "internet", "criticality": "dc"}]
    )
    findings = [_finding("DEFAULT-PANEL", "192.168.1.1")]
    assert compute_risk_score(scan, findings) == 5.75


def test_agent_finding_never_gets_kev_floor() -> None:
    """Even a high-severity class scores by formula, not the 9.0 KEV floor."""
    scan = _scan(
        hosts=[{"ip": "192.168.1.1", "trust_zone": "internal", "criticality": "iot"}]
    )
    findings = [_finding("DEFAULT-PANEL", "192.168.1.1")]
    # 7.0*0.25 + 0 + 0.4*10*0.25 + 0.1*10*0.15 = 1.75 + 1.0 + 0.15 = 2.90
    assert compute_risk_score(scan, findings) == 2.90


def test_cve_pin_still_holds_with_agent_findings_present() -> None:
    """The 7.92 contracts pin dominates smaller agent findings."""
    scan = _scan(
        hosts=[{"ip": "192.0.2.45", "trust_zone": "internet", "criticality": "dc"}],
        vulns=[
            {
                "cve_id": "CVE-2024-21667",
                "cvss": 9.8,
                "epss": 0.42,
                "host": "192.0.2.45",
                "port": 6379,
            }
        ],
    )
    findings = [_finding("MISCONFIG", "192.0.2.45", port=8080)]
    assert compute_risk_score(scan, findings) == 7.92


def test_findings_on_unknown_hosts_contribute_nothing() -> None:
    scan = _scan(hosts=[{"ip": "192.168.1.1", "trust_zone": "internal", "criticality": "iot"}])
    findings = [_finding("DEFAULT-PANEL", "203.0.113.99")]
    assert compute_risk_score(scan, findings) == 0.0


def test_assemble_report_flattens_and_scores() -> None:
    from src.models import TargetInvestigation

    scan = _scan(
        hosts=[{"ip": "192.168.1.1", "trust_zone": "internet", "criticality": "dc"}]
    )
    finding = _finding("DEFAULT-PANEL", "192.168.1.1")
    inv = TargetInvestigation(
        host="192.168.1.1",
        ports=[80],
        trigger="gateway",
        status="concluded",
        turns=3,
        summary="s",
        findings=[finding],
        transcript_path="agent_transcripts/192.168.1.1_80.json",
    )
    drift = DriftEvent(
        kind="NEW_HOST", host="192.168.1.1", ts=datetime.now(timezone.utc)
    )
    now = datetime.now(timezone.utc)
    report = assemble_report(scan, "playbook", [inv], [drift], now, now, ["note"])
    assert report.model == "playbook"
    assert report.findings == [finding]
    assert report.risk_score == 5.75
    assert report.observations == ["note"]
    assert len(report.drift) == 1
