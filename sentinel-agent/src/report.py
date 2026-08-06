"""agent_report.json assembly + deterministic risk scoring (agent-spec.md).

The risk formula is THE deterministic formula, identical to the scanner,
analyzer, and test/contracts.py oracle:

    RISK = (CVSS * 0.25) + (EPSS * 10 * 0.35)
         + (EXPOSURE * 10 * 0.25) + (CRITICALITY * 10 * 0.15)

Posture findings (R8) and agent findings enter with EPSS = 0 and no KEV
floor; the scan-level score is the maximum per-finding score, rounded
half-up to 2 decimals (1e-9 nudge, mirroring the scanner's round2).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from src import __version__
from src.models import AgentFinding, AgentReport, DriftEvent, TargetInvestigation

EXPOSURE_WEIGHTS: dict[str, float] = {
    "internet": 1.0,
    "dmz": 0.7,
    "internal": 0.4,
    "mgmt": 0.1,
    "airgap": 0.0,
}
CRITICALITY_WEIGHTS: dict[str, float] = {
    "dc": 1.0,
    "app": 0.7,
    "workstation": 0.4,
    "iot": 0.1,
}
KEV_RISK_FLOOR = 9.0


def round2(value: float) -> float:
    """Canonical 2dp rounding, mirroring the scanner's half-up round2."""
    return round(value + 1e-9, 2)


def per_finding_risk(
    cvss: float, epss: float, exposure: float, criticality: float, kev: bool = False
) -> float:
    """Deterministic per-finding risk score (KEV floor for CVE findings only)."""
    raw = (cvss * 0.25) + (epss * 10 * 0.35) + (exposure * 10 * 0.25) + (criticality * 10 * 0.15)
    return max(raw, KEV_RISK_FLOOR) if kev else raw


def compute_risk_score(scan: dict[str, Any], agent_findings: list[AgentFinding]) -> float:
    """Scan-level risk: max score over CVE, posture, and agent findings.

    Findings referencing an undiscovered host contribute nothing, mirroring
    the SPEC.md rule "host exposure/criticality applied". Agent findings use
    their class severity with EPSS = 0 and never carry a KEV flag.
    """
    hosts_by_ip = {host["ip"]: host for host in scan.get("hosts", [])}
    best = 0.0

    def host_weights(ip: str) -> tuple[float, float] | None:
        host = hosts_by_ip.get(ip)
        if host is None:
            return None
        return (
            EXPOSURE_WEIGHTS[host.get("trust_zone", "internal")],
            CRITICALITY_WEIGHTS[host.get("criticality", "workstation")],
        )

    for vuln in scan.get("vulnerabilities", []):
        weights = host_weights(vuln["host"])
        if weights is None:
            continue
        best = max(
            best,
            per_finding_risk(
                vuln["cvss"], vuln["epss"], weights[0], weights[1], vuln.get("kev", False)
            ),
        )
    for finding in scan.get("posture_findings", []):
        weights = host_weights(finding["host"])
        if weights is None:
            continue
        best = max(best, per_finding_risk(finding["severity"], 0.0, weights[0], weights[1]))
    for finding in agent_findings:
        weights = host_weights(finding.host)
        if weights is None:
            continue
        best = max(
            best,
            per_finding_risk(finding.severity_for_class(), 0.0, weights[0], weights[1]),
        )
    return round2(best)


def assemble_report(
    scan: dict[str, Any],
    model: str,
    investigations: list[TargetInvestigation],
    drift: list[DriftEvent],
    started_at: datetime,
    finished_at: datetime,
    observations: list[str] | None = None,
) -> AgentReport:
    """Assemble the agent_report.json document from investigation results."""
    findings = [f for inv in investigations for f in inv.findings]
    return AgentReport(
        agent_version=__version__,
        scan_id=scan["scan_id"],
        target=scan["target"],
        tier=scan["tier"],
        started_at=started_at,
        finished_at=finished_at,
        model=model,
        investigations=investigations,
        findings=findings,
        drift=drift,
        risk_score=compute_risk_score(scan, findings),
        observations=observations or [],
    )
