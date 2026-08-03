"""SENTINEL interface contracts, mirrored from SPEC.md ("sacred" interfaces).

These pydantic models intentionally duplicate the component-side models so the
orchestration test suites validate wire formats independently of any single
component's implementation. If a component and this file disagree, SPEC.md wins.

Also home to the deterministic risk-scoring formula:

    RISK_SCORE = (CVSS * 0.25) + (EPSS * 10 * 0.35)
               + (EXPOSURE * 10 * 0.25) + (CRITICALITY * 10 * 0.15)

The scan-level risk score is the maximum per-vulnerability score (with the
owning host's exposure/criticality applied), rounded to 2 decimals.

KEV override: findings flagged ``kev=True`` (CISA Known Exploited
Vulnerabilities catalog membership, per the cve_cache seed) floor at 9.0
(per-finding ``max(raw, KEV_RISK_FLOOR)`` before the scan-level max).
Evidence: METHODOLOGY.md Ch.8 R1/R2.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import UUID4, BaseModel, Field

Tier = Literal["daily", "authority", "hacker", "military"]
TrustZone = Literal["internet", "dmz", "internal", "mgmt", "airgap"]
Criticality = Literal["dc", "app", "workstation", "iot"]
AnalyzerMode = Literal["llm", "fallback"]

TIERS: tuple[str, ...] = ("daily", "authority", "hacker", "military")
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

# Cross-language float tolerance (Rust vs Python rounding at the 2dp boundary).
RISK_TOLERANCE = 0.011

# CISA KEV-catalog findings floor at this score (critical band; BOD 26-04-style
# escalation). Mirrors KEV_RISK_FLOOR in the scanner scorer and analyzer models.
KEV_RISK_FLOOR = 9.0


def round2(value: float) -> float:
    """Canonical 2dp rounding, mirroring the scanner's ``round2``.

    The Rust scorer (sentinel-scanner/src/vuln/scorer.rs) rounds half-up with
    a 1e-9 nudge to counteract binary float error, so a decimal-exact 4.805
    yields 4.81. Python's banker's ``round()`` would give 4.80; the nudge
    keeps every Python-side oracle in exact agreement with the shipped binary.
    """
    return round(value + 1e-9, 2)


class Port(BaseModel):
    """A single discovered listening service on a host."""

    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    state: Literal["open", "closed", "filtered"] = "open"
    service: str = ""
    version: str | None = None
    banner: str | None = None
    banner_confidence: Literal["high", "medium", "low"] | None = None


class Host(BaseModel):
    """A discovered host with its posture metadata."""

    ip: str
    hostname: str | None = None
    mac: str | None = None
    os_guess: str | None = None
    trust_zone: TrustZone = "internal"
    criticality: Criticality = "workstation"
    ports: list[Port] = Field(default_factory=list)


class Vulnerability(BaseModel):
    """A CVE finding bound to a host/port."""

    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    cvss: float = Field(ge=0.0, le=10.0)
    epss: float = Field(ge=0.0, le=1.0)
    host: str
    port: int = Field(ge=1, le=65535)
    summary: str = ""
    kev: bool = False


class ScanInput(BaseModel):
    """scan.json — scanner output, also the analyzer `/analyze` request body."""

    scan_id: UUID4
    target: str
    tier: Tier
    started_at: datetime
    finished_at: datetime
    hosts: list[Host] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=10.0)


class AttackChain(BaseModel):
    """One candidate attack path through the scanned topology."""

    path: list[str]
    description: str
    mitre_technique: str
    confidence: float = Field(ge=0.0, le=1.0)
    impact: float = Field(ge=0.0, le=1.0)
    priority: int = Field(ge=1)


class Remediation(BaseModel):
    """Tiered remediation guidance; every tier key is always present."""

    daily: list[str] = Field(default_factory=list)
    authority: list[str] = Field(default_factory=list)
    hacker: list[str] = Field(default_factory=list)
    military: list[str] = Field(default_factory=list)


class AnalysisOutput(BaseModel):
    """analysis.json — analyzer response for both llm and fallback modes."""

    attack_chains: list[AttackChain] = Field(default_factory=list)
    remediation: Remediation
    risk_score: float = Field(ge=0.0, le=10.0)
    observations: list[str] = Field(default_factory=list)
    analyzer_mode: AnalyzerMode


ANALYSIS_KEYS: tuple[str, ...] = (
    "attack_chains",
    "remediation",
    "risk_score",
    "observations",
    "analyzer_mode",
)


def per_vuln_risk(
    cvss: float, epss: float, exposure: float, criticality: float, kev: bool = False
) -> float:
    """Deterministic per-vulnerability risk score (formula from SPEC.md).

    KEV-listed findings floor at KEV_RISK_FLOOR (9.0) regardless of inputs.
    """
    raw = (cvss * 0.25) + (epss * 10 * 0.35) + (exposure * 10 * 0.25) + (criticality * 10 * 0.15)
    return max(raw, KEV_RISK_FLOOR) if kev else raw


def compute_risk_score(scan: ScanInput | dict) -> float:
    """Scan-level risk score: max per-vuln score over hosts, rounded to 2dp.

    Vulnerabilities referencing an undiscovered host contribute nothing, mirroring
    the rule "host exposure/criticality applied" from SPEC.md.

    Rounded with :func:`round2` so the oracle agrees with the scanner binary
    exactly at decimal half boundaries (e.g. 4.805 -> 4.81).
    """
    if isinstance(scan, dict):
        scan = ScanInput.model_validate(scan)
    hosts_by_ip = {host.ip: host for host in scan.hosts}
    best = 0.0
    for vuln in scan.vulnerabilities:
        host = hosts_by_ip.get(vuln.host)
        if host is None:
            continue
        score = per_vuln_risk(
            vuln.cvss,
            vuln.epss,
            EXPOSURE_WEIGHTS[host.trust_zone],
            CRITICALITY_WEIGHTS[host.criticality],
            vuln.kev,
        )
        best = max(best, score)
    return round2(best)


def sample_scan() -> dict:
    """A synthetic, fully valid ScanInput payload with a known risk score.

    Two hosts / three vulnerabilities; expected score 7.92:
      redis CVE on internet/dc host: 9.8*0.25 + 0.42*10*0.35 + 1.0*10*0.25 + 1.0*10*0.15
                                   = 2.45 + 1.47 + 2.5 + 1.5 = 7.92  (the max)
      ssh CVE on same host:          1.25 + 0.35 + 2.5 + 1.5 = 5.60
      redis CVE on internal/ws host: 2.45 + 1.47 + 1.0 + 0.6 = 5.52
    """
    scan = ScanInput(
        scan_id="3f6c8b4e-2c1a-4e5b-9a7d-0f1e2d3c4b5a",
        target="127.0.0.1/32",
        tier="daily",
        started_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        finished_at=datetime(2024, 1, 1, 12, 0, 42, tzinfo=timezone.utc),
        hosts=[
            Host(
                ip="192.0.2.45",
                hostname="db01",
                mac="aa:bb:cc:dd:ee:ff",
                os_guess="Linux 5.x",
                trust_zone="internet",
                criticality="dc",
                ports=[
                    Port(
                        port=6379,
                        protocol="tcp",
                        state="open",
                        service="redis",
                        version="6.2.7",
                        banner="-NOAUTH",
                    ),
                    Port(port=22, protocol="tcp", state="open", service="ssh", version="9.6"),
                ],
            ),
            Host(
                ip="192.0.2.46",
                hostname="ws07",
                trust_zone="internal",
                criticality="workstation",
                ports=[Port(port=6379, protocol="tcp", state="open", service="redis")],
            ),
        ],
        vulnerabilities=[
            Vulnerability(
                cve_id="CVE-2024-21667",
                cvss=9.8,
                epss=0.42,
                host="192.0.2.45",
                port=6379,
                summary="Unauthenticated redis instance reachable from the internet.",
            ),
            Vulnerability(
                cve_id="CVE-2024-6387",
                cvss=5.0,
                epss=0.1,
                host="192.0.2.45",
                port=22,
                summary="SSH signal-handler race condition (regreSSHion class).",
            ),
            Vulnerability(
                cve_id="CVE-2024-21667",
                cvss=9.8,
                epss=0.42,
                host="192.0.2.46",
                port=6379,
                summary="Unauthenticated redis instance on workstation segment.",
            ),
        ],
        risk_score=7.92,
    )
    return scan.model_dump(mode="json")


def sample_analysis(scan: dict | None = None) -> dict:
    """A synthetic, fully valid AnalysisOutput payload matching sample_scan()."""
    scan = scan if scan is not None else sample_scan()
    analysis = AnalysisOutput(
        attack_chains=[
            AttackChain(
                path=["192.0.2.45:6379"],
                description="Unauthenticated redis allows direct data access and lateral movement.",
                mitre_technique="T1110",
                confidence=0.9,
                impact=0.92,
                priority=1,
            )
        ],
        remediation=Remediation(
            daily=["Require redis AUTH and bind to localhost."],
            authority=["Segment redis behind a DMZ firewall with allowlists."],
            hacker=["Rotate credentials; enable TLS; audit replication users."],
            military=["Airgap the data tier; enforce mutual TLS and hardware keys."],
        ),
        risk_score=compute_risk_score(scan),
        observations=["2 hosts discovered", "3 vulnerabilities matched"],
        analyzer_mode="fallback",
    )
    return analysis.model_dump(mode="json")
