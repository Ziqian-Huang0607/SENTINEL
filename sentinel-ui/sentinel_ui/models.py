"""Pydantic models mirroring the SENTINEL interface contracts.

These types are strict mirrors of the ``ScanInput`` and ``AnalysisOutput``
JSON schemas defined in the master SPEC, plus the analyzer REST envelopes.
This module is Qt-free so it can be reused and tested headlessly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

APP_NAME = "SENTINEL"
ANALYZER_DEFAULT_URL = "http://127.0.0.1:8710"


class Tier(StrEnum):
    """Security tier selecting the threat model and compliance baseline."""

    DAILY = "daily"
    AUTHORITY = "authority"
    HACKER = "hacker"
    MILITARY = "military"


class TrustZone(StrEnum):
    """Network exposure zone of a discovered host."""

    INTERNET = "internet"
    DMZ = "dmz"
    INTERNAL = "internal"
    MGMT = "mgmt"
    AIRGAP = "airgap"


class Criticality(StrEnum):
    """Business criticality class of a discovered host."""

    DC = "dc"
    APP = "app"
    WORKSTATION = "workstation"
    IOT = "iot"


class AnalyzerMode(StrEnum):
    """Operating mode reported by the analyzer service."""

    LLM = "llm"
    FALLBACK = "fallback"


@dataclass(frozen=True)
class TierProfile:
    """Descriptive metadata for a security tier, per the SPEC tier table."""

    tier: Tier
    threat: str
    compliance: str
    patch_sla: str
    risk_threshold: float


TIER_PROFILES: dict[Tier, TierProfile] = {
    Tier.DAILY: TierProfile(
        tier=Tier.DAILY,
        threat="Worms, script kiddies",
        compliance="CIS Controls v8 L1",
        patch_sla="30 days",
        risk_threshold=4.0,
    ),
    Tier.AUTHORITY: TierProfile(
        tier=Tier.AUTHORITY,
        threat="Organized cybercrime",
        compliance="NIST 800-53 Moderate, ISO 27001",
        patch_sla="7 days",
        risk_threshold=2.5,
    ),
    Tier.HACKER: TierProfile(
        tier=Tier.HACKER,
        threat="APT, red teams",
        compliance="NIST 800-53 High, MITRE ATT&CK",
        patch_sla="24 hours",
        risk_threshold=1.5,
    ),
    Tier.MILITARY: TierProfile(
        tier=Tier.MILITARY,
        threat="Nation-state",
        compliance="NSA/CSS, TEMPEST, CNSS 1253",
        patch_sla="Immediate / airgap",
        risk_threshold=0.5,
    ),
}


class PortInfo(BaseModel):
    """A single probed port on a host."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    banner: str = ""


class HostInfo(BaseModel):
    """A discovered host within scan scope."""

    ip: str
    hostname: str = ""
    mac: str = ""
    os_guess: str = ""
    trust_zone: TrustZone = TrustZone.INTERNAL
    criticality: Criticality = Criticality.WORKSTATION
    ports: list[PortInfo] = Field(default_factory=list)

    def open_ports(self) -> list[PortInfo]:
        """Return only ports whose state is ``open``."""
        return [p for p in self.ports if p.state == "open"]


class Vulnerability(BaseModel):
    """A CVE finding bound to a host and port."""

    cve_id: str
    cvss: float = 0.0
    epss: float = 0.0
    host: str
    port: int
    summary: str = ""


class ScanInput(BaseModel):
    """Scanner output document; also the analyzer ``/analyze`` request body."""

    scan_id: str
    target: str
    tier: Tier
    started_at: str
    finished_at: str
    hosts: list[HostInfo] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    risk_score: float = 0.0


class AttackChain(BaseModel):
    """A correlated multi-step attack path."""

    path: list[str] = Field(default_factory=list)
    description: str = ""
    mitre_technique: str = ""
    confidence: float = 0.0
    impact: float = 0.0
    priority: int = 0


class Remediation(BaseModel):
    """Tiered remediation control checklists."""

    daily: list[str] = Field(default_factory=list)
    authority: list[str] = Field(default_factory=list)
    hacker: list[str] = Field(default_factory=list)
    military: list[str] = Field(default_factory=list)

    def for_tier(self, tier: Tier) -> list[str]:
        """Return the control checklist for one tier."""
        return list(getattr(self, tier.value))


class AnalysisOutput(BaseModel):
    """Analyzer output document returned by ``POST /analyze``."""

    attack_chains: list[AttackChain] = Field(default_factory=list)
    remediation: Remediation = Field(default_factory=Remediation)
    risk_score: float = 0.0
    observations: list[str] = Field(default_factory=list)
    analyzer_mode: AnalyzerMode = AnalyzerMode.FALLBACK


class HealthStatus(BaseModel):
    """Analyzer ``GET /health`` payload."""

    status: str
    mode: AnalyzerMode


class AgentFinding(BaseModel):
    """One grounded agent finding (mirror of sentinel-agent models, §4)."""

    model_config = ConfigDict(extra="allow")

    id: str
    finding_class: str = ""
    host: str = ""
    port: int = 0
    severity: float = 0.0
    title: str = ""
    detail: str = ""
    evidence: list[dict] = Field(default_factory=list)
    confidence: float = 0.0

    def endpoint(self) -> str:
        """``host:port`` display form."""
        return f"{self.host}:{self.port}" if self.port else self.host

    def evidence_ids(self) -> str:
        """Comma-joined transcript evidence ids (E1, E2, …)."""
        return ", ".join(str(e.get("id", "")) for e in self.evidence if e.get("id"))


class TargetInvestigation(BaseModel):
    """One per-target agent investigation summary."""

    model_config = ConfigDict(extra="allow")

    host: str = ""
    ports: list[int] = Field(default_factory=list)
    trigger: str = ""
    status: str = ""
    turns: int = 0
    summary: str = ""
    findings: list[AgentFinding] = Field(default_factory=list)
    transcript_path: str = ""


class DriftEvent(BaseModel):
    """One network-memory drift event."""

    model_config = ConfigDict(extra="allow")

    kind: str = ""
    host: str = ""
    port: int | None = None
    before: str = ""
    after: str = ""
    ts: str = ""

    def endpoint(self) -> str:
        """``host:port`` display form."""
        return f"{self.host}:{self.port}" if self.port is not None else self.host


class AgentReport(BaseModel):
    """agent_report.json contract (optional third report input, R9)."""

    model_config = ConfigDict(extra="allow")

    agent_version: str = ""
    scan_id: str = ""
    target: str = ""
    tier: str = ""
    started_at: str = ""
    finished_at: str = ""
    model: str = ""
    investigations: list[TargetInvestigation] = Field(default_factory=list)
    findings: list[AgentFinding] = Field(default_factory=list)
    drift: list[DriftEvent] = Field(default_factory=list)
    risk_score: float = 0.0
    observations: list[str] = Field(default_factory=list)


class ReportResponse(BaseModel):
    """Analyzer ``POST /report`` payload mapping format to saved file path."""

    files: dict[str, str] = Field(default_factory=dict)


@dataclass(frozen=True)
class ScanRequest:
    """Parameters collected from the New Scan view to launch a scan."""

    target: str
    tier: Tier
    formats: list[str] = field(default_factory=lambda: ["json"])
    concurrency: int = 200
    ports_preset: str = "top-1000"
    scanner_binary: str = ""
    analyzer_url: str = ANALYZER_DEFAULT_URL
    allow_public: bool = False
    run_agent: bool = True
    agent_dir: str = ""
