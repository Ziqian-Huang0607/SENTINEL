"""Pydantic v2 models for the SENTINEL analyzer interface contracts.

These models mirror, field-for-field, the sacred JSON contracts defined in
SPEC.md: the scanner output (``ScanInput``), the analyzer output
(``AnalysisOutput``) and the analyzer REST API request/response bodies.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Tier(StrEnum):
    """Security tier of the scanned environment (SPEC: Four Security Tiers)."""

    daily = "daily"
    authority = "authority"
    hacker = "hacker"
    military = "military"


class TrustZone(StrEnum):
    """Network trust zone of a host; drives the EXPOSURE factor."""

    internet = "internet"
    dmz = "dmz"
    internal = "internal"
    mgmt = "mgmt"
    airgap = "airgap"


class Criticality(StrEnum):
    """Business criticality of a host; drives the CRITICALITY factor."""

    dc = "dc"
    app = "app"
    workstation = "workstation"
    iot = "iot"


class AnalyzerMode(StrEnum):
    """Which engine produced an analysis."""

    llm = "llm"
    fallback = "fallback"


class ReportFormat(StrEnum):
    """Report formats supported by the reports service."""

    pdf = "pdf"
    json = "json"
    sarif = "sarif"


# Version semantics (R5): surfaced via /health and kept as named constants
# so the EPSS vintage and the pinned Ollama model are auditable in one place.
EPSS_VERSION = "v4"
EPSS_WINDOW_DAYS = 30
OLLAMA_MODEL = "llama3.1:8b"

# KEV rule: a finding catalogued in CISA's Known Exploited Vulnerabilities
# catalog scores at least this floor regardless of the raw formula result.
KEV_RISK_FLOOR = 9.0

# Deterministic scoring factors from SPEC.md (Risk Scoring section).
EXPOSURE_FACTOR: dict[TrustZone, float] = {
    TrustZone.internet: 1.0,
    TrustZone.dmz: 0.7,
    TrustZone.internal: 0.4,
    TrustZone.mgmt: 0.1,
    TrustZone.airgap: 0.0,
}

CRITICALITY_FACTOR: dict[Criticality, float] = {
    Criticality.dc: 1.0,
    Criticality.app: 0.7,
    Criticality.workstation: 0.4,
    Criticality.iot: 0.1,
}


def compute_risk_score(
    cvss: float,
    epss: float,
    trust_zone: TrustZone,
    criticality: Criticality,
    kev: bool = False,
) -> float:
    """Deterministic per-vulnerability risk score (SPEC: Risk Scoring).

    RISK_SCORE = (CVSS * 0.25) + (EPSS * 10 * 0.35)
               + (EXPOSURE * 10 * 0.25) + (CRITICALITY * 10 * 0.15)

    KEV override: when ``kev`` is true (the CVE is in CISA's Known
    Exploited Vulnerabilities catalog) the score is floored at
    ``KEV_RISK_FLOOR`` (9.0): max(raw_score, 9.0).

    Rounds with the same 1e-9 half-up nudge as the scanner's ``round2``
    (sentinel-scanner/src/vuln/scorer.rs) so analyzer-side recomputation
    agrees with the scanner binary at decimal half boundaries
    (e.g. 7.025 -> 7.03, where Python's banker's round() gives 7.02).
    """
    score = (
        cvss * 0.25
        + epss * 10.0 * 0.35
        + EXPOSURE_FACTOR[trust_zone] * 10.0 * 0.25
        + CRITICALITY_FACTOR[criticality] * 10.0 * 0.15
    )
    rounded = round(score + 1e-9, 2)
    return max(rounded, KEV_RISK_FLOOR) if kev else rounded


class Port(BaseModel):
    """A single probed port on a host."""

    model_config = ConfigDict(extra="ignore")

    port: int = Field(ge=0, le=65535)
    protocol: str = "tcp"
    state: str = "open"
    service: str | None = None
    version: str | None = None
    banner: str | None = None
    # Informational banner-grading confidence from the scanner; never
    # affects risk scoring.
    banner_confidence: str | None = None


class Host(BaseModel):
    """A discovered host in the scan target scope."""

    model_config = ConfigDict(extra="ignore")

    ip: str
    hostname: str | None = None
    mac: str | None = None
    os_guess: str | None = None
    trust_zone: TrustZone = TrustZone.internal
    criticality: Criticality = Criticality.workstation
    ports: list[Port] = Field(default_factory=list)


class Vulnerability(BaseModel):
    """A CVE finding mapped to a host/port."""

    model_config = ConfigDict(extra="ignore")

    cve_id: str
    cvss: float = Field(ge=0.0, le=10.0)
    epss: float = Field(ge=0.0, le=1.0)
    host: str
    port: int = Field(ge=0, le=65535)
    summary: str = ""
    # True when the CVE is in CISA's Known Exploited Vulnerabilities
    # catalog; floors the deterministic risk score at KEV_RISK_FLOOR.
    kev: bool = False


class PostureFinding(BaseModel):
    """An exposure finding without a CVE identifier (R8).

    Emitted by the scanner for observed risky conditions — unauthenticated
    web/IPP interfaces, legacy cleartext services, exposed data stores —
    and scored through the same deterministic formula with EPSS = 0.
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    host: str
    port: int = Field(ge=0, le=65535)
    severity: float = Field(ge=0.0, le=10.0)
    title: str = ""
    evidence: str = ""


class CveDbInfo(BaseModel):
    """Provenance of the scanner's embedded CVE signature DB (R8)."""

    model_config = ConfigDict(extra="ignore")

    version: str = ""
    signatures: int = 0


class ScanInput(BaseModel):
    """Scanner output contract (scan.json); also the analyzer input."""

    model_config = ConfigDict(extra="ignore")

    scan_id: str
    target: str
    tier: Tier
    started_at: datetime
    finished_at: datetime
    hosts: list[Host] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    # Additive R8 fields; absent in pre-R8 scan files (default empty).
    posture_findings: list[PostureFinding] = Field(default_factory=list)
    cve_db: CveDbInfo = Field(default_factory=CveDbInfo)
    risk_score: float = Field(ge=0.0, le=10.0)


class AttackChain(BaseModel):
    """One hypothesized attack path through the scanned environment."""

    model_config = ConfigDict(extra="ignore")

    path: list[str]
    description: str
    mitre_technique: str
    confidence: float = Field(ge=0.0, le=1.0)
    impact: float = Field(ge=0.0, le=1.0)
    priority: int = Field(ge=1)


class TieredRemediation(BaseModel):
    """Remediation control lists keyed by security tier."""

    model_config = ConfigDict(extra="ignore")

    daily: list[str] = Field(default_factory=list)
    authority: list[str] = Field(default_factory=list)
    hacker: list[str] = Field(default_factory=list)
    military: list[str] = Field(default_factory=list)


class AnalysisOutput(BaseModel):
    """Analyzer output contract (analysis.json)."""

    model_config = ConfigDict(extra="ignore")

    attack_chains: list[AttackChain] = Field(default_factory=list)
    remediation: TieredRemediation = Field(default_factory=TieredRemediation)
    risk_score: float = Field(ge=0.0, le=10.0)
    observations: list[str] = Field(default_factory=list)
    analyzer_mode: AnalyzerMode
    # R8: exposure findings passed through from the scan so reports can
    # render "0 CVE matches != no risk" sections. Not LLM-generated.
    posture_findings: list[PostureFinding] = Field(default_factory=list)


class ReportRequest(BaseModel):
    """Body of POST /report; forwarded to the reports service."""

    model_config = ConfigDict(extra="ignore")

    scan: ScanInput
    analysis: AnalysisOutput
    formats: list[ReportFormat]


class ReportResponse(BaseModel):
    """Response of POST /report: generated file paths keyed by format."""

    model_config = ConfigDict(extra="ignore")

    files: dict[str, str] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    """Response of GET /health."""

    model_config = ConfigDict(extra="ignore")

    status: str = "ok"
    mode: AnalyzerMode
    epss_version: str = EPSS_VERSION
