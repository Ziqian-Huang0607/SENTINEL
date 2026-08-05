"""Report generator for the SENTINEL vulnerability assessment platform.

Public entry point: :func:`generate`. Inputs are validated with pydantic
models that mirror the ScanInput / AnalysisOutput contracts from SPEC.md.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Tier = Literal["daily", "authority", "hacker", "military"]
TrustZone = Literal["internet", "dmz", "internal", "mgmt", "airgap"]
Criticality = Literal["dc", "app", "workstation", "iot"]
AnalyzerMode = Literal["llm", "fallback"]
ReportFormat = Literal["pdf", "json", "sarif"]

SUPPORTED_FORMATS: tuple[str, ...] = ("pdf", "json", "sarif")


class Port(BaseModel):
    """A single discovered port on a host (ScanInput contract)."""

    model_config = ConfigDict(extra="allow")

    port: int = Field(ge=0, le=65535)
    protocol: str = "tcp"
    state: str = "open"
    service: str | None = None
    version: str | None = None
    banner: str | None = None


class Host(BaseModel):
    """A discovered host (ScanInput contract)."""

    model_config = ConfigDict(extra="allow")

    ip: str
    hostname: str | None = None
    mac: str | None = None
    os_guess: str | None = None
    trust_zone: TrustZone = "internal"
    criticality: Criticality = "workstation"
    ports: list[Port] = Field(default_factory=list)


class Vulnerability(BaseModel):
    """A single vulnerability finding (ScanInput contract)."""

    model_config = ConfigDict(extra="allow")

    cve_id: str
    cvss: float = Field(ge=0.0, le=10.0)
    epss: float = Field(ge=0.0, le=1.0)
    host: str
    port: int = Field(ge=0, le=65535)
    summary: str = ""


class PostureFinding(BaseModel):
    """An exposure finding without a CVE identifier (R8)."""

    model_config = ConfigDict(extra="allow")

    id: str
    host: str
    port: int = Field(ge=0, le=65535)
    severity: float = Field(ge=0.0, le=10.0)
    title: str = ""
    evidence: str = ""


class CveDbInfo(BaseModel):
    """Embedded CVE signature DB provenance (R8 coverage note)."""

    model_config = ConfigDict(extra="allow")

    version: str = ""
    signatures: int = 0


class ScanInput(BaseModel):
    """Scanner output / analyzer ScanInput contract (SPEC.md section 1)."""

    model_config = ConfigDict(extra="allow")

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
    """A single attack chain (AnalysisOutput contract)."""

    model_config = ConfigDict(extra="allow")

    path: list[str] = Field(default_factory=list)
    description: str = ""
    mitre_technique: str = ""
    confidence: float = Field(ge=0.0, le=1.0)
    impact: float = Field(ge=0.0, le=1.0)
    priority: int = 0


class Remediation(BaseModel):
    """Four-tier remediation guidance (AnalysisOutput contract)."""

    model_config = ConfigDict(extra="allow")

    daily: list[str] = Field(default_factory=list)
    authority: list[str] = Field(default_factory=list)
    hacker: list[str] = Field(default_factory=list)
    military: list[str] = Field(default_factory=list)


class AnalysisOutput(BaseModel):
    """Analyzer output contract (SPEC.md section 2)."""

    model_config = ConfigDict(extra="allow")

    attack_chains: list[AttackChain] = Field(default_factory=list)
    remediation: Remediation = Field(default_factory=Remediation)
    risk_score: float = Field(ge=0.0, le=10.0)
    observations: list[str] = Field(default_factory=list)
    analyzer_mode: AnalyzerMode = "fallback"


def _report_stem(scan_id: str) -> str:
    """Return a filesystem-safe report filename stem for a scan id."""
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in scan_id)
    return f"sentinel-report-{safe}"


def generate(
    scan: dict[str, Any],
    analysis: dict[str, Any],
    formats: list[str],
    out_dir: str,
) -> dict[str, str]:
    """Generate SENTINEL reports in the requested formats.

    Args:
        scan: Scanner output document (ScanInput contract).
        analysis: Analyzer output document (AnalysisOutput contract).
        formats: Any subset of ``["pdf", "json", "sarif"]``.
        out_dir: Directory the report files are written to (created if
            missing).

    Returns:
        Mapping of format name to the absolute path of the generated file.

    Raises:
        pydantic.ValidationError: If ``scan`` or ``analysis`` violate the
            contracts.
        ValueError: If an unsupported format is requested.
    """
    scan_model = ScanInput.model_validate(scan)
    analysis_model = AnalysisOutput.model_validate(analysis)

    unknown = [f for f in formats if f not in SUPPORTED_FORMATS]
    if unknown:
        raise ValueError(
            f"Unsupported report format(s): {unknown}. "
            f"Supported: {list(SUPPORTED_FORMATS)}"
        )

    out_path = Path(out_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)
    stem = _report_stem(scan_model.scan_id)

    from src.formatters import json_formatter, pdf_formatter, sarif_formatter

    files: dict[str, str] = {}
    for fmt in formats:
        target = out_path / f"{stem}.{fmt}"
        if fmt == "pdf":
            files["pdf"] = pdf_formatter.render_pdf(scan_model, analysis_model, str(target))
        elif fmt == "json":
            files["json"] = json_formatter.render_json(scan_model, analysis_model, str(target))
        elif fmt == "sarif":
            files["sarif"] = sarif_formatter.render_sarif(scan_model, analysis_model, str(target))
    return files
