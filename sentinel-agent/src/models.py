"""Pydantic contracts for the SENTINEL agent layer.

Mirrors docs/agent-spec.md section 4 exactly — that spec is sacred; if this
file and the spec disagree, the spec wins.

Agent findings enter the deterministic risk formula exactly like R8 posture
findings: severity as the CVSS term, EPSS = 0, no KEV floor, host
exposure/criticality applied. Severities come from CLASS_SEVERITY (fixed
constants), never from the LLM — model-chosen scores would be untestable.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

FindingClass = Literal[
    "SERVICE-IDENT",  # unknown port identified (informational)
    "DEFAULT-PANEL",  # known router/admin panel matched
    "SENSITIVE-SERVICE",  # sensitive service confirmed reachable
    "MISCONFIG",  # other configuration weakness
    "DRIFT",  # change vs memory
]

# Fixed pseudo-CVSS per finding class (agent-spec.md section 4). DRIFT has no
# intrinsic severity; the underlying finding's class drives scoring.
CLASS_SEVERITY: dict[str, float] = {
    "SERVICE-IDENT": 2.0,
    "DEFAULT-PANEL": 7.0,
    "SENSITIVE-SERVICE": 5.5,
    "MISCONFIG": 5.0,
    "DRIFT": 0.0,
}

InvestigationStatus = Literal["concluded", "inconclusive", "budget_exhausted", "skipped"]

DriftKind = Literal[
    "NEW_HOST",
    "GONE_HOST",
    "NEW_PORT",
    "CLOSED_PORT",
    "VERSION_CHANGE",
    "AUTH_CHANGE",
]


class EvidenceRef(BaseModel):
    """One compacted tool result recorded in an investigation transcript."""

    id: str  # "E1", "E2", ... per investigation
    tool: str
    args: dict
    excerpt: str = Field(max_length=600)
    ts: datetime


class AgentFinding(BaseModel):
    """A grounded agent conclusion. Every claim cites transcript evidence."""

    id: str  # "AGENT-<CLASS>-<n>" per target
    finding_class: FindingClass
    host: str
    port: int = Field(ge=1, le=65535)
    severity: float = Field(ge=0.0, le=10.0)
    title: str
    detail: str = ""
    evidence: list[str] = Field(default_factory=list)  # evidence ids
    confidence: float = Field(ge=0.0, le=1.0)

    def severity_for_class(self) -> float:
        """Canonical severity: the class constant, not the LLM-supplied value."""
        return CLASS_SEVERITY[self.finding_class]


class TargetBrief(BaseModel):
    """Deterministic input describing why a target is investigated."""

    host: str
    ports: list[int]
    trigger: str  # e.g. "unauth_posture", "unknown_service", "gateway", "cve"
    hints: dict = Field(default_factory=dict)  # service/version/posture context


class TargetInvestigation(BaseModel):
    """Outcome of one per-target agent run."""

    host: str
    ports: list[int]
    trigger: str
    status: InvestigationStatus
    turns: int = 0
    summary: str = ""
    findings: list[AgentFinding] = Field(default_factory=list)
    transcript_path: str = ""


class DriftEvent(BaseModel):
    """One change between the latest scan state and the previous one."""

    kind: DriftKind
    host: str
    port: int | None = None
    before: str = ""
    after: str = ""
    ts: datetime


class AgentReport(BaseModel):
    """agent_report.json — the agent layer's output contract."""

    agent_version: str
    scan_id: str
    target: str
    tier: str
    started_at: datetime
    finished_at: datetime
    model: str  # "ollama/llama3.1:8b" | "playbook"
    investigations: list[TargetInvestigation] = Field(default_factory=list)
    findings: list[AgentFinding] = Field(default_factory=list)
    drift: list[DriftEvent] = Field(default_factory=list)
    risk_score: float = Field(ge=0.0, le=10.0)
    observations: list[str] = Field(default_factory=list)
