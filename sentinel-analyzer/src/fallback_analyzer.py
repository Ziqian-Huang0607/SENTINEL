"""Rule-based, deterministic SENTINEL analyzer.

Produces the same ``AnalysisOutput`` contract as the LLM path, with
``analyzer_mode="fallback"``. Attack chains come from the deterministic
candidate templates in ``src.attack_chain`` (unauthenticated
redis/mongo/elasticsearch, lateral SMB/SSH/RDP/WinRM staging,
default-credential services, exposed admin panels and unpatched RCE CVEs),
sorted by descending risk with priority assigned by rank. Remediation comes
from the tiered library in ``src.remediation`` and the risk score is
recomputed with the exact SPEC formula and verified against the scan's
score (the maximum is used).
"""

from __future__ import annotations

from src.attack_chain import CandidateChain, extract_candidate_chains
from src.models import (
    AnalysisOutput,
    AnalyzerMode,
    AttackChain,
    Criticality,
    ScanInput,
    TrustZone,
    compute_risk_score,
)
from src.remediation import build_remediation, tier_profile


def _sort_key(chain: CandidateChain) -> tuple[float, str, tuple[str, ...], str]:
    """Total deterministic ordering: risk desc, then rule/path/technique."""
    return (-chain.risk, chain.rule, chain.path, chain.mitre_technique)


def recompute_risk_score(scan: ScanInput) -> float:
    """Max per-finding deterministic risk score (host context applied).

    Covers CVE vulnerabilities (CVSS + EPSS, KEV floor) and R8 posture
    findings (severity, EPSS = 0) through the same formula — identical to
    the scanner's scan-level aggregation.
    """
    hosts_by_ip = {host.ip: host for host in scan.hosts}
    best = 0.0
    for vuln in scan.vulnerabilities:
        host = hosts_by_ip.get(vuln.host)
        zone = host.trust_zone if host else TrustZone.internal
        crit = host.criticality if host else Criticality.workstation
        best = max(
            best,
            compute_risk_score(vuln.cvss, vuln.epss, zone, crit, kev=vuln.kev),
        )
    for finding in scan.posture_findings:
        host = hosts_by_ip.get(finding.host)
        zone = host.trust_zone if host else TrustZone.internal
        crit = host.criticality if host else Criticality.workstation
        best = max(best, compute_risk_score(finding.severity, 0.0, zone, crit))
    return round(best, 2)


def analyze_fallback(scan: ScanInput) -> AnalysisOutput:
    """Analyze a scan deterministically with the rule-based engine."""
    candidates = sorted(extract_candidate_chains(scan), key=_sort_key)
    attack_chains = [
        AttackChain(
            path=list(candidate.path),
            description=candidate.description,
            mitre_technique=candidate.mitre_technique,
            confidence=candidate.confidence,
            impact=candidate.impact,
            priority=rank,
        )
        for rank, candidate in enumerate(candidates, start=1)
    ]

    classes: list[str] = []
    for candidate in candidates:
        if candidate.rule not in classes:
            classes.append(candidate.rule)
    remediation = build_remediation(classes)

    recomputed = recompute_risk_score(scan)
    risk_score = round(max(recomputed, scan.risk_score), 2)
    observations = _build_observations(
        scan, len(attack_chains), recomputed, risk_score
    )
    return AnalysisOutput(
        attack_chains=attack_chains,
        remediation=remediation,
        risk_score=risk_score,
        observations=observations,
        analyzer_mode=AnalyzerMode.fallback,
        posture_findings=list(scan.posture_findings),
    )


def _build_observations(
    scan: ScanInput,
    chain_count: int,
    recomputed: float,
    risk_score: float,
) -> list[str]:
    """Deterministic observation list summarizing counts and mode."""
    open_ports = sum(
        1
        for host in scan.hosts
        for port in host.ports
        if port.state.lower() == "open"
    )
    profile = tier_profile(scan.tier)
    observations = [
        (
            f"Analyzed {len(scan.hosts)} host(s), {open_ports} open port(s), "
            f"{len(scan.vulnerabilities)} CVE finding(s) and "
            f"{len(scan.posture_findings)} posture exposure(s) for tier "
            f"'{scan.tier.value}'."
        ),
        (
            f"Identified {chain_count} attack chain(s) with the rule-based "
            "engine; priority is assigned by descending risk."
        ),
        (
            f"Risk score {risk_score} is the maximum of the "
            f"scanner-reported score ({scan.risk_score}) and the "
            f"deterministic recomputation ({recomputed})."
        ),
    ]
    if risk_score >= profile.risk_threshold:
        observations.append(
            f"Risk score {risk_score} is at or above the "
            f"'{scan.tier.value}' tier threshold of "
            f"{profile.risk_threshold}; escalate remediation per the tier "
            "table."
        )
    else:
        observations.append(
            f"Risk score {risk_score} is below the '{scan.tier.value}' "
            f"tier threshold of {profile.risk_threshold}."
        )
    observations.append(
        "Analyzer mode: fallback (rule-based). The Ollama LLM was "
        "unavailable or failed; results are deterministic."
    )
    return observations
