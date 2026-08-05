"""R8 hardening tests: posture findings, chain grounding, defensive
remediation enforcement, and posture-aware risk recomputation.

Regression coverage for the real-network failure mode: 0 CVE matches
reported as 0.00 risk with uniform LLM filler chains and an offensive
"exploit the service" remediation item.
"""

from __future__ import annotations

from src.attack_chain import (
    extract_candidate_chains,
    ground_chains,
    observed_path_steps,
)
from src.fallback_analyzer import analyze_fallback, recompute_risk_score
from src.llm_client import (
    ANALYSIS_RULES,
    build_user_prompt,
    enforce_defensive_remediation,
    finalize_analysis,
)
from src.models import (
    AnalysisOutput,
    AnalyzerMode,
    AttackChain,
    ScanInput,
    TieredRemediation,
)


def _posture_scan(scan_payload: dict) -> ScanInput:
    """The fixture scan plus one posture exposure on an observed host."""
    payload = dict(scan_payload)
    payload["posture_findings"] = [
        {
            "id": "POSTURE-UNAUTH-WEB",
            "host": "192.168.1.45",
            "port": 8080,
            "severity": 6.5,
            "title": "Web interface reachable without authentication",
            "evidence": "GET / -> 200; Server: nginx",
        }
    ]
    return ScanInput.model_validate(payload)


def test_posture_findings_parse_and_default_empty(scan_payload: dict) -> None:
    """Posture findings parse; pre-R8 payloads default to an empty list."""
    plain = ScanInput.model_validate(scan_payload)
    assert plain.posture_findings == []
    scan = _posture_scan(scan_payload)
    assert scan.posture_findings[0].id == "POSTURE-UNAUTH-WEB"
    assert scan.posture_findings[0].severity == 6.5


def test_recompute_risk_score_includes_posture(scan_payload: dict) -> None:
    """Posture findings enter the deterministic max with EPSS = 0."""
    plain = ScanInput.model_validate(scan_payload)
    with_posture = _posture_scan(scan_payload)
    # Posture: 6.5*0.25 + 0 + exposure*2.5 + criticality*1.5 on the redis
    # host (internal 0.4 / workstation 0.4) = 1.625 + 1.0 + 0.6 = 3.23 —
    # below the fixture CVE max, so the max is unchanged but the posture
    # contribution is provably computed.
    assert recompute_risk_score(with_posture) >= recompute_risk_score(plain)

    # A posture-only scan must score non-zero (the 0.00-is-safe bug).
    posture_only_payload = dict(scan_payload)
    posture_only_payload["vulnerabilities"] = []
    posture_only_payload["posture_findings"] = [
        {
            "id": "POSTURE-UNAUTH-WEB-GATEWAY",
            "host": "192.168.1.45",
            "port": 80,
            "severity": 7.5,
            "title": "Gateway/router web admin reachable without authentication",
            "evidence": "GET / -> 200",
        }
    ]
    posture_only_payload["risk_score"] = 5.13
    scan = ScanInput.model_validate(posture_only_payload)
    # fixture host .45 is dmz (0.7) / dc (1.0):
    # 7.5*0.25 + 0 + 0.7*10*0.25 + 1.0*10*0.15 = 1.875 + 1.75 + 1.5 = 5.13
    assert recompute_risk_score(scan) == 5.13


def test_posture_candidates_use_weakness_specific_techniques(
    scan_payload: dict,
) -> None:
    """Posture findings yield candidate chains with per-class techniques."""
    payload = dict(scan_payload)
    payload["posture_findings"] = [
        {
            "id": "POSTURE-UNAUTH-WEB-GATEWAY",
            "host": "192.168.1.45",
            "port": 80,
            "severity": 7.5,
            "title": "Gateway/router web admin reachable without authentication",
            "evidence": "GET / -> 200",
        },
        {
            "id": "POSTURE-CLEARTEXT",
            "host": "192.168.1.45",
            "port": 23,
            "severity": 6.5,
            "title": "Telnet exposes cleartext credentials",
            "evidence": "port 23 open",
        },
    ]
    scan = ScanInput.model_validate(payload)
    posture_chains = [
        c for c in extract_candidate_chains(scan) if c.rule == "posture_exposure"
    ]
    techniques = {c.path[0]: c.mitre_technique for c in posture_chains}
    assert techniques["192.168.1.45:80"] == "T1190"
    assert techniques["192.168.1.45:23"] == "T1040"
    assert len({c.mitre_technique for c in posture_chains}) > 1, (
        "posture chains must not share one uniform technique"
    )


def test_fallback_passes_posture_through(scan_payload: dict) -> None:
    """Fallback AnalysisOutput carries posture findings for the report."""
    out = analyze_fallback(_posture_scan(scan_payload))
    assert [f.id for f in out.posture_findings] == ["POSTURE-UNAUTH-WEB"]


def _chain(path: list[str], priority: int) -> AttackChain:
    return AttackChain(
        path=path,
        description="test chain",
        mitre_technique="T1190",
        confidence=0.5,
        impact=0.5,
        priority=priority,
    )


def test_grounding_drops_invented_hosts_and_ports(scan: ScanInput) -> None:
    """Chains referencing absent hosts/ports are dropped; kept ones renumber."""
    observed = observed_path_steps(scan)
    real_step = min(observed)
    chains = [
        _chain([real_step], 1),
        _chain(["203.0.113.99:80"], 2),  # invented host
        _chain([real_step, "192.168.1.45:9999"], 3),  # invented port
    ]
    kept, dropped = ground_chains(chains, scan)
    assert dropped == 2
    assert [c.priority for c in kept] == [1]
    assert kept[0].path == [real_step]


def test_grounding_accepts_posture_locations(scan_payload: dict) -> None:
    """Posture finding host:port pairs are legitimate chain steps."""
    scan = _posture_scan(scan_payload)
    chains = [_chain(["192.168.1.45:8080"], 1)]
    kept, dropped = ground_chains(chains, scan)
    assert dropped == 0
    assert len(kept) == 1


def _analysis_with(items: dict[str, list[str]]) -> AnalysisOutput:
    return AnalysisOutput(
        attack_chains=[],
        remediation=TieredRemediation(**items),
        risk_score=0.0,
        observations=[],
        analyzer_mode=AnalyzerMode.llm,
    )


def test_offensive_remediation_items_are_dropped() -> None:
    """'Exploit the CUPS service' style items never reach the report."""
    analysis = _analysis_with(
        {
            "daily": ["Enable authentication on the CUPS admin interface"],
            "authority": ["Restrict printer ports to admin subnets"],
            "hacker": ["Exploit unauthenticated access to the CUPS service"],
            "military": ["Use the open admin panel to compromise the router"],
        }
    )
    cleaned, dropped = enforce_defensive_remediation(analysis)
    assert dropped == 2
    assert cleaned.remediation.daily == ["Enable authentication on the CUPS admin interface"]
    assert cleaned.remediation.authority == ["Restrict printer ports to admin subnets"]
    assert cleaned.remediation.hacker == []
    assert cleaned.remediation.military == []


def test_finalize_analysis_full_pipeline(scan: ScanInput) -> None:
    """finalize: grounds chains, filters offensive items, pins risk, passes
    posture through, and records every intervention as an observation."""
    observed = min(observed_path_steps(scan))
    analysis = AnalysisOutput(
        attack_chains=[_chain([observed], 1), _chain(["198.51.100.7:22"], 2)],
        remediation=TieredRemediation(
            daily=["Patch the service"],
            authority=[],
            hacker=["Exploit the weak admin panel"],
            military=[],
        ),
        risk_score=0.0,
        observations=[],
        analyzer_mode=AnalyzerMode.llm,
    )
    out = finalize_analysis(analysis, scan)
    assert [c.priority for c in out.attack_chains] == [1]
    assert out.remediation.hacker == []
    assert out.risk_score == round(
        max(recompute_risk_score(scan), scan.risk_score), 2
    )
    assert out.posture_findings == list(scan.posture_findings)
    joined = " ".join(out.observations)
    assert "Dropped 1 LLM attack chain(s)" in joined
    assert "Dropped 1 remediation item(s)" in joined


def test_prompt_carries_analysis_rules(scan: ScanInput) -> None:
    """The user prompt embeds the grounding/defensive rules verbatim."""
    prompt = build_user_prompt(scan, [])
    assert ANALYSIS_RULES in prompt
    assert "observed host or host:port" in prompt
    assert "NEVER instruct exploitation" in prompt
