"""Tests for the deterministic rule-based fallback analyzer."""

from __future__ import annotations

from src.attack_chain import extract_candidate_chains
from src.fallback_analyzer import analyze_fallback, recompute_risk_score
from src.models import AnalysisOutput, AnalyzerMode, ScanInput


def test_fallback_is_deterministic(scan: ScanInput) -> None:
    """Same input twice yields byte-identical output."""
    first = analyze_fallback(scan)
    second = analyze_fallback(scan)
    assert first.model_dump() == second.model_dump()
    assert first.model_dump_json() == second.model_dump_json()


def test_candidate_extraction_is_deterministic(scan: ScanInput) -> None:
    """Candidate chains are identical across runs."""
    assert extract_candidate_chains(scan) == extract_candidate_chains(scan)


def test_fallback_output_schema_conformance(scan: ScanInput) -> None:
    """Fallback output satisfies the AnalysisOutput contract."""
    out = analyze_fallback(scan)
    validated = AnalysisOutput.model_validate(out.model_dump(mode="json"))
    assert validated == out
    assert out.analyzer_mode is AnalyzerMode.fallback
    assert out.attack_chains, "fixture scan must yield attack chains"
    assert [c.priority for c in out.attack_chains] == list(
        range(1, len(out.attack_chains) + 1)
    )
    for chain in out.attack_chains:
        assert 0.0 <= chain.confidence <= 1.0
        assert 0.0 <= chain.impact <= 1.0
        assert chain.mitre_technique.startswith("T")
        assert chain.path


def test_fallback_detects_fixture_chains(scan: ScanInput) -> None:
    """The rule templates fire on the rich fixture scan."""
    out = analyze_fallback(scan)
    paths = {tuple(chain.path) for chain in out.attack_chains}

    # Unauthenticated redis and elasticsearch are flagged.
    assert ("192.168.1.45:6379",) in paths
    assert ("192.168.1.10:9200",) in paths
    # Lateral staging from unauth redis to smb and ssh.
    assert ("192.168.1.45:6379", "192.168.1.50:445") in paths
    assert ("192.168.1.45:6379", "192.168.1.45:22") in paths
    # Closed rdp port never appears in any chain.
    assert all("192.168.1.50:3389" not in path for path in paths)
    # Unpatched RCE CVE chain present with highest-priority ordering by risk.
    cve_chains = [
        c
        for c in out.attack_chains
        if "CVE-2024-21667" in c.description
    ]
    assert cve_chains, "expected an unpatched-rce chain for the fixture CVE"


def test_fallback_chains_sorted_by_risk_desc(scan: ScanInput) -> None:
    """Priority 1 is the riskiest chain (risk desc, deterministic ties)."""
    candidates = extract_candidate_chains(scan)
    out = analyze_fallback(scan)
    risk_by_path = {c.path: c.risk for c in candidates}
    risks = [risk_by_path[tuple(c.path)] for c in out.attack_chains]
    assert risks == sorted(risks, reverse=True)


def test_fallback_risk_score_uses_max(scan: ScanInput) -> None:
    """risk_score = max(deterministic recomputation, scan's own score)."""
    # Fixture vuln: 9.8*0.25 + 0.85*10*0.35 + 0.7*10*0.25 + 1.0*10*0.15
    #   = 2.45 + 2.975 + 1.75 + 1.5 = 8.675 -> 8.68 (scanner round2 parity)
    assert recompute_risk_score(scan) == 8.68
    assert analyze_fallback(scan).risk_score == 8.97


def test_recompute_risk_score_kev_floor(scan: ScanInput) -> None:
    """A kev=true vuln with raw < 9.0 recomputes to >= 9.0; kev=false doesn't."""
    flagged = scan.model_copy(deep=True)
    flagged.vulnerabilities[0].kev = True
    # Fixture raw recompute is 8.68 (see above); the KEV floor lifts it.
    assert recompute_risk_score(scan) == 8.68
    assert recompute_risk_score(flagged) == 9.0
    assert analyze_fallback(flagged).risk_score == 9.0


def test_fallback_empty_scan_still_valid() -> None:
    """A scan with no hosts/vulns still yields a valid, deterministic output."""
    scan = ScanInput.model_validate(
        {
            "scan_id": "empty-1",
            "target": "10.0.0.0/30",
            "tier": "daily",
            "started_at": "2024-05-01T10:00:00Z",
            "finished_at": "2024-05-01T10:00:05Z",
            "hosts": [],
            "vulnerabilities": [],
            "risk_score": 3.25,
        }
    )
    out = analyze_fallback(scan)
    assert out.analyzer_mode is AnalyzerMode.fallback
    assert out.attack_chains == []
    assert out.risk_score == 3.25  # max(0.0 recomputed, 3.25 reported)
    for tier in ("daily", "authority", "hacker", "military"):
        assert getattr(out.remediation, tier), f"tier {tier} must be non-empty"
    assert any("fallback" in obs for obs in out.observations)


def test_fallback_observations_summarize_counts(scan: ScanInput) -> None:
    """Observations summarize host/port/vuln counts and the mode notice."""
    out = analyze_fallback(scan)
    joined = " ".join(out.observations)
    assert "3 host(s)" in joined
    assert "5 open port(s)" in joined
    assert "1 CVE finding(s)" in joined
    assert "posture exposure(s)" in joined
    assert "fallback" in joined
