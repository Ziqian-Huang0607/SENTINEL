"""Tests for the pydantic contract models (SPEC interface contracts)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from src.models import (
    EPSS_VERSION,
    KEV_RISK_FLOOR,
    AnalysisOutput,
    AnalyzerMode,
    AttackChain,
    Criticality,
    ScanInput,
    Tier,
    TieredRemediation,
    TrustZone,
    compute_risk_score,
)


def test_scan_input_valid_fixture(scan_payload: dict) -> None:
    """The rich fixture scan validates against the ScanInput contract."""
    scan = ScanInput.model_validate(scan_payload)
    assert scan.scan_id == scan_payload["scan_id"]
    assert scan.tier is Tier.hacker
    assert len(scan.hosts) == 3
    assert scan.hosts[0].trust_zone is TrustZone.dmz
    assert scan.hosts[0].criticality is Criticality.dc
    assert scan.hosts[0].ports[0].service == "redis"
    assert scan.vulnerabilities[0].cve_id == "CVE-2024-21667"
    assert scan.risk_score == 8.97


def test_scan_input_minimal_defaults() -> None:
    """Only the contract-required fields are needed; the rest defaults."""
    scan = ScanInput.model_validate(
        {
            "scan_id": "s-1",
            "target": "10.0.0.1",
            "tier": "daily",
            "started_at": "2024-05-01T10:00:00Z",
            "finished_at": "2024-05-01T10:00:30Z",
            "risk_score": 0.0,
        }
    )
    assert scan.hosts == []
    assert scan.vulnerabilities == []
    host = scan.model_copy(update={"hosts": []})
    assert host.hosts == []


def test_host_field_defaults() -> None:
    """Optional host fields default; zone/criticality enums coerce."""
    from src.models import Host

    parsed = Host.model_validate({"ip": "10.0.0.5"})
    assert parsed.hostname is None
    assert parsed.trust_zone is TrustZone.internal
    assert parsed.criticality is Criticality.workstation
    assert parsed.ports == []


@pytest.mark.parametrize(
    ("mutation", "field"),
    [
        (lambda p: p.update({"tier": "platinum"}), "tier"),
        (lambda p: p.pop("scan_id"), "scan_id"),
        (lambda p: p.pop("target"), "target"),
        (lambda p: p.pop("started_at"), "started_at"),
        (lambda p: p.update({"started_at": "not-a-date"}), "started_at"),
        (lambda p: p.update({"risk_score": 11.5}), "risk_score"),
        (lambda p: p["hosts"][0].update({"trust_zone": "orbit"}), "trust_zone"),
        (
            lambda p: p["hosts"][0].update({"criticality": "everything"}),
            "criticality",
        ),
        (lambda p: p["hosts"][0]["ports"][0].update({"port": 70000}), "port"),
        (lambda p: p["vulnerabilities"][0].update({"cvss": 10.5}), "cvss"),
        (lambda p: p["vulnerabilities"][0].update({"epss": 1.5}), "epss"),
    ],
)
def test_scan_input_bad_payloads_rejected(
    scan_payload: dict, mutation, field: str
) -> None:
    """Schema violations raise pydantic ValidationError (API gives 422)."""
    mutation(scan_payload)
    with pytest.raises(ValidationError) as excinfo:
        ScanInput.model_validate(scan_payload)
    assert field in str(excinfo.value)


def test_analysis_output_roundtrip() -> None:
    """AnalysisOutput serializes per the analysis.json contract."""
    out = AnalysisOutput(
        attack_chains=[
            AttackChain(
                path=["192.168.1.45:6379"],
                description="Unauthenticated redis.",
                mitre_technique="T1190",
                confidence=0.9,
                impact=0.92,
                priority=1,
            )
        ],
        remediation=TieredRemediation(
            daily=["Enable auth"],
            authority=["ACL the service"],
            hacker=["Rotate keys"],
            military=["Airgap the host"],
        ),
        risk_score=8.97,
        observations=["one host"],
        analyzer_mode=AnalyzerMode.llm,
    )
    dumped = out.model_dump(mode="json")
    assert dumped["analyzer_mode"] == "llm"
    assert set(dumped["remediation"]) == {
        "daily",
        "authority",
        "hacker",
        "military",
    }
    assert AnalysisOutput.model_validate(dumped) == out


@pytest.mark.parametrize("mode", ["llm", "fallback"])
def test_analyzer_mode_enum_values(mode: str) -> None:
    """AnalyzerMode accepts exactly the two contract modes."""
    assert AnalyzerMode(mode).value == mode


def test_analyzer_mode_invalid() -> None:
    """Unknown analyzer modes are rejected."""
    with pytest.raises(ValidationError):
        AnalysisOutput.model_validate(
            {
                "attack_chains": [],
                "remediation": {},
                "risk_score": 1.0,
                "observations": [],
                "analyzer_mode": "quantum",
            }
        )


def test_attack_chain_bounds() -> None:
    """Confidence/impact are bounded to [0, 1], priority >= 1."""
    with pytest.raises(ValidationError):
        AttackChain(
            path=["a:1"],
            description="x",
            mitre_technique="T1110",
            confidence=1.5,
            impact=0.5,
            priority=1,
        )
    with pytest.raises(ValidationError):
        AttackChain(
            path=["a:1"],
            description="x",
            mitre_technique="T1110",
            confidence=0.5,
            impact=0.5,
            priority=0,
        )


def test_compute_risk_score_matches_spec_formula() -> None:
    """RISK_SCORE = CVSS*.25 + EPSS*10*.35 + EXPOSURE*10*.25 + CRIT*10*.15."""
    # 9.8*0.25 + 0.85*10*0.35 + 0.7*10*0.25 + 1.0*10*0.15
    #   = 2.45 + 2.975 + 1.75 + 1.5 = 8.675 -> 8.68
    # (half-up 1e-9 nudge, matching the scanner's round2)
    assert (
        compute_risk_score(9.8, 0.85, TrustZone.dmz, Criticality.dc) == 8.68
    )
    # 9.8*0.25 + 0.85*10*0.35 + 0.4*10*0.25 + 0.4*10*0.15
    #   = 2.45 + 2.975 + 1.0 + 0.6 = 7.025 -> 7.03 (decimal half boundary)
    assert (
        compute_risk_score(9.8, 0.85, TrustZone.internal, Criticality.workstation)
        == 7.03
    )
    # Saturating case: everything maximal -> 10.0
    assert (
        compute_risk_score(10.0, 1.0, TrustZone.internet, Criticality.dc)
        == 10.0
    )
    # Zero CVSS/EPSS on airgap: only the iot criticality contributes.
    # 0 + 0 + 0 + 0.1*10*0.15 = 0.15
    assert (
        compute_risk_score(0.0, 0.0, TrustZone.airgap, Criticality.iot)
        == 0.15
    )
    # 4.0*0.25 + 0.1*10*0.35 + 0.4*10*0.25 + 0.4*10*0.15
    #   = 1.0 + 0.35 + 1.0 + 0.6 = 2.95
    assert (
        compute_risk_score(4.0, 0.1, TrustZone.internal, Criticality.workstation)
        == 2.95
    )
    # 7.0*0.25 + 0.5*10*0.35 + 0.1*10*0.25 + 0.1*10*0.15
    #   = 1.75 + 1.75 + 0.25 + 0.15 = 3.90
    assert (
        compute_risk_score(7.0, 0.5, TrustZone.mgmt, Criticality.iot) == 3.90
    )


def test_compute_risk_score_kev_floor() -> None:
    """kev=true floors the score at KEV_RISK_FLOOR; kev=false is unchanged."""
    # Raw score 2.95 (see above); KEV-flagged it is floored to 9.0.
    raw = compute_risk_score(
        4.0, 0.1, TrustZone.internal, Criticality.workstation
    )
    assert raw == 2.95
    floored = compute_risk_score(
        4.0, 0.1, TrustZone.internal, Criticality.workstation, kev=True
    )
    assert floored == KEV_RISK_FLOOR == 9.0
    # A raw score above the floor is left untouched by the KEV rule:
    # 9.8*0.25 + 0.85*10*0.35 + 1.0*10*0.25 + 1.0*10*0.15
    #   = 2.45 + 2.975 + 2.5 + 1.5 = 9.425 -> 9.43 (>= 9.0, no change).
    assert (
        compute_risk_score(
            9.8, 0.85, TrustZone.internet, Criticality.dc, kev=True
        )
        == compute_risk_score(9.8, 0.85, TrustZone.internet, Criticality.dc)
        == 9.43
    )
    # kev defaults to False.
    assert (
        compute_risk_score(4.0, 0.1, TrustZone.internal, Criticality.workstation)
        == compute_risk_score(
            4.0, 0.1, TrustZone.internal, Criticality.workstation, kev=False
        )
    )


def test_new_contract_fields_default_and_roundtrip(scan_payload: dict) -> None:
    """kev/banner_confidence are additive: default off, accepted when sent."""
    from src.models import Port, Vulnerability

    vuln = Vulnerability.model_validate(
        {"cve_id": "CVE-2024-0001", "cvss": 1.0, "epss": 0.1,
         "host": "10.0.0.1", "port": 80}
    )
    assert vuln.kev is False
    flagged = Vulnerability.model_validate(
        {"cve_id": "CVE-2024-0001", "cvss": 1.0, "epss": 0.1,
         "host": "10.0.0.1", "port": 80, "kev": True}
    )
    assert flagged.kev is True

    port = Port.model_validate({"port": 22})
    assert port.banner_confidence is None
    graded = Port.model_validate({"port": 22, "banner_confidence": "high"})
    assert graded.banner_confidence == "high"

    # Extra keys are still ignored; the new fields flow through ScanInput.
    scan_payload["vulnerabilities"][0]["kev"] = True
    scan_payload["hosts"][0]["ports"][0]["banner_confidence"] = "medium"
    scan = ScanInput.model_validate(scan_payload)
    assert scan.vulnerabilities[0].kev is True
    assert scan.hosts[0].ports[0].banner_confidence == "medium"


def test_epss_version_constant() -> None:
    """The EPSS vintage constant is pinned at v4."""
    assert EPSS_VERSION == "v4"


def test_enums_cover_spec_values() -> None:
    """Enums carry exactly the SPEC value sets."""
    assert {t.value for t in Tier} == {"daily", "authority", "hacker", "military"}
    assert {z.value for z in TrustZone} == {
        "internet",
        "dmz",
        "internal",
        "mgmt",
        "airgap",
    }
    assert {c.value for c in Criticality} == {"dc", "app", "workstation", "iot"}
