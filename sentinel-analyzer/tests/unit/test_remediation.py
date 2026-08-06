"""Tests for the tiered remediation library."""

from __future__ import annotations

import pytest
from src.models import Tier
from src.remediation import (
    REMEDIATION_LIBRARY,
    TIER_PROFILES,
    build_remediation,
    remediation_for_class,
    tier_profile,
)

ALL_TIERS = ("daily", "authority", "hacker", "military")


@pytest.mark.parametrize("vuln_class", sorted(REMEDIATION_LIBRARY))
def test_every_class_covers_all_four_tiers(vuln_class: str) -> None:
    """Each vuln class has non-empty controls on all four tiers."""
    remediation = remediation_for_class(vuln_class)
    for tier in ALL_TIERS:
        assert getattr(remediation, tier), (
            f"class {vuln_class!r} has no controls for tier {tier!r}"
        )


def test_unknown_class_yields_empty_lists() -> None:
    """Unknown classes produce empty (but valid) tier lists."""
    remediation = remediation_for_class("does_not_exist")
    for tier in ALL_TIERS:
        assert getattr(remediation, tier) == []


def test_build_remediation_always_includes_baseline() -> None:
    """Even with no classes, every tier is non-empty via the baseline."""
    remediation = build_remediation([])
    for tier in ALL_TIERS:
        assert getattr(remediation, tier)


def test_build_remediation_merges_and_dedupes() -> None:
    """Class controls merge into the baseline without duplicates."""
    merged = build_remediation(["unauth_service", "unauth_service", "unpatched_rce"])
    for tier in ALL_TIERS:
        controls = getattr(merged, tier)
        assert len(controls) == len(set(controls)), "controls must be deduped"
    baseline = build_remediation([])
    assert len(merged.daily) > len(baseline.daily)
    assert any("Redis" in c for c in merged.daily)
    assert any("RCE" in c for c in merged.authority)
    assert any("airgap" in c.lower() for c in merged.military)


def test_tier_profiles_match_spec_table() -> None:
    """SLAs, compliance frameworks and thresholds match the SPEC table."""
    assert set(TIER_PROFILES) == set(Tier)

    daily = tier_profile(Tier.daily)
    assert daily.patch_sla_critical == "30 days"
    assert daily.compliance == ("CIS Controls v8 L1",)
    assert daily.risk_threshold == 4.0

    authority = tier_profile(Tier.authority)
    assert authority.patch_sla_critical == "7 days"
    assert authority.compliance == ("NIST 800-53 Moderate", "ISO 27001")
    assert authority.risk_threshold == 2.5

    hacker = tier_profile(Tier.hacker)
    assert hacker.patch_sla_critical == "24 hours"
    assert hacker.compliance == ("NIST 800-53 High", "MITRE ATT&CK")
    assert hacker.risk_threshold == 1.5

    military = tier_profile(Tier.military)
    assert military.patch_sla_critical == "immediate/airgap"
    assert military.compliance == ("NSA/CSS", "TEMPEST", "CNSS 1253")
    assert military.risk_threshold == 0.5
