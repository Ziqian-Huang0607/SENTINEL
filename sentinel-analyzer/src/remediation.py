"""Tiered remediation library for SENTINEL analyses.

Maps vulnerability classes to control lists for each of the four SPEC
security tiers (daily, authority, hacker, military). Control wording encodes
the SPEC tier table: patch SLAs for critical findings (30 days / 7 days /
24 hours / immediate-airgap), compliance frameworks (CIS Controls v8 L1;
NIST 800-53 Moderate + ISO 27001; NIST 800-53 High + MITRE ATT&CK;
NSA/CSS + TEMPEST + CNSS 1253) and risk thresholds (4.0 / 2.5 / 1.5 / 0.5).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from src.models import Tier, TieredRemediation


@dataclass(frozen=True)
class TierProfile:
    """SPEC tier-table row: threat, compliance, patch SLA, risk threshold."""

    tier: Tier
    threat: str
    compliance: tuple[str, ...]
    patch_sla_critical: str
    risk_threshold: float


TIER_PROFILES: dict[Tier, TierProfile] = {
    Tier.daily: TierProfile(
        tier=Tier.daily,
        threat="worms, script kiddies",
        compliance=("CIS Controls v8 L1",),
        patch_sla_critical="30 days",
        risk_threshold=4.0,
    ),
    Tier.authority: TierProfile(
        tier=Tier.authority,
        threat="organized cybercrime",
        compliance=("NIST 800-53 Moderate", "ISO 27001"),
        patch_sla_critical="7 days",
        risk_threshold=2.5,
    ),
    Tier.hacker: TierProfile(
        tier=Tier.hacker,
        threat="APT, red teams",
        compliance=("NIST 800-53 High", "MITRE ATT&CK"),
        patch_sla_critical="24 hours",
        risk_threshold=1.5,
    ),
    Tier.military: TierProfile(
        tier=Tier.military,
        threat="nation-state",
        compliance=("NSA/CSS", "TEMPEST", "CNSS 1253"),
        patch_sla_critical="immediate/airgap",
        risk_threshold=0.5,
    ),
}

# vuln-class -> tier -> control list. Class names match attack_chain rules.
REMEDIATION_LIBRARY: dict[str, dict[Tier, tuple[str, ...]]] = {
    "generic": {
        Tier.daily: (
            "Patch critical vulnerabilities within 30 days per CIS Controls "
            "v8 L1; keep the overall risk score below 4.0.",
            "Maintain a complete asset inventory and remove services that "
            "lack a documented business need.",
        ),
        Tier.authority: (
            "Patch critical vulnerabilities within 7 days per NIST 800-53 "
            "Moderate and ISO 27001; keep the overall risk score below 2.5.",
            "Enforce least privilege and firewall segmentation between "
            "trust zones (internet, dmz, internal, mgmt, airgap).",
        ),
        Tier.hacker: (
            "Patch critical vulnerabilities within 24 hours per NIST 800-53 "
            "High; keep the overall risk score below 1.5.",
            "Deploy detections mapped to MITRE ATT&CK for every observed "
            "technique and run continuous threat hunting.",
        ),
        Tier.military: (
            "Remediate critical findings immediately; isolate or airgap "
            "affected systems per NSA/CSS, TEMPEST and CNSS 1253; keep the "
            "overall risk score below 0.5.",
            "Enforce zero-trust segmentation with continuous monitoring and "
            "cross-domain controls on all flows.",
        ),
    },
    "unauth_service": {
        Tier.daily: (
            "Enable authentication with strong, unique credentials on all "
            "data-store services (Redis, MongoDB, Elasticsearch) within 30 "
            "days per CIS Controls v8 L1.",
            "Bind data-store services to localhost or internal interfaces "
            "only; never expose them on untrusted networks.",
        ),
        Tier.authority: (
            "Close unauthenticated data-store access within 7 days per "
            "NIST 800-53 Moderate and ISO 27001 access-control requirements.",
            "Restrict data-store ports with host firewalls and network ACLs "
            "so only authorized application subnets can connect.",
        ),
        Tier.hacker: (
            "Remediate unauthenticated data stores within 24 hours per "
            "NIST 800-53 High; assume stored data is already compromised.",
            "Rotate every credential and key reachable through the "
            "unauthenticated service and audit access logs for MITRE ATT&CK "
            "T1190 exploitation.",
        ),
        Tier.military: (
            "Disconnect or airgap unauthenticated data stores immediately "
            "per NSA/CSS and CNSS 1253.",
            "Acquire forensic images before remediation; treat all stored "
            "data as compromised by nation-state actors.",
        ),
    },
    "lateral_movement": {
        Tier.daily: (
            "Restrict lateral-movement services (SMB 445, RDP 3389, SSH 22, "
            "WinRM 5985) to management subnets within 30 days per CIS "
            "Controls v8 L1.",
        ),
        Tier.authority: (
            "Segment lateral-movement ports between trust zones within 7 "
            "days per NIST 800-53 Moderate; require jump hosts for admin "
            "protocols.",
        ),
        Tier.hacker: (
            "Deploy MITRE ATT&CK T1021 detections for SMB/RDP/SSH/WinRM "
            "within 24 hours and enforce MFA on all remote access.",
        ),
        Tier.military: (
            "Disable or airgap lateral-movement services immediately; "
            "require hardware-backed administrative credentials per NSA/CSS "
            "guidance.",
        ),
    },
    "default_credentials": {
        Tier.daily: (
            "Change default credentials on remote-access and database "
            "services (Telnet, FTP, VNC, MySQL, PostgreSQL, MSSQL, SNMP) "
            "within 30 days per CIS Controls v8 L1.",
        ),
        Tier.authority: (
            "Enforce unique vaulted credentials and organization password "
            "policies within 7 days per ISO 27001 and NIST 800-53 Moderate.",
        ),
        Tier.hacker: (
            "Rotate all potentially exposed credentials within 24 hours and "
            "deploy MITRE ATT&CK T1078 valid-account detections.",
        ),
        Tier.military: (
            "Replace password authentication with PKI or hardware tokens "
            "immediately; audit all account usage per CNSS 1253.",
        ),
    },
    "exposed_admin_panel": {
        Tier.daily: (
            "Remove administrative web panels from general network reach "
            "(VPN-gate or allow-list) within 30 days per CIS Controls v8 L1.",
        ),
        Tier.authority: (
            "Restrict admin panels to allow-listed management networks "
            "within 7 days per NIST 800-53 Moderate.",
        ),
        Tier.hacker: (
            "Take exposed admin panels offline within 24 hours; review "
            "panel access logs for unauthorized use mapped to MITRE ATT&CK "
            "T1190.",
        ),
        Tier.military: (
            "Airgap administrative interfaces immediately; permit access "
            "only from hardened privileged-access workstations per NSA/CSS.",
        ),
    },
    "unpatched_rce": {
        Tier.daily: (
            "Patch remote-code-execution vulnerabilities (CVSS >= 7.0) "
            "within 30 days per CIS Controls v8 L1.",
        ),
        Tier.authority: (
            "Patch critical RCE vulnerabilities within 7 days per NIST "
            "800-53 Moderate and ISO 27001; apply WAF virtual patching "
            "until fixes are deployed.",
        ),
        Tier.hacker: (
            "Patch or isolate RCE-affected services within 24 hours per "
            "NIST 800-53 High; hunt for exploitation using the mapped MITRE "
            "ATT&CK techniques.",
        ),
        Tier.military: (
            "Isolate or airgap RCE-affected systems immediately; rebuild "
            "from known-good media per NSA/CSS and CNSS 1253.",
        ),
    },
    "internet_exposure": {
        Tier.daily: (
            "Minimize internet-exposed services within 30 days and document "
            "business justification for each per CIS Controls v8 L1.",
        ),
        Tier.authority: (
            "Move internet-facing services into a firewalled DMZ within 7 "
            "days per NIST 800-53 Moderate.",
        ),
        Tier.hacker: (
            "Reduce the internet attack surface within 24 hours; front "
            "exposed services with WAF/IPS and MITRE ATT&CK-based "
            "monitoring.",
        ),
        Tier.military: (
            "Remove all non-essential internet exposure immediately; "
            "enforce physical segmentation or airgaps per TEMPEST and "
            "NSA/CSS guidance.",
        ),
    },
}


def tier_profile(tier: Tier) -> TierProfile:
    """Return the SPEC tier-table profile for a tier."""
    return TIER_PROFILES[tier]


def remediation_for_class(vuln_class: str) -> TieredRemediation:
    """Return the 4-tier control lists for one vulnerability class.

    Unknown classes yield empty lists on every tier.
    """
    entry = REMEDIATION_LIBRARY.get(vuln_class, {})
    return TieredRemediation(
        daily=list(entry.get(Tier.daily, ())),
        authority=list(entry.get(Tier.authority, ())),
        hacker=list(entry.get(Tier.hacker, ())),
        military=list(entry.get(Tier.military, ())),
    )


def build_remediation(vuln_classes: Iterable[str]) -> TieredRemediation:
    """Merge baseline and per-class controls into one 4-tier library.

    The ``generic`` baseline is always included so every tier is non-empty;
    controls are deduplicated while preserving deterministic order.
    """
    merged = remediation_for_class("generic")
    tiers = (Tier.daily, Tier.authority, Tier.hacker, Tier.military)
    lists: dict[Tier, list[str]] = {
        Tier.daily: merged.daily,
        Tier.authority: merged.authority,
        Tier.hacker: merged.hacker,
        Tier.military: merged.military,
    }
    for vuln_class in vuln_classes:
        per_class = remediation_for_class(vuln_class)
        per_tier: dict[Tier, list[str]] = {
            Tier.daily: per_class.daily,
            Tier.authority: per_class.authority,
            Tier.hacker: per_class.hacker,
            Tier.military: per_class.military,
        }
        for tier in tiers:
            for control in per_tier[tier]:
                if control not in lists[tier]:
                    lists[tier].append(control)
    return TieredRemediation(
        daily=lists[Tier.daily],
        authority=lists[Tier.authority],
        hacker=lists[Tier.hacker],
        military=lists[Tier.military],
    )
