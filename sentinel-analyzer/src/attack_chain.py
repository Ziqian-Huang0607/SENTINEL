"""Deterministic candidate attack-chain extraction from scan data.

The candidates built here serve two consumers:

1. the LLM client, which receives them as grounding context in the prompt;
2. the fallback analyzer, which converts them directly into contract
   ``AttackChain`` objects when the LLM is unavailable.

Everything in this module is deterministic: no randomness, no wall-clock
dependence, and stable ordering that follows the input scan ordering.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.models import (
    CRITICALITY_FACTOR,
    EXPOSURE_FACTOR,
    AttackChain,
    Criticality,
    Host,
    Port,
    ScanInput,
    TrustZone,
    compute_risk_score,
)

# Data-store services that are high-signal when reachable without auth.
UNAUTH_SERVICES: dict[str, str] = {
    "redis": "Redis",
    "mongodb": "MongoDB",
    "mongo": "MongoDB",
    "elasticsearch": "Elasticsearch",
    "elastic": "Elasticsearch",
    "memcached": "Memcached",
    "cassandra": "Cassandra",
    "zookeeper": "ZooKeeper",
}

# Banner markers (lowercased) that indicate missing authentication.
NOAUTH_MARKERS: tuple[str, ...] = (
    "-noauth",
    "noauth",
    "no authentication",
    "authentication disabled",
    "auth disabled",
    "without authentication",
)

# Lateral-movement ports: port -> (display name, MITRE ATT&CK technique).
LATERAL_PORTS: dict[int, tuple[str, str]] = {
    445: ("SMB", "T1021.002"),
    3389: ("RDP", "T1021.001"),
    22: ("SSH", "T1021.004"),
    5985: ("WinRM", "T1021.006"),
}

# Services commonly deployed with default or weak credentials.
DEFAULT_CRED_SERVICES: dict[str, str] = {
    "telnet": "Telnet",
    "ftp": "FTP",
    "vnc": "VNC",
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "mssql": "MSSQL",
    "snmp": "SNMP",
}

# Web admin panels that must never be exposed.
ADMIN_PANEL_SERVICES: dict[str, str] = {
    "tomcat": "Tomcat Manager",
    "jenkins": "Jenkins",
    "phpmyadmin": "phpMyAdmin",
    "webmin": "Webmin",
    "grafana": "Grafana",
    "kibana": "Kibana",
    "adminer": "Adminer",
}

# Generic HTTP ports worth flagging as exposed admin surfaces.
ADMIN_PANEL_PORTS: frozenset[int] = frozenset(
    {8000, 8080, 8443, 8888, 9000, 9090, 4848, 7001, 10000}
)
HTTP_LIKE_SERVICES: frozenset[str] = frozenset(
    {"http", "https", "http-alt", "http-proxy", "www", "ssl/http"}
)

HIGH_CVSS_THRESHOLD = 7.0
HIGH_EPSS_THRESHOLD = 0.2
MAX_LATERAL_TARGETS = 5

# Posture finding classes (R8, scanner src/vuln/posture.rs) mapped to the
# ATT&CK technique that actually matches the weakness, plus per-class
# confidence and impact base. Fixes the "uniform T1568 filler" failure seen
# in LLM output on finding-free scans.
POSTURE_TECHNIQUES: dict[str, tuple[str, float, float]] = {
    "POSTURE-UNAUTH-WEB-GATEWAY": ("T1190", 0.85, 0.65),
    "POSTURE-UNAUTH-WEB": ("T1190", 0.8, 0.5),
    "POSTURE-UNAUTH-IPP": ("T1190", 0.8, 0.55),
    "POSTURE-UNAUTH-DATASTORE": ("T1190", 0.9, 0.6),
    "POSTURE-CLEARTEXT": ("T1040", 0.75, 0.45),
    "POSTURE-LEGACY-LPD": ("T1190", 0.7, 0.4),
    "POSTURE-RAW-PRINTER": ("T1190", 0.65, 0.3),
}


@dataclass(frozen=True)
class CandidateChain:
    """A deterministic, rule-derived attack-chain candidate."""

    rule: str
    path: tuple[str, ...]
    description: str
    mitre_technique: str
    confidence: float
    impact: float
    risk: float


def _is_open(port: Port) -> bool:
    """Return True when the port state is 'open' (case-insensitive)."""
    return port.state.lower() == "open"


def _service_name(port: Port) -> str:
    """Normalized service name for a port."""
    return (port.service or "").strip().lower()


def _host_label(host: Host) -> str:
    """Human label for a host: hostname when known, else IP."""
    return host.hostname or host.ip


def _impact(exposure: float, criticality: float, base: float) -> float:
    """Bounded deterministic impact in [0, 1] from context factors."""
    return round(min(1.0, base + 0.25 * exposure + 0.20 * criticality), 2)


def _chain_risk(confidence: float, impact: float) -> float:
    """0-10 risk for non-CVE chains, derived from confidence/impact."""
    return round(10.0 * (0.5 * confidence + 0.5 * impact), 2)


def detect_unauth_service(port: Port) -> tuple[bool, bool]:
    """Detect an unauthenticated data-store service from its banner.

    Returns a tuple ``(is_unauth, marker_found)``. ``is_unauth`` is True
    when a no-auth marker is present in the banner; ``marker_found`` echoes
    whether the detection is banner-confirmed (vs. never raised here).
    """
    banner = (port.banner or "").lower()
    marker_found = any(marker in banner for marker in NOAUTH_MARKERS)
    return marker_found, marker_found


def _is_exposed_admin_panel(host: Host, port: Port) -> bool:
    """Detect exposed web admin panels.

    Named panels (jenkins, phpmyadmin, ...) are flagged on any zone; generic
    HTTP services on well-known admin ports only when the host is exposed
    (internet or dmz), to stay high-signal.
    """
    name = _service_name(port)
    if name in ADMIN_PANEL_SERVICES:
        return True
    return (
        name in HTTP_LIKE_SERVICES
        and port.port in ADMIN_PANEL_PORTS
        and host.trust_zone in (TrustZone.internet, TrustZone.dmz)
    )


def _lateral_targets(scan: ScanInput) -> list[tuple[Host, Port]]:
    """All (host, port) pairs offering lateral-movement services."""
    targets: list[tuple[Host, Port]] = []
    for host in scan.hosts:
        for port in host.ports:
            if _is_open(port) and port.port in LATERAL_PORTS:
                targets.append((host, port))
    return targets


def _service_display(port: Port) -> str:
    """Display name for a service, falling back to the raw name."""
    name = _service_name(port)
    return (
        UNAUTH_SERVICES.get(name)
        or DEFAULT_CRED_SERVICES.get(name)
        or ADMIN_PANEL_SERVICES.get(name)
        or (port.service or "service")
    )


def extract_candidate_chains(scan: ScanInput) -> list[CandidateChain]:
    """Extract deterministic attack-chain candidates from a scan.

    Rules: unauthenticated data stores, lateral-movement staging from those
    stores, default-credential-prone services, exposed admin panels,
    internet-exposed attack surface, and high CVSS+EPSS RCE candidates.
    """
    chains: list[CandidateChain] = []
    hosts_by_ip = {host.ip: host for host in scan.hosts}
    lateral = _lateral_targets(scan)

    for host in scan.hosts:
        exposure = EXPOSURE_FACTOR[host.trust_zone]
        criticality = CRITICALITY_FACTOR[host.criticality]
        open_ports = [p for p in host.ports if _is_open(p)]

        if host.trust_zone is TrustZone.internet and open_ports:
            confidence, impact = 0.5, _impact(exposure, criticality, 0.35)
            chains.append(
                CandidateChain(
                    rule="internet_exposure",
                    path=(host.ip,),
                    description=(
                        f"Internet-exposed host {_host_label(host)} ({host.ip}) "
                        f"with {len(open_ports)} open port(s) is directly "
                        "reachable from untrusted networks."
                    ),
                    mitre_technique="T1190",
                    confidence=confidence,
                    impact=impact,
                    risk=_chain_risk(confidence, impact),
                )
            )

        for port in open_ports:
            is_unauth, _ = detect_unauth_service(port)
            if is_unauth:
                name = _service_name(port)
                confidence = 0.9 if name in UNAUTH_SERVICES else 0.75
                impact = _impact(exposure, criticality, 0.55)
                display = _service_display(port)
                chains.append(
                    CandidateChain(
                        rule="unauth_service",
                        path=(f"{host.ip}:{port.port}",),
                        description=(
                            f"Unauthenticated {display} on "
                            f"{_host_label(host)} ({host.ip}:{port.port}) "
                            "allows any unauthenticated client to read, "
                            "modify or delete stored data."
                        ),
                        mitre_technique="T1190",
                        confidence=confidence,
                        impact=impact,
                        risk=_chain_risk(confidence, impact),
                    )
                )
                for tgt_host, tgt_port in lateral[:MAX_LATERAL_TARGETS]:
                    lat_name, lat_mitre = LATERAL_PORTS[tgt_port.port]
                    lat_confidence = 0.75
                    lat_impact = _impact(
                        EXPOSURE_FACTOR[tgt_host.trust_zone],
                        CRITICALITY_FACTOR[tgt_host.criticality],
                        0.6,
                    )
                    chains.append(
                        CandidateChain(
                            rule="lateral_movement",
                            path=(
                                f"{host.ip}:{port.port}",
                                f"{tgt_host.ip}:{tgt_port.port}",
                            ),
                            description=(
                                f"Pivot from unauthenticated {display} on "
                                f"{host.ip}:{port.port} to {lat_name} "
                                f"({tgt_port.port}) on {_host_label(tgt_host)} "
                                f"({tgt_host.ip}) to stage tooling and move "
                                "laterally through the environment."
                            ),
                            mitre_technique=lat_mitre,
                            confidence=lat_confidence,
                            impact=lat_impact,
                            risk=_chain_risk(lat_confidence, lat_impact),
                        )
                    )

            name = _service_name(port)
            if name in DEFAULT_CRED_SERVICES:
                confidence = 0.6
                impact = _impact(exposure, criticality, 0.45)
                chains.append(
                    CandidateChain(
                        rule="default_credentials",
                        path=(f"{host.ip}:{port.port}",),
                        description=(
                            f"{DEFAULT_CRED_SERVICES[name]} on "
                            f"{_host_label(host)} ({host.ip}:{port.port}) is "
                            "commonly deployed with default or weak "
                            "credentials, enabling trivial authenticated "
                            "access."
                        ),
                        mitre_technique="T1078",
                        confidence=confidence,
                        impact=impact,
                        risk=_chain_risk(confidence, impact),
                    )
                )

            if _is_exposed_admin_panel(host, port):
                confidence = 0.65
                impact = _impact(exposure, criticality, 0.5)
                chains.append(
                    CandidateChain(
                        rule="exposed_admin_panel",
                        path=(f"{host.ip}:{port.port}",),
                        description=(
                            f"Administrative web panel ({_service_display(port)}) "
                            f"exposed on {_host_label(host)} "
                            f"({host.ip}:{port.port}); a single auth bypass or "
                            "default login yields full application control."
                        ),
                        mitre_technique="T1190",
                        confidence=confidence,
                        impact=impact,
                        risk=_chain_risk(confidence, impact),
                    )
                )

    # R8: posture findings — real exposures with no CVE identifier. Chain
    # risk reuses the deterministic posture score (EPSS = 0) so chain
    # ordering agrees with the report headline score.
    for finding in scan.posture_findings:
        technique, confidence, impact_base = POSTURE_TECHNIQUES.get(
            finding.id, ("T1190", 0.7, 0.45)
        )
        host = hosts_by_ip.get(finding.host)
        zone = host.trust_zone if host else TrustZone.internal
        crit = host.criticality if host else Criticality.workstation
        impact = _impact(EXPOSURE_FACTOR[zone], CRITICALITY_FACTOR[crit], impact_base)
        risk = compute_risk_score(finding.severity, 0.0, zone, crit)
        chains.append(
            CandidateChain(
                rule="posture_exposure",
                path=(f"{finding.host}:{finding.port}",),
                description=(
                    f"{finding.title} on {finding.host}:{finding.port} "
                    f"(severity {finding.severity}; {finding.evidence})."
                ),
                mitre_technique=technique,
                confidence=confidence,
                impact=impact,
                risk=risk,
            )
        )

    for vuln in scan.vulnerabilities:
        if vuln.cvss >= HIGH_CVSS_THRESHOLD and vuln.epss >= HIGH_EPSS_THRESHOLD:
            host = hosts_by_ip.get(vuln.host)
            zone = host.trust_zone if host else TrustZone.internal
            crit = host.criticality if host else Criticality.workstation
            risk = compute_risk_score(
                vuln.cvss, vuln.epss, zone, crit, kev=vuln.kev
            )
            confidence = round(min(0.95, 0.5 + vuln.epss * 0.5), 2)
            impact = round(
                min(
                    1.0,
                    vuln.cvss / 10.0 * 0.7
                    + 0.15 * EXPOSURE_FACTOR[zone]
                    + 0.15 * CRITICALITY_FACTOR[crit],
                ),
                2,
            )
            mitre = (
                "T1190"
                if zone in (TrustZone.internet, TrustZone.dmz)
                else "T1210"
            )
            chains.append(
                CandidateChain(
                    rule="unpatched_rce",
                    path=(f"{vuln.host}:{vuln.port}",),
                    description=(
                        f"Unpatched remote-code-execution candidate "
                        f"{vuln.cve_id} (CVSS {vuln.cvss}, EPSS {vuln.epss}) "
                        f"on {vuln.host}:{vuln.port} is exploitable with "
                        "publicly available techniques."
                    ),
                    mitre_technique=mitre,
                    confidence=confidence,
                    impact=impact,
                    risk=risk,
                )
            )

    return _dedupe(chains)


def _dedupe(chains: list[CandidateChain]) -> list[CandidateChain]:
    """Drop exact duplicate (rule, path, technique) candidates, keep order."""
    seen: set[tuple[str, tuple[str, ...], str]] = set()
    unique: list[CandidateChain] = []
    for chain in chains:
        key = (chain.rule, chain.path, chain.mitre_technique)
        if key not in seen:
            seen.add(key)
            unique.append(chain)
    return unique


def observed_path_steps(scan: ScanInput) -> frozenset[str]:
    """All path steps a chain may legitimately reference.

    Every observed host IP, every ``host:port`` open-port pair, plus the
    finding locations from vulnerabilities and posture findings. The LLM
    grounding validator drops any chain whose path leaves this set — chain
    steps must describe the scanned environment, not invented hosts.
    """
    steps: set[str] = set()
    for host in scan.hosts:
        steps.add(host.ip)
        for port in host.ports:
            if _is_open(port):
                steps.add(f"{host.ip}:{port.port}")
    for vuln in scan.vulnerabilities:
        steps.add(vuln.host)
        steps.add(f"{vuln.host}:{vuln.port}")
    for finding in scan.posture_findings:
        steps.add(finding.host)
        steps.add(f"{finding.host}:{finding.port}")
    return frozenset(steps)


def ground_chains(
    chains: list[AttackChain], scan: ScanInput
) -> tuple[list[AttackChain], int]:
    """Drop chains referencing hosts/ports absent from the scan.

    Returns ``(kept, dropped_count)``. A chain is dropped when ANY path
    step is unobserved — partially grounded speculation is still
    speculation, and reports must never show invented infrastructure.
    Priorities are renumbered after filtering to stay rank-consistent.
    """
    observed = observed_path_steps(scan)
    kept: list[AttackChain] = []
    dropped = 0
    for chain in chains:
        if chain.path and all(step in observed for step in chain.path):
            kept.append(chain)
        else:
            dropped += 1
    kept = [
        chain.model_copy(update={"priority": rank})
        for rank, chain in enumerate(kept, start=1)
    ]
    return kept, dropped
