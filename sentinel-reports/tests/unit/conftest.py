"""Shared fixtures: a rich multi-host scan and a fallback-mode analysis."""

from __future__ import annotations

from typing import Any

import pytest


@pytest.fixture()
def scan_data() -> dict[str, Any]:
    """Multi-host ScanInput document covering all SARIF severity levels."""
    return {
        "scan_id": "7f3a2b1c-9d4e-4f5a-8b6c-1e2d3c4b5a69",
        "target": "192.168.1.0/24",
        "tier": "hacker",
        "started_at": "2024-06-12T09:15:00+00:00",
        "finished_at": "2024-06-12T09:16:42+00:00",
        "hosts": [
            {
                "ip": "192.168.1.45",
                "hostname": "db01",
                "mac": "aa:bb:cc:dd:ee:01",
                "os_guess": "Linux 5.x",
                "trust_zone": "dmz",
                "criticality": "dc",
                "ports": [
                    {
                        "port": 6379,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "redis",
                        "version": "6.2.7",
                        "banner": "-NOAUTH",
                    },
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "ssh",
                        "version": "OpenSSH 8.9p1",
                        "banner": "SSH-2.0-OpenSSH_8.9p1",
                    },
                    {
                        "port": 5432,
                        "protocol": "tcp",
                        "state": "closed",
                        "service": None,
                        "version": None,
                        "banner": None,
                    },
                ],
            },
            {
                "ip": "192.168.1.50",
                "hostname": "web01",
                "mac": "aa:bb:cc:dd:ee:02",
                "os_guess": "Linux 5.x",
                "trust_zone": "internet",
                "criticality": "app",
                "ports": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "https",
                        "version": "nginx 1.18.0",
                        "banner": "Server: nginx/1.18.0",
                    },
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "version": "nginx 1.18.0",
                        "banner": "Server: nginx/1.18.0",
                    },
                ],
            },
            {
                "ip": "192.168.1.77",
                "hostname": "cam01",
                "mac": "aa:bb:cc:dd:ee:03",
                "os_guess": "Embedded Linux",
                "trust_zone": "mgmt",
                "criticality": "iot",
                "ports": [
                    {
                        "port": 8080,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "version": "GoAhead-Webs 3.6.2",
                        "banner": "Server: GoAhead-Webs",
                    }
                ],
            },
        ],
        "vulnerabilities": [
            {
                "cve_id": "CVE-2022-0543",
                "cvss": 10.0,
                "epss": 0.94,
                "host": "192.168.1.45",
                "port": 6379,
                "summary": "Redis Lua sandbox escape permits remote code execution on the host.",
            },
            {
                "cve_id": "CVE-2024-21667",
                "cvss": 9.8,
                "epss": 0.85,
                "host": "192.168.1.45",
                "port": 6379,
                "summary": "Unauthenticated Redis instance exposes data and command execution.",
            },
            {
                "cve_id": "CVE-2017-17562",
                "cvss": 9.8,
                "epss": 0.75,
                "host": "192.168.1.77",
                "port": 8080,
                "summary": "GoAhead CGI handler allows remote code execution via LD_PRELOAD.",
            },
            {
                "cve_id": "CVE-2021-23017",
                "cvss": 7.7,
                "epss": 0.22,
                "host": "192.168.1.50",
                "port": 443,
                "summary": "nginx resolver off-by-one heap write allows denial of service or RCE.",
            },
            {
                "cve_id": "CVE-2023-44487",
                "cvss": 7.5,
                "epss": 0.51,
                "host": "192.168.1.50",
                "port": 443,
                "summary": "HTTP/2 rapid reset enables high-volume denial of service attacks.",
            },
            {
                "cve_id": "CVE-2016-2183",
                "cvss": 5.0,
                "epss": 0.36,
                "host": "192.168.1.45",
                "port": 22,
                "summary": "SWEET32 birthday attack against 3DES cipher suites in TLS/SSH.",
            },
        ],
        "risk_score": 9.1,
    }


@pytest.fixture()
def analysis_data() -> dict[str, Any]:
    """Fallback-mode AnalysisOutput document with chains and 4-tier fixes."""
    return {
        "attack_chains": [
            {
                "path": ["192.168.1.45:6379", "192.168.1.45:22"],
                "description": (
                    "The unauthenticated Redis instance permits Lua sandbox escape "
                    "(CVE-2022-0543), yielding code execution on db01; the host "
                    "foothold then enables SSH-based lateral movement across the "
                    "database segment."
                ),
                "mitre_technique": "T1190",
                "confidence": 0.9,
                "impact": 0.95,
                "priority": 1,
            },
            {
                "path": ["192.168.1.77:8080", "192.168.1.50:443"],
                "description": (
                    "The GoAhead management panel on cam01 is reachable from the "
                    "mgmt zone; CVE-2017-17562 grants code execution that can be "
                    "used to stage attacks against the internet-facing web tier."
                ),
                "mitre_technique": "T1078",
                "confidence": 0.72,
                "impact": 0.6,
                "priority": 2,
            },
        ],
        "remediation": {
            "daily": [
                "Require Redis AUTH and bind 6379/tcp to localhost or a dedicated VLAN.",
                "Disable 3DES cipher suites on SSH and TLS endpoints.",
                "Apply vendor firmware updates to cam01 within 30 days.",
            ],
            "authority": [
                "Patch nginx to a release that resolves CVE-2021-23017 within 7 days.",
                "Enforce network segmentation between the dmz and database segment.",
                "Deploy central log collection for redis and nginx audit events.",
            ],
            "hacker": [
                "Mitigate HTTP/2 rapid reset (CVE-2023-44487) on web01 within 24 hours.",
                "Rotate all credentials reachable from hosts in the attack-chain paths.",
                "Add MITRE ATT&CK T1190/T1078 detections for exploit and lateral movement.",
            ],
            "military": [
                "Airgap the database segment; remove all internet-routed paths to db01.",
                "Rebuild cam01 from signed firmware and disable the CGI handler entirely.",
                "Apply CNSS-1253 controls to management-plane interfaces immediately.",
            ],
        },
        "risk_score": 9.1,
        "observations": [
            "Unauthenticated Redis on db01 is the dominant risk driver (score 9.10).",
            "Two internet-facing services on web01 run versions with public exploits.",
            "The mgmt-zone camera panel provides a staging point toward the web tier.",
        ],
        "analyzer_mode": "fallback",
    }
