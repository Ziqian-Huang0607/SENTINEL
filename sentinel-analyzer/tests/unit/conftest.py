"""Shared pytest fixtures for the sentinel-analyzer unit tests."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Rich fixture scan: multi-host, redis -NOAUTH, ssh, smb (plus a closed rdp
# port to prove open-filtering), an internet-exposed http/elasticsearch host
# and one high CVSS+EPSS CVE.
FIXTURE_SCAN_PAYLOAD: dict = {
    "scan_id": "3f6b8c2e-1234-4abc-9def-0123456789ab",
    "target": "192.168.1.0/24",
    "tier": "hacker",
    "started_at": "2024-05-01T10:00:00Z",
    "finished_at": "2024-05-01T10:01:12Z",
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
                    "version": "9.6",
                    "banner": "SSH-2.0-OpenSSH_9.6",
                },
            ],
        },
        {
            "ip": "192.168.1.50",
            "hostname": "ws01",
            "mac": "aa:bb:cc:dd:ee:02",
            "os_guess": "Windows 10",
            "trust_zone": "internal",
            "criticality": "workstation",
            "ports": [
                {"port": 445, "protocol": "tcp", "state": "open", "service": "smb"},
                {
                    "port": 3389,
                    "protocol": "tcp",
                    "state": "closed",
                    "service": "rdp",
                },
            ],
        },
        {
            "ip": "192.168.1.10",
            "hostname": "web01",
            "trust_zone": "internet",
            "criticality": "app",
            "ports": [
                {
                    "port": 8080,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "banner": "Server: nginx",
                },
                {
                    "port": 9200,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "elasticsearch",
                    "banner": "authentication disabled",
                },
            ],
        },
    ],
    "vulnerabilities": [
        {
            "cve_id": "CVE-2024-21667",
            "cvss": 9.8,
            "epss": 0.85,
            "host": "192.168.1.45",
            "port": 6379,
            "summary": "Redis RCE via crafted Lua script.",
        }
    ],
    "risk_score": 8.97,
}


@pytest.fixture(autouse=True)
def _raw_archive_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Redirect the raw LLM archive to a tmp dir for every test.

    Keeps the working tree clean; tests exercising the archive override
    this with their own SENTINEL_RAW_ARCHIVE_DIR.
    """
    monkeypatch.setenv("SENTINEL_RAW_ARCHIVE_DIR", str(tmp_path / "archive"))


@pytest.fixture()
def scan_payload() -> dict:
    """Return a deep copy of the rich fixture scan payload."""
    return copy.deepcopy(FIXTURE_SCAN_PAYLOAD)


@pytest.fixture()
def scan(scan_payload: dict):
    """Return the fixture scan as a validated ScanInput."""
    from src.models import ScanInput

    return ScanInput.model_validate(scan_payload)
