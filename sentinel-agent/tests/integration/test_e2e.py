"""End-to-end agent run: stub scanner -> playbook investigation -> memory -> report.

Hermetic: a stub scanner "binary" emits a canned scan.json pointing at a real
loopback HTTP listener; SENTINEL_AGENT_MODEL=playbook forces the deterministic
path (no Ollama needed); memory and audit land in tmp dirs.
"""

from __future__ import annotations

import json
import stat
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from src.__main__ import async_main
from src.models import AgentReport


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><head><title>Test Router</title></head></html>"
        self.send_response(200)
        self.send_header("Server", "test-httpd/1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        pass


@pytest.fixture()
def http_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    thread.join(timeout=5)


def _stub_scanner(tmp_path: Path, scan: dict) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    stub = tmp_path / "stub-scanner.sh"
    scan_file = tmp_path / "canned_scan.json"
    scan_file.write_text(json.dumps(scan), encoding="utf-8")
    stub.write_text(
        "#!/bin/sh\n"
        "out=''\n"
        "while [ $# -gt 0 ]; do\n"
        "  if [ \"$1\" = '--output' ]; then shift; out=$1; fi\n"
        "  shift\n"
        "done\n"
        f"cp '{scan_file}' \"$out\"\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return stub


def _scan(port: int) -> dict:
    return {
        "scan_id": "e2e-1",
        "target": "127.0.0.1/32",
        "tier": "daily",
        "started_at": "2026-08-04T00:00:00+00:00",
        "finished_at": "2026-08-04T00:00:05+00:00",
        "hosts": [
            {
                "ip": "127.0.0.1",
                "hostname": "localhost",
                "os": "unknown",
                "ports": [
                    {
                        "port": port,
                        "protocol": "tcp",
                        "service": "http",
                        "product": "",
                        "version": "",
                        "state": "open",
                    }
                ],
                "cve_matches": [],
            }
        ],
        "posture_findings": [
            {
                "id": "POSTURE-UNAUTH-WEB",
                "host": "127.0.0.1",
                "port": port,
                "severity": 6.5,
                "title": "Unauthenticated web interface",
                "detail": "GET / answered 200 without an authentication challenge.",
            }
        ],
        "cve_db": {"version": "test-seed", "signature_count": 1},
    }


@pytest.mark.asyncio
async def test_e2e_playbook_run(tmp_path, http_server, monkeypatch):
    monkeypatch.setenv("SENTINEL_AGENT_MODEL", "playbook")
    monkeypatch.setenv("SENTINEL_MEMORY_DB", str(tmp_path / "memory.db"))
    monkeypatch.setenv("SENTINEL_AUDIT_LOG", str(tmp_path / "audit.log"))
    stub = _stub_scanner(tmp_path, _scan(http_server))
    out = tmp_path / "agent_report.json"

    rc = await async_main(
        [
            "--target", "127.0.0.1/32",
            "--tier", "daily",
            "--scanner", str(stub),
            "--yes",
            "--out", str(out),
            "--transcripts-dir", str(tmp_path / "transcripts"),
        ]
    )

    assert rc == 0
    report = AgentReport.model_validate_json(out.read_text(encoding="utf-8"))
    assert report.scan_id == "e2e-1"
    assert report.model == "playbook"
    assert len(report.investigations) == 1
    inv = report.investigations[0]
    assert inv.status in {"concluded", "inconclusive"}
    assert any("playbook" in obs for obs in report.observations)
    # First scan of this target = baseline: no drift events.
    assert report.drift == []

    audit_lines = (tmp_path / "audit.log").read_text(encoding="utf-8").strip().splitlines()
    assert len(audit_lines) == 1
    entry = json.loads(audit_lines[0])
    assert entry["confirm_method"] == "--yes"
    assert entry["outcome"] == "confirmed"


@pytest.mark.asyncio
async def test_e2e_scan_file_reuses_existing_scan(tmp_path, http_server, monkeypatch):
    """--scan-file skips the scanner entirely (GUI hand-off path)."""
    monkeypatch.setenv("SENTINEL_AGENT_MODEL", "playbook")
    monkeypatch.setenv("SENTINEL_MEMORY_DB", str(tmp_path / "memory.db"))
    monkeypatch.setenv("SENTINEL_AUDIT_LOG", str(tmp_path / "audit.log"))
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps(_scan(http_server)), encoding="utf-8")
    out = tmp_path / "agent_report.json"

    rc = await async_main(
        [
            "--target", "127.0.0.1/32",
            "--tier", "daily",
            "--scanner", str(tmp_path / "does-not-exist"),  # must not be consulted
            "--scan-file", str(scan_file),
            "--yes",
            "--out", str(out),
            "--transcripts-dir", str(tmp_path / "transcripts"),
        ]
    )

    assert rc == 0
    report = AgentReport.model_validate_json(out.read_text(encoding="utf-8"))
    assert report.scan_id == "e2e-1"
    assert len(report.investigations) == 1


@pytest.mark.asyncio
async def test_e2e_second_run_reports_drift(tmp_path, http_server, monkeypatch):
    monkeypatch.setenv("SENTINEL_AGENT_MODEL", "playbook")
    monkeypatch.setenv("SENTINEL_MEMORY_DB", str(tmp_path / "memory.db"))
    monkeypatch.setenv("SENTINEL_AUDIT_LOG", str(tmp_path / "audit.log"))

    scan = _scan(http_server)
    stub = _stub_scanner(tmp_path, scan)
    argv = [
        "--target", "127.0.0.1/32",
        "--tier", "daily",
        "--scanner", str(stub),
        "--yes",
        "--out", str(tmp_path / "r1.json"),
        "--transcripts-dir", str(tmp_path / "t1"),
    ]
    assert await async_main(argv) == 0

    # Second scan: same host, port closed (absent) -> CLOSED_PORT drift.
    scan2 = _scan(http_server)
    scan2["scan_id"] = "e2e-2"
    scan2["hosts"][0]["ports"] = []
    stub2 = _stub_scanner(tmp_path / "second", scan2)
    argv[argv.index(str(stub))] = str(stub2)
    argv[argv.index(str(tmp_path / "r1.json"))] = str(tmp_path / "r2.json")
    argv[argv.index(str(tmp_path / "t1"))] = str(tmp_path / "t2")
    assert await async_main(argv) == 0

    report = AgentReport.model_validate_json(
        (tmp_path / "r2.json").read_text(encoding="utf-8")
    )
    kinds = {e.kind for e in report.drift}
    assert "CLOSED_PORT" in kinds
