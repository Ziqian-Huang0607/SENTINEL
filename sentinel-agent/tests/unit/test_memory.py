"""Unit tests for src/memory.py — sqlite network memory + drift detection.

All tests run against a tmp_path sqlite database; no network is touched.
Covers the full six-kind drift matrix (agent-spec.md section 9), the
baseline rule, idempotency, first_seen/last_seen semantics, the
SENTINEL_MEMORY_DB override, compute_drift round-trips, and findings
recorded as observations.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
from src.memory import compute_drift, init_db, memory_path, record_scan
from src.models import AgentFinding

TARGET = "192.168.1.0/24"

T1 = datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc)
T2 = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)
T3 = datetime(2026, 8, 6, 12, 0, 0, tzinfo=timezone.utc)


# --- scan.json-shaped fixtures -----------------------------------------------


def _port(port: int, service: str = "", version: str = "", state: str = "open") -> dict:
    return {"port": port, "state": state, "service": service, "version": version}


def _host(ip: str, hostname: str = "", ports: tuple = ()) -> dict:
    return {"ip": ip, "hostname": hostname, "ports": list(ports)}


def _scan(
    scan_id: str,
    hosts: list[dict],
    target: str = TARGET,
    tier: str = "daily",
    risk_score: float = 5.13,
) -> dict:
    return {
        "scan_id": scan_id,
        "target": target,
        "tier": tier,
        "hosts": hosts,
        "risk_score": risk_score,
    }


def _finding(host: str = "192.168.1.1", port: int = 80) -> AgentFinding:
    return AgentFinding(
        id="AGENT-DEFAULT-PANEL-1",
        finding_class="DEFAULT-PANEL",
        host=host,
        port=port,
        severity=7.0,
        title="Router admin panel reachable without authentication",
        detail="Matched known panel signature",
        evidence=["E1"],
        confidence=0.9,
    )


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    c = init_db(tmp_path / "memory.db")
    yield c
    c.close()


def _kinds(events: list) -> set[str]:
    return {e.kind for e in events}


# --- memory_path / init_db ----------------------------------------------------


def test_memory_path_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    override = tmp_path / "nested" / "custom.db"
    monkeypatch.setenv("SENTINEL_MEMORY_DB", str(override))
    assert memory_path() == override
    assert override.parent.is_dir()  # parents created


def test_memory_path_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("SENTINEL_MEMORY_DB", raising=False)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    assert memory_path() == tmp_path / ".sentinel" / "memory.db"
    assert (tmp_path / ".sentinel").is_dir()


def test_init_db_uses_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    override = tmp_path / "env" / "memory.db"
    monkeypatch.setenv("SENTINEL_MEMORY_DB", str(override))
    c = init_db()
    c.close()
    assert override.is_file()


def test_init_db_creates_schema_idempotently(tmp_path: Path) -> None:
    for _ in range(2):  # second call must not fail or duplicate anything
        c = init_db(tmp_path / "memory.db")
        tables = {
            row[0]
            for row in c.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        c.close()
    assert {"scans", "hosts", "services", "observations"} <= tables


# --- baseline & idempotency ---------------------------------------------------


def test_first_scan_is_baseline_no_drift(conn: sqlite3.Connection) -> None:
    scan = _scan("s1", [_host("192.168.1.1", "router", (_port(80, "http", "nginx 1.18.0"),))])
    events = record_scan(conn, scan, ts=T1)
    assert events == []
    assert compute_drift(conn, TARGET, "s1") == []
    # the scan itself was still recorded
    row = conn.execute(
        "SELECT target, tier, risk_score FROM scans WHERE scan_id = 's1'"
    ).fetchone()
    assert row == (TARGET, "daily", 5.13)


def test_recording_same_scan_twice_yields_zero_drift(conn: sqlite3.Connection) -> None:
    hosts = [
        _host("192.168.1.1", "router", (_port(80, "http", "nginx 1.18.0"), _port(443, "https"))),
        _host("192.168.1.10", "nas", (_port(445, "smb"),)),
    ]
    auth = {("192.168.1.1", 80): "gated", ("192.168.1.10", 445): "unauth"}
    record_scan(conn, _scan("s1", hosts), ts=T1, auth_states=auth)
    events = record_scan(conn, _scan("s2", hosts), ts=T2, auth_states=auth)
    assert events == []
    assert compute_drift(conn, TARGET, "s2") == []


# --- host-level drift ---------------------------------------------------------


def test_new_host(conn: sqlite3.Connection) -> None:
    record_scan(conn, _scan("s1", [_host("192.168.1.1")]), ts=T1)
    events = record_scan(
        conn, _scan("s2", [_host("192.168.1.1"), _host("192.168.1.20")]), ts=T2
    )
    assert len(events) == 1
    (e,) = events
    assert e.kind == "NEW_HOST"
    assert e.host == "192.168.1.20"
    assert e.port is None  # host-level event
    assert e.before == "absent"
    assert e.after == "present"
    assert e.ts == T2  # event ts is the scan ts


def test_gone_host(conn: sqlite3.Connection) -> None:
    record_scan(conn, _scan("s1", [_host("192.168.1.1"), _host("192.168.1.20")]), ts=T1)
    events = record_scan(conn, _scan("s2", [_host("192.168.1.1")]), ts=T2)
    assert len(events) == 1
    (e,) = events
    assert e.kind == "GONE_HOST"
    assert e.host == "192.168.1.20"
    assert e.port is None
    assert e.before == "present"
    assert e.after == "absent"


def test_new_host_subsumes_its_ports(conn: sqlite3.Connection) -> None:
    record_scan(conn, _scan("s1", [_host("192.168.1.1")]), ts=T1)
    events = record_scan(
        conn,
        _scan("s2", [_host("192.168.1.1"), _host("192.168.1.20", "cam", (_port(22, "ssh"),))]),
        ts=T2,
    )
    assert _kinds(events) == {"NEW_HOST"}  # no NEW_PORT for the new host's ports


def test_gone_host_subsumes_its_ports(conn: sqlite3.Connection) -> None:
    record_scan(
        conn,
        _scan("s1", [_host("192.168.1.1", "router", (_port(80, "http"),)), _host("192.168.1.2")]),
        ts=T1,
    )
    events = record_scan(conn, _scan("s2", [_host("192.168.1.2")]), ts=T2)
    assert _kinds(events) == {"GONE_HOST"}  # no CLOSED_PORT for the gone host's ports


def test_reappearing_host_is_new_host_again(conn: sqlite3.Connection) -> None:
    record_scan(conn, _scan("s1", [_host("192.168.1.1"), _host("192.168.1.20")]), ts=T1)
    record_scan(conn, _scan("s2", [_host("192.168.1.1")]), ts=T2)
    events = record_scan(conn, _scan("s3", [_host("192.168.1.1"), _host("192.168.1.20")]), ts=T3)
    assert _kinds(events) == {"NEW_HOST"}
    # ...but its original first_seen survived in memory
    row = conn.execute(
        "SELECT first_seen, last_seen FROM hosts WHERE target = ? AND ip = '192.168.1.20'",
        (TARGET,),
    ).fetchone()
    assert row == (T1.isoformat(), T3.isoformat())


# --- port-level drift ---------------------------------------------------------


def test_new_port(conn: sqlite3.Connection) -> None:
    host = _host("192.168.1.1", "router", (_port(80, "http"),))
    record_scan(conn, _scan("s1", [host]), ts=T1)
    events = record_scan(
        conn,
        _scan("s2", [_host("192.168.1.1", "router", (_port(80, "http"), _port(443, "https")))]),
        ts=T2,
    )
    assert len(events) == 1
    (e,) = events
    assert e.kind == "NEW_PORT"
    assert (e.host, e.port) == ("192.168.1.1", 443)
    assert e.before == "closed"
    assert e.after == "open"


def test_closed_port(conn: sqlite3.Connection) -> None:
    record_scan(
        conn,
        _scan("s1", [_host("192.168.1.1", "router", (_port(80, "http"), _port(23, "telnet")))]),
        ts=T1,
    )
    events = record_scan(
        conn, _scan("s2", [_host("192.168.1.1", "router", (_port(80, "http"),))]), ts=T2
    )
    assert len(events) == 1
    (e,) = events
    assert e.kind == "CLOSED_PORT"
    assert (e.host, e.port) == ("192.168.1.1", 23)
    assert e.before == "open"
    assert e.after == "closed"


def test_non_open_port_becomes_closed_port_and_no_service_row(
    conn: sqlite3.Connection,
) -> None:
    record_scan(conn, _scan("s1", [_host("192.168.1.1", "r", (_port(80, "http"),))]), ts=T1)
    events = record_scan(
        conn,
        _scan("s2", [_host("192.168.1.1", "r", (_port(80, "http", state="closed"),))]),
        ts=T2,
    )
    assert _kinds(events) == {"CLOSED_PORT"}
    # a port that was never open never becomes a service row
    record_scan(
        conn, _scan("s3", [_host("192.168.1.9", "x", (_port(99, state="filtered"),))]), ts=T3
    )
    count = conn.execute(
        "SELECT COUNT(*) FROM services WHERE target = ? AND ip = '192.168.1.9'",
        (TARGET,),
    ).fetchone()[0]
    assert count == 0


def test_version_change(conn: sqlite3.Connection) -> None:
    record_scan(
        conn, _scan("s1", [_host("192.168.1.1", "r", (_port(80, "http", "nginx 1.18.0"),))]), ts=T1
    )
    events = record_scan(
        conn, _scan("s2", [_host("192.168.1.1", "r", (_port(80, "http", "nginx 1.20.1"),))]), ts=T2
    )
    assert len(events) == 1
    (e,) = events
    assert e.kind == "VERSION_CHANGE"
    assert (e.host, e.port) == ("192.168.1.1", 80)
    assert e.before == "nginx 1.18.0"
    assert e.after == "nginx 1.20.1"
    assert e.ts == T2


def test_empty_version_never_triggers_version_change(conn: sqlite3.Connection) -> None:
    record_scan(
        conn, _scan("s1", [_host("192.168.1.1", "r", (_port(80, "http"),))]), ts=T1
    )
    events = record_scan(
        conn,
        _scan("s2", [_host("192.168.1.1", "r", (_port(80, "http", "nginx 1.20.1"),))]),
        ts=T2,
    )
    assert events == []  # unidentified -> identified is not a version *change*


# --- auth drift (both directions) ----------------------------------------------


def test_auth_change_unauth_to_gated(conn: sqlite3.Connection) -> None:
    hosts = [_host("192.168.1.1", "r", (_port(80, "http"),))]
    record_scan(conn, _scan("s1", hosts), ts=T1, auth_states={("192.168.1.1", 80): "unauth"})
    events = record_scan(
        conn, _scan("s2", hosts), ts=T2, auth_states={("192.168.1.1", 80): "gated"}
    )
    assert len(events) == 1
    (e,) = events
    assert e.kind == "AUTH_CHANGE"
    assert (e.host, e.port) == ("192.168.1.1", 80)
    assert e.before == "unauth"
    assert e.after == "gated"


def test_auth_change_gated_to_unauth(conn: sqlite3.Connection) -> None:
    hosts = [_host("192.168.1.1", "r", (_port(80, "http"),))]
    record_scan(conn, _scan("s1", hosts), ts=T1, auth_states={("192.168.1.1", 80): "gated"})
    events = record_scan(
        conn, _scan("s2", hosts), ts=T2, auth_states={("192.168.1.1", 80): "unauth"}
    )
    assert len(events) == 1
    (e,) = events
    assert e.kind == "AUTH_CHANGE"
    assert e.before == "gated"
    assert e.after == "unauth"


def test_no_auth_states_means_no_auth_change(conn: sqlite3.Connection) -> None:
    hosts = [_host("192.168.1.1", "r", (_port(80, "http"),))]
    record_scan(conn, _scan("s1", hosts), ts=T1)  # auth_states=None
    events = record_scan(conn, _scan("s2", hosts), ts=T2)
    assert events == []
    row = conn.execute(
        "SELECT auth_state FROM services WHERE target = ? AND ip = '192.168.1.1' AND port = 80",
        (TARGET,),
    ).fetchone()
    assert row == ("",)


# --- first_seen / last_seen ----------------------------------------------------


def test_first_seen_preserved_last_seen_advances(conn: sqlite3.Connection) -> None:
    hosts = [_host("192.168.1.1", "router", (_port(80, "http", "nginx 1.18.0"),))]
    record_scan(conn, _scan("s1", hosts), ts=T1)
    record_scan(conn, _scan("s2", hosts), ts=T2)

    host_row = conn.execute(
        "SELECT first_seen, last_seen FROM hosts WHERE target = ? AND ip = '192.168.1.1'",
        (TARGET,),
    ).fetchone()
    assert host_row == (T1.isoformat(), T2.isoformat())

    svc_row = conn.execute(
        "SELECT first_seen, last_seen FROM services"
        " WHERE target = ? AND ip = '192.168.1.1' AND port = 80",
        (TARGET,),
    ).fetchone()
    assert svc_row == (T1.isoformat(), T2.isoformat())


# --- compute_drift round-trip ---------------------------------------------------


def test_compute_drift_roundtrips_all_six_kinds(conn: sqlite3.Connection) -> None:
    record_scan(
        conn,
        _scan(
            "s1",
            [
                _host("192.168.1.1", "router", (_port(80, "http", "nginx 1.18.0"), _port(23, "telnet"))),
                _host("192.168.1.20", "cam"),
            ],
        ),
        ts=T1,
        auth_states={("192.168.1.1", 80): "unauth"},
    )
    scan2 = _scan(
        "s2",
        [
            # same host: port 443 NEW_PORT, 23 CLOSED_PORT, 80 VERSION+AUTH_CHANGE
            _host("192.168.1.1", "router", (_port(80, "http", "nginx 1.20.1"), _port(443, "https"))),
            # 192.168.1.20 gone; 192.168.1.30 new
            _host("192.168.1.30", "tv"),
        ],
    )
    events = record_scan(
        conn, scan2, ts=T2, auth_states={("192.168.1.1", 80): "gated"}
    )
    assert _kinds(events) == {
        "NEW_HOST",
        "GONE_HOST",
        "NEW_PORT",
        "CLOSED_PORT",
        "VERSION_CHANGE",
        "AUTH_CHANGE",
    }

    # explicit scan_id round-trip
    reconstructed = compute_drift(conn, TARGET, "s2")
    assert reconstructed == events

    # default = latest scan of the target
    assert compute_drift(conn, TARGET) == events

    # before/after intact per kind
    by_kind = {e.kind: e for e in reconstructed}
    assert (by_kind["NEW_HOST"].before, by_kind["NEW_HOST"].after) == ("absent", "present")
    assert (by_kind["GONE_HOST"].before, by_kind["GONE_HOST"].after) == ("present", "absent")
    assert (by_kind["NEW_PORT"].before, by_kind["NEW_PORT"].after) == ("closed", "open")
    assert (by_kind["CLOSED_PORT"].before, by_kind["CLOSED_PORT"].after) == ("open", "closed")
    assert (by_kind["VERSION_CHANGE"].before, by_kind["VERSION_CHANGE"].after) == (
        "nginx 1.18.0",
        "nginx 1.20.1",
    )
    assert (by_kind["AUTH_CHANGE"].before, by_kind["AUTH_CHANGE"].after) == ("unauth", "gated")
    assert by_kind["NEW_HOST"].port is None
    assert all(e.ts == T2 for e in reconstructed)

    # the baseline scan reconstructs to nothing
    assert compute_drift(conn, TARGET, "s1") == []


def test_compute_drift_unknown_target_returns_empty(conn: sqlite3.Connection) -> None:
    assert compute_drift(conn, "10.0.0.0/24") == []


def test_drift_is_scoped_per_target(conn: sqlite3.Connection) -> None:
    other = "10.0.0.0/24"
    record_scan(conn, _scan("s1", [_host("192.168.1.1")]), ts=T1)
    # first scan of a DIFFERENT target is its own baseline
    events = record_scan(conn, _scan("s2", [_host("10.0.0.5")], target=other), ts=T2)
    assert events == []


# --- findings as observations ---------------------------------------------------


def test_findings_recorded_as_observations(conn: sqlite3.Connection) -> None:
    finding = _finding()
    record_scan(
        conn,
        _scan("s1", [_host("192.168.1.1", "router", (_port(80, "http"),))]),
        findings=[finding],
        ts=T1,
    )
    rows = conn.execute(
        "SELECT scan_id, ip, port, kind, detail, ts FROM observations"
        " WHERE kind = ?",
        (finding.finding_class,),
    ).fetchall()
    assert rows == [
        ("s1", finding.host, finding.port, "DEFAULT-PANEL", finding.title, T1.isoformat())
    ]
    # findings are not drift and never leak into compute_drift
    assert compute_drift(conn, TARGET, "s1") == []


def test_drift_events_and_findings_coexist_in_observations(conn: sqlite3.Connection) -> None:
    hosts = [_host("192.168.1.1", "router", (_port(80, "http"),))]
    record_scan(conn, _scan("s1", hosts), ts=T1)
    record_scan(
        conn,
        _scan("s2", hosts + [_host("192.168.1.30")]),
        findings=[_finding()],
        ts=T2,
    )
    kinds = {
        row[0]
        for row in conn.execute(
            "SELECT kind FROM observations WHERE scan_id = 's2'"
        ).fetchall()
    }
    assert kinds == {"NEW_HOST", "DEFAULT-PANEL"}
