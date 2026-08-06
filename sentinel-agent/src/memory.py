"""SQLite network memory + drift detection (agent-spec.md section 9).

The agent persists every confirmed scan into a local sqlite database and
derives drift events by diffing each incoming scan against the stored state
for the same target. The DDL below is sacred — it mirrors the spec verbatim.

Semantics
---------
- The FIRST scan recorded for a target is the baseline: it produces NO
  drift events.
- "Stored state" for a diff is the state as of the previous scan of the
  same target — hosts/services rows whose ``last_seen`` matches the previous
  scan's timestamp. Rows persist (first_seen preserved, last_seen advanced
  by later sightings), so a host that vanished and later reappears is
  reported as NEW_HOST again while keeping its original first_seen.
- Six drift kinds (DriftEvent):
    NEW_HOST       host in the new scan, absent from stored state
    GONE_HOST      host in stored state, absent from the new scan
    NEW_PORT       open port in the new scan, absent from stored state
    CLOSED_PORT    port in stored state, absent from the new scan
    VERSION_CHANGE same (target, ip, port), differing non-empty versions
    AUTH_CHANGE    same (target, ip, port), differing auth_state
  Host-level events carry port=None; a GONE_HOST subsumes its ports and a
  NEW_HOST subsumes its ports (no double reporting).
- before/after strings: "absent"/"present" for host events, "closed"/"open"
  for port events, the actual versions for VERSION_CHANGE, and the actual
  auth states for AUTH_CHANGE (e.g. "unauth" -> "gated").
- Every drift event is also appended to the observations table
  (kind = drift kind, detail = "before -> after"), so compute_drift can
  reconstruct DriftEvents for any recorded scan.

Auth states are NOT part of scan.json: they come from posture findings, so
``record_scan`` accepts an optional ``auth_states`` mapping ``(ip, port) ->
state``. When omitted, every service stores auth_state="" and no AUTH_CHANGE
can fire.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from src.models import AgentFinding, DriftEvent

# --- Sacred DDL (agent-spec.md section 9, verbatim) -------------------------

_DDL = (
    """CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, ts TEXT, target TEXT,
  tier TEXT, risk_score REAL)""",
    """CREATE TABLE IF NOT EXISTS hosts (target TEXT, ip TEXT, hostname TEXT,
  first_seen TEXT, last_seen TEXT, PRIMARY KEY (target, ip))""",
    """CREATE TABLE IF NOT EXISTS services (target TEXT, ip TEXT, port INTEGER,
  service TEXT, version TEXT, auth_state TEXT, first_seen TEXT, last_seen TEXT,
  PRIMARY KEY (target, ip, port))""",
    """CREATE TABLE IF NOT EXISTS observations (id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT, ip TEXT, port INTEGER, kind TEXT, detail TEXT, ts TEXT)""",
)

_DRIFT_KINDS = (
    "NEW_HOST",
    "GONE_HOST",
    "NEW_PORT",
    "CLOSED_PORT",
    "VERSION_CHANGE",
    "AUTH_CHANGE",
)

_ENV_VAR = "SENTINEL_MEMORY_DB"


def memory_path() -> Path:
    """Return the memory database path, creating parent directories.

    Honors the SENTINEL_MEMORY_DB override; otherwise defaults to
    ``~/.sentinel/memory.db``. The file itself is not created here.
    """
    override = os.environ.get(_ENV_VAR)
    path = Path(override) if override else Path.home() / ".sentinel" / "memory.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def init_db(path: Path | None = None) -> sqlite3.Connection:
    """Open the database at ``path`` (default: memory_path()) and create tables.

    Idempotent: the DDL uses CREATE TABLE IF NOT EXISTS, so repeated calls
    are safe. Returns the open connection.
    """
    db_path = path if path is not None else memory_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    for stmt in _DDL:
        conn.execute(stmt)
    conn.commit()
    return conn


def _previous_scan_ts(conn: sqlite3.Connection, target: str) -> str | None:
    """Timestamp of the most recently recorded scan for ``target`` (None if none)."""
    row = conn.execute(
        "SELECT ts FROM scans WHERE target = ? ORDER BY rowid DESC LIMIT 1",
        (target,),
    ).fetchone()
    return row[0] if row else None


def _stored_hosts(conn: sqlite3.Connection, target: str, state_ts: str) -> dict[str, str]:
    """Hosts present as of the previous scan: {ip: hostname}."""
    rows = conn.execute(
        "SELECT ip, hostname FROM hosts WHERE target = ? AND last_seen = ?",
        (target, state_ts),
    ).fetchall()
    return {ip: hostname for ip, hostname in rows}


def _stored_services(
    conn: sqlite3.Connection, target: str, state_ts: str
) -> dict[tuple[str, int], tuple[str, str, str]]:
    """Services present as of the previous scan: {(ip, port): (service, version, auth)}."""
    rows = conn.execute(
        "SELECT ip, port, service, version, auth_state FROM services"
        " WHERE target = ? AND last_seen = ?",
        (target, state_ts),
    ).fetchall()
    return {(ip, port): (service, version, auth) for ip, port, service, version, auth in rows}


def _incoming(scan: dict) -> tuple[dict[str, str], dict[tuple[str, int], dict[str, str]]]:
    """Extract hosts and open-port services from a scan.json-shaped dict.

    Only ports with state == "open" become service rows (mirrors scan.json).
    """
    hosts: dict[str, str] = {}
    services: dict[tuple[str, int], dict[str, str]] = {}
    for host in scan.get("hosts", []):
        ip = host["ip"]
        hosts[ip] = host.get("hostname", "") or ""
        for port_info in host.get("ports", []):
            if port_info.get("state") != "open":
                continue
            services[(ip, int(port_info["port"]))] = {
                "service": port_info.get("service", "") or "",
                "version": port_info.get("version", "") or "",
            }
    return hosts, services


def _diff(
    target: str,
    ts: datetime,
    hosts: dict[str, str],
    services: dict[tuple[str, int], dict[str, str]],
    stored_hosts: dict[str, str],
    stored_services: dict[tuple[str, int], tuple[str, str, str]],
    auth_states: dict[tuple[str, int], str] | None,
) -> list[DriftEvent]:
    """Diff incoming scan content against stored state; deterministic order."""
    events: list[DriftEvent] = []

    for ip in sorted(hosts):
        if ip not in stored_hosts:
            events.append(
                DriftEvent(kind="NEW_HOST", host=ip, before="absent", after="present", ts=ts)
            )
    for ip in sorted(stored_hosts):
        if ip not in hosts:
            events.append(
                DriftEvent(kind="GONE_HOST", host=ip, before="present", after="absent", ts=ts)
            )

    # Port-level drift only for hosts present on both sides — a NEW_HOST or
    # GONE_HOST already subsumes its ports.
    for ip in sorted(set(hosts) & set(stored_hosts)):
        current = {port for (hip, port) in services if hip == ip}
        stored = {port for (hip, port) in stored_services if hip == ip}
        for port in sorted(current - stored):
            events.append(
                DriftEvent(
                    kind="NEW_PORT", host=ip, port=port, before="closed", after="open", ts=ts
                )
            )
        for port in sorted(stored - current):
            events.append(
                DriftEvent(
                    kind="CLOSED_PORT", host=ip, port=port, before="open", after="closed", ts=ts
                )
            )
        for port in sorted(current & stored):
            _old_service, old_version, old_auth = stored_services[(ip, port)]
            new_version = services[(ip, port)]["version"]
            if old_version and new_version and old_version != new_version:
                events.append(
                    DriftEvent(
                        kind="VERSION_CHANGE",
                        host=ip,
                        port=port,
                        before=old_version,
                        after=new_version,
                        ts=ts,
                    )
                )
            new_auth = (auth_states or {}).get((ip, port), "")
            if new_auth != old_auth:
                events.append(
                    DriftEvent(
                        kind="AUTH_CHANGE",
                        host=ip,
                        port=port,
                        before=old_auth,
                        after=new_auth,
                        ts=ts,
                    )
                )
    return events


def record_scan(
    conn: sqlite3.Connection,
    scan: dict,
    findings: list[AgentFinding] | None = None,
    ts: datetime | None = None,
    auth_states: dict[tuple[str, int], str] | None = None,
) -> list[DriftEvent]:
    """Record a scan, compute drift, and persist everything atomically.

    Order of operations (drift is computed BEFORE any mutation):

    1. Diff the incoming scan's hosts/open services against the stored state
       for the same target -> the returned DriftEvents. The first scan of a
       target is the baseline and yields no events.
    2. Upsert hosts/services rows (first_seen preserved on conflict,
       last_seen advanced to this scan's ts).
    3. Insert the scans row and append observations rows: one per drift
       event (kind = drift kind, detail = "before -> after") and one per
       AgentFinding (kind = finding_class, detail = title).

    ``auth_states`` maps ``(ip, port)`` to a posture-derived auth state
    (e.g. "unauth", "gated"); None means all services store "".
    """
    scan_ts = ts or datetime.now(timezone.utc)
    ts_text = scan_ts.isoformat()
    target = scan["target"]
    hosts, services = _incoming(scan)

    with conn:
        # 1) Drift against stored state, before mutating. No prior scan for
        #    this target -> baseline, no events.
        prev_ts = _previous_scan_ts(conn, target)
        events: list[DriftEvent] = []
        if prev_ts is not None:
            events = _diff(
                target,
                scan_ts,
                hosts,
                services,
                _stored_hosts(conn, target, prev_ts),
                _stored_services(conn, target, prev_ts),
                auth_states,
            )

        # 2) Upsert hosts/services (first_seen preserved, last_seen updated).
        for ip, hostname in hosts.items():
            conn.execute(
                "INSERT INTO hosts (target, ip, hostname, first_seen, last_seen)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(target, ip) DO UPDATE SET"
                "   hostname = excluded.hostname, last_seen = excluded.last_seen",
                (target, ip, hostname, ts_text, ts_text),
            )
        for (ip, port), info in services.items():
            auth = (auth_states or {}).get((ip, port), "")
            conn.execute(
                "INSERT INTO services (target, ip, port, service, version, auth_state,"
                " first_seen, last_seen)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(target, ip, port) DO UPDATE SET"
                "   service = excluded.service, version = excluded.version,"
                "   auth_state = excluded.auth_state, last_seen = excluded.last_seen",
                (target, ip, port, info["service"], info["version"], auth, ts_text, ts_text),
            )

        # 3) scans row + observations for drift events and agent findings.
        conn.execute(
            "INSERT INTO scans (scan_id, ts, target, tier, risk_score)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                scan["scan_id"],
                ts_text,
                target,
                scan.get("tier", "") or "",
                float(scan.get("risk_score", 0.0) or 0.0),
            ),
        )
        for event in events:
            conn.execute(
                "INSERT INTO observations (scan_id, ip, port, kind, detail, ts)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    scan["scan_id"],
                    event.host,
                    event.port,
                    event.kind,
                    f"{event.before} -> {event.after}",
                    ts_text,
                ),
            )
        for finding in findings or []:
            conn.execute(
                "INSERT INTO observations (scan_id, ip, port, kind, detail, ts)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    scan["scan_id"],
                    finding.host,
                    finding.port,
                    finding.finding_class,
                    finding.title,
                    ts_text,
                ),
            )
    return events


def compute_drift(
    conn: sqlite3.Connection, target: str, scan_id: str | None = None
) -> list[DriftEvent]:
    """Reconstruct DriftEvents from observations for one scan of ``target``.

    Defaults to the latest recorded scan of the target. before/after are
    recovered from the stored "before -> after" detail string, so events
    round-trip exactly as record_scan produced them. Returns an empty list
    when no matching scan exists.
    """
    if scan_id is None:
        row = conn.execute(
            "SELECT scan_id FROM scans WHERE target = ? ORDER BY rowid DESC LIMIT 1",
            (target,),
        ).fetchone()
        if row is None:
            return []
        scan_id = row[0]

    placeholders = ", ".join("?" for _ in _DRIFT_KINDS)
    rows = conn.execute(
        f"SELECT ip, port, kind, detail, ts FROM observations"
        f" WHERE scan_id = ? AND kind IN ({placeholders}) ORDER BY id",
        (scan_id, *_DRIFT_KINDS),
    ).fetchall()

    events: list[DriftEvent] = []
    for ip, port, kind, detail, ts_text in rows:
        before, sep, after = detail.partition(" -> ")
        if not sep:
            before, after = "", detail
        events.append(
            DriftEvent(
                kind=kind,
                host=ip,
                port=port,
                before=before,
                after=after,
                ts=datetime.fromisoformat(ts_text),
            )
        )
    return events
