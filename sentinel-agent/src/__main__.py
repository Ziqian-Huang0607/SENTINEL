"""SENTINEL agent CLI: ``cd sentinel-agent && python -m src`` (agent-spec.md section 10).

Flow: CONFIRM scope gate (audit-logged) -> scanner sweep -> per-target agent
investigation (LLM loop or deterministic playbook) -> memory + drift ->
agent_report.json + terminal summary.

Exit codes mirror sentinel-cli: 0 ok, 1 error, 2 aborted at the scope gate.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from src import __version__
from src.loop import investigate_target, select_targets
from src.memory import compute_drift, init_db, memory_path, record_scan
from src.model_client import PlaybookClient, select_client
from src.playbook import investigate_target_playbook
from src.report import assemble_report
from src.scope import Scope
from src.service_id import identify_unknown_service
from src.tools import TOOL_REGISTRY

TIERS = ("daily", "authority", "hacker", "military")
DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_ANALYZER_URL = "http://localhost:8710"

# Audit constants mirror sentinel-cli/internal/audit exactly: one JSON line
# per gated attempt, same field names and values.
AUDIT_METHOD_TYPED = "typed-CONFIRM"
AUDIT_METHOD_YES = "--yes"
AUDIT_CONFIRMED = "confirmed"
AUDIT_ABORTED = "aborted"


def audit_log_path() -> Path:
    """~/.sentinel/audit.log (SENTINEL_AUDIT_LOG override for tests)."""
    override = os.environ.get("SENTINEL_AUDIT_LOG")
    if override:
        return Path(override)
    return Path.home() / ".sentinel" / "audit.log"


def audit(target: str, tier: str, method: str, outcome: str) -> None:
    """Append one JSON-lines audit entry (same schema as the Go CLI)."""
    path = audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "tier": tier,
        "confirm_method": method,
        "outcome": outcome,
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def scope_gate(target: str, tier: str, assume_yes: bool) -> bool:
    """Print the scope summary and require typing exactly CONFIRM.

    Returns True when the scan is authorized. Every attempt is audit-logged,
    including aborts (same contract as sentinel-cli).
    """
    method = AUDIT_METHOD_YES if assume_yes else AUDIT_METHOD_TYPED
    print(f"Target: {target}")
    print(f"Tier:   {tier}")
    print("Scope is restricted to private/loopback ranges unless --allow-public.")
    authorized = True
    if not assume_yes:
        try:
            typed = input('Type CONFIRM to authorize this scan: ')
        except (EOFError, KeyboardInterrupt):
            typed = ""
        authorized = typed == "CONFIRM"
    audit(target, tier, method, AUDIT_CONFIRMED if authorized else AUDIT_ABORTED)
    return authorized


def run_scanner(scanner: Path, target: str, tier: str, out_path: Path) -> dict:
    """Run the Rust scanner sweep and return the parsed scan.json."""
    subprocess.run(
        [str(scanner), "--target", target, "--tier", tier, "--output", str(out_path)],
        check=True,
        timeout=300,
    )
    return json.loads(out_path.read_text(encoding="utf-8"))


def posture_auth_states(scan: dict) -> dict[tuple[str, int], str]:
    """(ip, port) -> 'unauth' map derived from posture findings (memory input)."""
    states: dict[tuple[str, int], str] = {}
    for finding in scan.get("posture_findings", []):
        if "UNAUTH" in finding.get("id", ""):
            states[(finding["host"], finding["port"])] = "unauth"
    return states


async def investigate_all(
    scan: dict, client, scope: Scope, max_steps: int, max_seconds: int, transcripts: Path
):
    """Investigate every selected target; returns list[TargetInvestigation]."""
    investigations = []
    for brief in select_targets(scan):
        if isinstance(client, PlaybookClient):
            inv = await investigate_target_playbook(brief, TOOL_REGISTRY, scope)
        else:
            pre = None
            if brief.trigger == "unknown_service":
                pre = await identify_unknown_service(brief, TOOL_REGISTRY, client, scope)
                if pre is not None:
                    brief.hints["preidentified"] = {
                        "service": pre.detail,
                        "confidence": pre.confidence,
                    }
            inv = await investigate_target(
                brief, TOOL_REGISTRY, client, scope,
                max_steps=max_steps, max_seconds=max_seconds, transcript_dir=transcripts,
            )
            if pre is not None and all(f.id != pre.id for f in inv.findings):
                inv.findings.insert(0, pre)
        investigations.append(inv)
    return investigations


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel_agent",
        description="SENTINEL agent — AI-driven internal-network investigation.",
    )
    parser.add_argument("--target", required=True, help="CIDR or IP (private/loopback)")
    parser.add_argument("--tier", required=True, choices=TIERS)
    parser.add_argument(
        "--scanner",
        type=Path,
        default=Path(__file__).resolve().parents[2]
        / "sentinel-scanner"
        / "target"
        / "release"
        / "sentinel-scanner",
    )
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument("--max-steps", type=int, default=12)
    parser.add_argument("--max-seconds", type=int, default=180)
    parser.add_argument("--out", type=Path, default=Path("agent_report.json"))
    parser.add_argument("--transcripts-dir", type=Path, default=Path("agent_transcripts"))
    parser.add_argument("--yes", action="store_true", help="Skip the CONFIRM gate (tests/CI)")
    parser.add_argument(
        "--scan-file",
        type=Path,
        default=None,
        help="Reuse an existing scan.json instead of running the scanner",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Hand off to the analyzer/reports services after the agent run",
    )
    parser.add_argument("--analyzer-url", default=DEFAULT_ANALYZER_URL)
    parser.add_argument(
        "--report-formats",
        default="json,pdf",
        help="Comma-separated report formats for --report (json,sarif,pdf,html)",
    )
    return parser


async def hand_off_to_reports(analyzer_url: str, scan: dict, agent: dict, formats: list[str]) -> dict:
    """POST scan -> /analyze, then {scan, analysis, agent, formats} -> /report.

    Returns the reports-service JSON (output file paths). Raises on transport
    or HTTP errors — the caller turns that into a non-fatal observation.
    """
    import httpx

    base = analyzer_url.rstrip("/")
    async with httpx.AsyncClient(timeout=120.0) as http:
        analysis = (await http.post(f"{base}/analyze", json=scan)).json()
        body = {"scan": scan, "analysis": analysis, "agent": agent, "formats": formats}
        resp = await http.post(f"{base}/report", json=body)
        resp.raise_for_status()
        return resp.json()


async def async_main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not scope_gate(args.target, args.tier, args.yes):
        print("Scan aborted at the scope gate.")
        return 2
    if args.scan_file is not None:
        if not args.scan_file.is_file():
            print(f"error: scan file not found at {args.scan_file}")
            return 1
    elif not args.scanner.is_file():
        print(f"error: scanner binary not found at {args.scanner} (build it first)")
        return 1

    started = datetime.now(timezone.utc)
    args.transcripts_dir.mkdir(parents=True, exist_ok=True)
    if args.scan_file is not None:
        scan = json.loads(args.scan_file.read_text(encoding="utf-8"))
    else:
        with tempfile.TemporaryDirectory(prefix="sentinel-agent-") as tmp:
            scan = run_scanner(args.scanner, args.target, args.tier, Path(tmp) / "scan.json")

    scope = Scope.from_scan(scan)
    client = await select_client(args.ollama_url)
    observations: list[str] = []
    if isinstance(client, PlaybookClient):
        observations.append(
            "Ollama unavailable (or playbook forced); investigations ran the "
            "deterministic playbook — same tools, fixed order, no model."
        )

    investigations = await investigate_all(
        scan, client, scope, args.max_steps, args.max_seconds, args.transcripts_dir
    )

    conn = init_db()
    findings = [f for inv in investigations for f in inv.findings]
    drift = record_scan(
        conn, scan, findings=findings, ts=started, auth_states=posture_auth_states(scan)
    )
    drift = drift or compute_drift(conn, scan["target"], scan_id=scan["scan_id"])

    finished = datetime.now(timezone.utc)
    report = assemble_report(
        scan, client.name, investigations, drift, started, finished, observations
    )
    report_json = report.model_dump_json(indent=2) + "\n"
    args.out.write_text(report_json, encoding="utf-8")

    report_outputs: dict | None = None
    if args.report:
        try:
            report_outputs = await hand_off_to_reports(
                args.analyzer_url,
                scan,
                json.loads(report_json),
                [f.strip() for f in args.report_formats.split(",") if f.strip()],
            )
        except Exception as exc:  # noqa: BLE001 — transport or HTTP failure, non-fatal
            print(f"warning: report hand-off failed ({exc}); agent_report.json still written")

    by_class: dict[str, int] = {}
    for f in report.findings:
        by_class[f.finding_class] = by_class.get(f.finding_class, 0) + 1
    print(f"SENTINEL agent v{__version__} — model: {client.name}")
    print(f"hosts: {len(scan.get('hosts', []))}  targets investigated: {len(investigations)}")
    print(f"findings: {len(report.findings)} {by_class or ''}")
    print(f"drift events: {len(drift)}")
    print(f"risk score: {report.risk_score:.2f} / 10.00")
    print(f"report: {args.out}  transcripts: {args.transcripts_dir}  memory: {memory_path()}")
    if report_outputs:
        print(f"service reports: {report_outputs}")
    return 0


def main() -> int:
    """Entry point; Ctrl+C aborts cleanly like the CLI's gate."""
    try:
        return asyncio.run(async_main())
    except KeyboardInterrupt:
        print("\nAborted by operator.")
        return 2


if __name__ == "__main__":
    sys.exit(main())
