"""Agent loop — observe -> hypothesize -> probe -> conclude (spec 3 + 7).

``select_targets`` deterministically picks interesting hosts from a scan
(never LLM-chosen). ``investigate_target`` runs the per-target LLM tool-use
loop: each turn is one strict-JSON completion, either an action against the
injected tool registry or a final conclusion. All conclusions are hardened
deterministically: severities come from ``CLASS_SEVERITY`` (never the
model), findings must cite transcript evidence ids (grounding, DRIFT
exempt), and offensive phrasing is filtered before anything enters a report.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from src.model_client import ModelClient, ModelUnavailable
from src.models import (
    CLASS_SEVERITY,
    AgentFinding,
    EvidenceRef,
    TargetBrief,
    TargetInvestigation,
)
from src.scope import Scope, ScopeViolation
from src.tools.base import Tool

DEFAULT_MAX_STEPS = 12
DEFAULT_MAX_SECONDS = 180.0
THOUGHT_LIMIT = 400
SUMMARY_LIMIT = 600
TRANSCRIPT_TAIL = 6

# Trigger priority (agent-spec.md section 7): gateway first, then unauth,
# then unknown services, then CVE hosts.
TRIGGER_ORDER = ("gateway", "unauth_posture", "unknown_service", "cve")

SYSTEM_PROMPT = (
    "You are SENTINEL-agent, a defensive internal-network security "
    "investigator. You investigate ONE target per session.\n"
    "RULES:\n"
    "1. Use ONLY the benign reconnaissance tools listed in the tool menu. "
    "No credential attempts, no exploit payloads, no brute forcing.\n"
    "2. Observed evidence only: every finding MUST cite evidence_ids from "
    "THIS transcript (E1, E2, ...). Never cite evidence you have not "
    "observed.\n"
    "3. Defensive framing only: describe exposure and remediation for the "
    "defender. Never use offensive or exploitation language.\n"
    "4. An empty findings list is a valid result — do not invent findings.\n"
    "5. Respond with ONE strict JSON object and nothing else (no prose, no "
    "markdown fences), either:\n"
    '   {"thought": "<=400 chars", "action": {"tool": "<name>", "args": {}}}\n'
    "or, to conclude the target:\n"
    '   {"thought": "...", "final": {"summary": "<=600 chars", '
    '"findings": [AgentFinding], "confidence": 0.0-1.0}}\n'
    "AgentFinding: {id, finding_class: SERVICE-IDENT|DEFAULT-PANEL|"
    "SENSITIVE-SERVICE|MISCONFIG|DRIFT, host, port, severity, title, "
    "detail, evidence: [evidence ids], confidence}."
)

SCHEMA_REMINDER = (
    "SCHEMA REMINDER: your previous reply was invalid. Respond with ONE "
    "strict JSON object and nothing else (no prose, no code fences). It "
    "MUST be either "
    '{"thought": "...", "action": {"tool": "<name from the tool menu>", '
    '"args": {...}}} or {"thought": "...", "final": {"summary": "...", '
    '"findings": [...], "confidence": 0.0-1.0}}. Every finding MUST cite '
    "evidence ids (E1, E2, ...) that exist in this transcript; findings "
    "citing unknown evidence are rejected."
)

# Offensive phrasing that must never survive into agent output (R8 filter,
# same list as the analyzer's remediation guard). Matching text is replaced
# with REMOVED_MARKER, case-insensitively.
_OFFENSIVE_PATTERNS = (
    "exploit",
    "compromise",
    "gain access",
    "escalate privileges",
    "brute force",
    "brute-force",
    "crack ",
    "payload",
    "shell on",
    "pivot to attack",
)
REMOVED_MARKER = "[removed: non-defensive phrasing]"
_OFFENSIVE_RE = re.compile(
    "|".join(re.escape(pattern) for pattern in _OFFENSIVE_PATTERNS),
    re.IGNORECASE,
)

_HOST_SAFE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


class ProtocolViolation(Exception):
    """The model reply broke the section-3 wire format or grounding rules."""


def filter_offensive(text: str) -> str:
    """Replace offensive phrasing with the defensive-only marker."""
    return _OFFENSIVE_RE.sub(REMOVED_MARKER, text)


def strip_code_fences(text: str) -> str:
    """Remove a surrounding ``` / ```json markdown fence, if present."""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    return stripped


def select_targets(scan: dict) -> list[TargetBrief]:
    """Deterministically pick interesting targets from a scan.json dict.

    A host is interesting when it has (a) an unauthenticated posture
    finding (``UNAUTH`` in the finding id), (b) an open port with an
    empty/None service (unknown), (c) a gateway posture finding
    (``GATEWAY`` in the id), or (d) a CVE finding in ``vulnerabilities``.
    Ports are grouped per host; output order is gateway first, then
    unauth, then unknowns, then CVE hosts (stable within each class).
    """
    posture_by_host: dict[str, list[dict]] = {}
    for finding in scan.get("posture_findings", []):
        posture_by_host.setdefault(finding.get("host", ""), []).append(finding)
    vulns_by_host: dict[str, list[dict]] = {}
    for vuln in scan.get("vulnerabilities", []):
        vulns_by_host.setdefault(vuln.get("host", ""), []).append(vuln)

    buckets: dict[str, list[TargetBrief]] = {key: [] for key in TRIGGER_ORDER}
    for host in scan.get("hosts", []):
        ip = host.get("ip", "")
        host_posture = posture_by_host.get(ip, [])
        host_vulns = vulns_by_host.get(ip, [])
        posture_ids = [str(f.get("id", "")) for f in host_posture]
        gateway_ids = [pid for pid in posture_ids if "GATEWAY" in pid]
        unauth_ids = [pid for pid in posture_ids if "UNAUTH" in pid]
        ports = host.get("ports", [])
        unknown_ports = [
            p for p in ports
            if p.get("state") == "open" and not p.get("service")
        ]

        if gateway_ids:
            trigger = "gateway"
        elif unauth_ids:
            trigger = "unauth_posture"
        elif unknown_ports:
            trigger = "unknown_service"
        elif host_vulns:
            trigger = "cve"
        else:
            continue

        interesting_ports = sorted({
            int(f["port"]) for f in host_posture if f.get("port")
        } | {
            int(p["port"]) for p in unknown_ports if p.get("port")
        } | {
            int(v["port"]) for v in host_vulns if v.get("port")
        })
        hints: dict[str, Any] = {
            "services": {
                str(p["port"]): p["service"]
                for p in ports if p.get("port") and p.get("service")
            },
            "versions": {
                str(p["port"]): p["version"]
                for p in ports if p.get("port") and p.get("version")
            },
            "posture_ids": posture_ids,
            "cve_ids": [str(v.get("cve_id", "")) for v in host_vulns],
        }
        if host.get("hostname"):
            hints["hostname"] = host["hostname"]
        buckets[trigger].append(
            TargetBrief(host=ip, ports=interesting_ports, trigger=trigger, hints=hints)
        )

    briefs: list[TargetBrief] = []
    for key in TRIGGER_ORDER:
        briefs.extend(buckets[key])
    return briefs


def build_user_prompt(
    brief: TargetBrief,
    registry: dict[str, Tool],
    transcript: list[dict[str, Any]],
) -> str:
    """Target brief + tool menu + transcript tail (last 6 turns, excerpts)."""
    menu = "\n".join(
        sorted(tool.menu_line() for tool in registry.values())
    ) or "(no tools available)"
    tail_lines = []
    for entry in transcript[-TRANSCRIPT_TAIL:]:
        line = f"Turn {entry['turn']}: {entry.get('kind', '?')}"
        if entry.get("action"):
            line += f" {entry['action']['tool']}({json.dumps(entry['action']['args'])})"
        for excerpt in entry.get("excerpts", []):
            line += f"\n  {excerpt}"
        if entry.get("error"):
            line += f"\n  error: {entry['error']}"
        tail_lines.append(line)
    tail = "\n".join(tail_lines) or "(no turns yet)"
    return (
        "TARGET BRIEF:\n"
        f"{brief.model_dump_json()}\n\n"
        "TOOL MENU:\n"
        f"{menu}\n\n"
        "TRANSCRIPT TAIL (last turns, evidence excerpts only):\n"
        f"{tail}\n\n"
        "Either call one tool or conclude the target with your final JSON."
    )


def parse_turn(raw: str) -> dict[str, Any]:
    """Parse one model reply into a validated turn dict.

    Raises ``ProtocolViolation`` on invalid JSON or any schema violation of
    the section-3 wire format.
    """
    try:
        data = json.loads(strip_code_fences(raw))
    except json.JSONDecodeError as exc:
        raise ProtocolViolation(f"reply is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ProtocolViolation("reply is not a JSON object")
    thought = data.get("thought")
    if not isinstance(thought, str):
        raise ProtocolViolation("missing string 'thought'")
    data["thought"] = thought[:THOUGHT_LIMIT]
    has_action = "action" in data
    has_final = "final" in data
    if has_action == has_final:
        raise ProtocolViolation("reply must contain exactly one of 'action'/'final'")
    if has_action:
        action = data["action"]
        if not isinstance(action, dict) or not isinstance(action.get("tool"), str):
            raise ProtocolViolation("'action' must be {tool: str, args: object}")
        if not isinstance(action.get("args", {}), dict):
            raise ProtocolViolation("'action.args' must be a JSON object")
        action.setdefault("args", {})
    else:
        final = data["final"]
        if not isinstance(final, dict):
            raise ProtocolViolation("'final' must be a JSON object")
        if not isinstance(final.get("summary", ""), str):
            raise ProtocolViolation("'final.summary' must be a string")
        if not isinstance(final.get("findings", []), list):
            raise ProtocolViolation("'final.findings' must be a list")
        final.setdefault("summary", "")
        final.setdefault("findings", [])
    return data


def validate_final(
    final: dict[str, Any],
    brief: TargetBrief,
    known_evidence_ids: set[str],
) -> list[AgentFinding]:
    """Validate, ground, and harden the model's final findings.

    Severities are overridden with ``CLASS_SEVERITY``, ids are renumbered
    canonically (``AGENT-<CLASS>-<n>``), missing host/port default to the
    brief, and offensive phrasing is filtered. Raises ``ProtocolViolation``
    when a finding fails schema validation or cites an evidence id absent
    from the transcript (grounding; DRIFT findings are exempt).
    """
    findings: list[AgentFinding] = []
    for raw_finding in final.get("findings", []):
        if not isinstance(raw_finding, dict):
            raise ProtocolViolation("finding is not a JSON object")
        candidate = dict(raw_finding)
        candidate.setdefault("id", "AGENT-PENDING")
        candidate.setdefault("host", brief.host)
        if not candidate.get("port") and brief.ports:
            candidate["port"] = brief.ports[0]
        candidate.setdefault("severity", 0.0)
        candidate.setdefault("confidence", 0.5)
        try:
            finding = AgentFinding.model_validate(candidate)
        except ValidationError as exc:
            raise ProtocolViolation(f"finding failed validation: {exc}") from exc
        cited = [eid for eid in finding.evidence if eid not in known_evidence_ids]
        if finding.finding_class != "DRIFT":
            if not finding.evidence:
                raise ProtocolViolation(
                    f"finding {finding.id} cites no evidence (grounding)"
                )
            if cited:
                raise ProtocolViolation(
                    f"finding {finding.id} cites unknown evidence ids: {cited}"
                )
        index = len(findings) + 1
        findings.append(
            finding.model_copy(update={
                "id": f"AGENT-{finding.finding_class}-{index}",
                "severity": finding.severity_for_class(),
                "title": filter_offensive(finding.title),
                "detail": filter_offensive(finding.detail),
            })
        )
    return findings


def _sanitize_filename(text: str) -> str:
    """Make a string safe for use as a transcript filename component."""
    return _HOST_SAFE_RE.sub("_", text).strip("_") or "unknown"


def _write_transcript(
    transcript_dir: Path,
    brief: TargetBrief,
    model: str,
    transcript: list[dict[str, Any]],
    evidence: list[EvidenceRef],
    investigation: TargetInvestigation,
) -> str:
    """Best-effort dump of the full transcript JSON; returns the path.

    Returns the path ``transcript_dir / <host>_<port-or-multi>.json`` even
    when the write fails (transcript persistence must never break an
    investigation); on failure the empty string is returned instead.
    """
    port_part = (
        str(brief.ports[0]) if len(brief.ports) == 1 else "multi"
    )
    filename = f"{_sanitize_filename(brief.host)}_{port_part}.json"
    path = Path(transcript_dir) / filename
    record = {
        "host": brief.host,
        "ports": brief.ports,
        "trigger": brief.trigger,
        "model": model,
        "status": investigation.status,
        "turns": transcript,
        "evidence": [ref.model_dump(mode="json") for ref in evidence],
        "summary": investigation.summary,
        "findings": [f.model_dump(mode="json") for f in investigation.findings],
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, indent=2, default=str))
    except OSError:
        return ""
    return str(path)


async def investigate_target(
    brief: TargetBrief,
    registry: dict[str, Tool],
    client: ModelClient,
    scope: Scope,
    max_steps: int = DEFAULT_MAX_STEPS,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    transcript_dir: Path | None = None,
) -> TargetInvestigation:
    """Run the per-target LLM observe->hypothesize->probe->conclude loop.

    Tools are resolved through the injected ``registry`` only. Protocol
    violations (invalid JSON, schema violations, unknown tools, ungrounded
    findings) get one retry with a schema reminder; a second violation
    marks the target ``inconclusive``. Budget exhaustion (``max_steps``
    turns or ``max_seconds`` wall clock) concludes with the findings so
    far and status ``budget_exhausted``.
    """
    started = time.monotonic()
    transcript: list[dict[str, Any]] = []
    evidence: list[EvidenceRef] = []
    findings: list[AgentFinding] = []
    summary = ""
    status = "budget_exhausted"
    violations = 0
    reminder_pending = False

    def _record(entry: dict[str, Any]) -> None:
        entry.setdefault("ts", datetime.now(timezone.utc).isoformat())
        transcript.append(entry)

    def _violate(reason: str, turn: int) -> bool:
        """Handle one protocol violation; True means stop inconclusive."""
        nonlocal violations, reminder_pending, status, summary
        violations += 1
        _record({"turn": turn, "kind": "protocol_violation",
                 "error": reason, "evidence_ids": []})
        if violations >= 2:
            status = "inconclusive"
            summary = (
                "model repeatedly violated the response protocol: "
                f"{reason}"
            )
            return True
        reminder_pending = True
        return False

    turn = 0
    done = False
    while not done and turn < max_steps:
        if time.monotonic() - started >= max_seconds:
            break
        turn += 1
        user_prompt = build_user_prompt(brief, registry, transcript)
        if reminder_pending:
            user_prompt = f"{user_prompt}\n\n{SCHEMA_REMINDER}"
            reminder_pending = False
        try:
            raw = await client.complete(SYSTEM_PROMPT, user_prompt)
        except ModelUnavailable as exc:
            _record({"turn": turn, "kind": "error", "error": str(exc),
                     "evidence_ids": []})
            status = "inconclusive"
            summary = f"model unavailable mid-investigation: {exc}"
            done = True
            break

        try:
            parsed = parse_turn(raw)
        except ProtocolViolation as exc:
            if _violate(str(exc), turn):
                break
            continue

        thought = parsed["thought"]
        if "action" in parsed:
            action = parsed["action"]
            tool_name = action["tool"]
            args = action["args"]
            tool = registry.get(tool_name)
            if tool is None:
                if _violate(f"unknown tool: {tool_name!r}", turn):
                    break
                continue
            try:
                result = await tool.run(args, scope)
            except ScopeViolation:
                _record({
                    "turn": turn, "kind": "action", "thought": thought,
                    "action": {"tool": tool_name, "args": args},
                    "evidence_ids": [], "error": "out of scope",
                    "excerpts": ["out of scope"],
                })
                continue
            except Exception as exc:  # noqa: BLE001 - tool failure is a turn
                _record({
                    "turn": turn, "kind": "action", "thought": thought,
                    "action": {"tool": tool_name, "args": args},
                    "evidence_ids": [], "error": str(exc),
                })
                continue
            ref = EvidenceRef(
                id=f"E{len(evidence) + 1}",
                tool=tool_name,
                args=args,
                excerpt=result.excerpt[:600],
                ts=datetime.now(timezone.utc),
            )
            evidence.append(ref)
            _record({
                "turn": turn, "kind": "action", "thought": thought,
                "action": {"tool": tool_name, "args": args},
                "evidence_ids": [ref.id], "ok": result.ok,
                "excerpts": [f"{ref.id}: {ref.excerpt}"],
            })
            continue

        # Final reply: validate + ground + harden before accepting.
        final = parsed["final"]
        try:
            findings = validate_final(
                final, brief, {ref.id for ref in evidence}
            )
        except ProtocolViolation as exc:
            if _violate(str(exc), turn):
                break
            continue
        summary = filter_offensive(str(final.get("summary", "")))[:SUMMARY_LIMIT]
        status = "concluded"
        done = True

    if not done and status == "budget_exhausted":
        summary = (
            f"investigation budget exhausted after {turn} turn(s); "
            "concluding with findings so far"
        )

    investigation = TargetInvestigation(
        host=brief.host,
        ports=brief.ports,
        trigger=brief.trigger,
        status=status,  # type: ignore[arg-type]
        turns=turn,
        summary=summary,
        findings=findings,
    )
    if transcript_dir is not None:
        investigation.transcript_path = _write_transcript(
            Path(transcript_dir), brief, client.name, transcript, evidence,
            investigation,
        )
    return investigation


__all__ = [
    "CLASS_SEVERITY",
    "SCHEMA_REMINDER",
    "SYSTEM_PROMPT",
    "ProtocolViolation",
    "build_user_prompt",
    "filter_offensive",
    "investigate_target",
    "parse_turn",
    "select_targets",
    "strip_code_fences",
    "validate_final",
]
