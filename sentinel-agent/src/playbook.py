"""Deterministic playbook fallback investigation (agent-spec.md section 8).

Zero-LLM investigation with the same tools as the agent loop, in a fixed
order per trigger class: unauth web (http_get -> default_panel_check ->
tls_hello on 443-like ports -> cve_lookup when a product/version is seen),
unknown port (grab_banner -> http_get -> tls_hello with a banner-regex
service table), IPP (ipp_enumerate -> http_get), and datastore/smb
(grab_banner / smb_probe). Findings cite transcript evidence ids exactly
like LLM mode and severities come from CLASS_SEVERITY. Fully
deterministic: identical inputs produce identical findings.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from src.models import (
    CLASS_SEVERITY,
    AgentFinding,
    EvidenceRef,
    TargetBrief,
    TargetInvestigation,
)
from src.scope import Scope, ScopeViolation
from src.tools.base import Tool, ToolResult

# Ports treated as TLS-carrying for the unauth-web flow.
TLS_PORTS = frozenset({443, 8443})

# Banner regex table for the unknown-port flow. Banners reaching us have
# been sanitized (control bytes -> "."), so the SMB entry also matches the
# sanitized forms of the \xffSMB / \xfeSMB protocol headers.
BANNER_SERVICES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"SSH-"), "ssh"),
    (re.compile(r"HTTP/"), "http"),
    (re.compile(r"\+OK"), "pop3"),
    (re.compile(r"-ERR|-NOAUTH"), "redis"),
    (re.compile(r"mysql|MariaDB|\x0a\d+\.\d+\.\d+", re.IGNORECASE), "mysql"),
    (re.compile(r"[\xff\xfe.]SMB"), "smb"),
    (re.compile(r"^220[ -]"), "ftp/smtp"),
]


def identify_banner(banner: str) -> str | None:
    """Return the service name the banner-regex table identifies, if any."""
    for pattern, service in BANNER_SERVICES:
        if pattern.search(banner):
            return service
    return None


class _ProbeLog:
    """Per-investigation evidence accumulator (E1, E2, ...)."""

    def __init__(self) -> None:
        self.evidence: list[EvidenceRef] = []

    def add(self, tool: str, args: dict[str, Any], result: ToolResult) -> EvidenceRef:
        """Record one tool result as transcript evidence."""
        ref = EvidenceRef(
            id=f"E{len(self.evidence) + 1}",
            tool=tool,
            args=args,
            excerpt=result.excerpt[:600],
            ts=datetime.now(timezone.utc),
        )
        self.evidence.append(ref)
        return ref


async def _run(
    registry: dict[str, Tool],
    scope: Scope,
    log: _ProbeLog,
    tool_name: str,
    args: dict[str, Any],
) -> ToolResult | None:
    """Run one tool defensively; failures become evidence-free None."""
    tool = registry.get(tool_name)
    if tool is None:
        return None
    try:
        result = await tool.run(args, scope)
    except ScopeViolation:
        log.add(tool_name, args, ToolResult.failure("out of scope"))
        return None
    except Exception as exc:  # noqa: BLE001 - playbook must not crash
        log.add(tool_name, args, ToolResult.failure(str(exc)))
        return None
    log.add(tool_name, args, result)
    return result


def _parse_product_version(server: str) -> tuple[str, str] | None:
    """Split a ``Product/Version`` server header into (product, version)."""
    match = re.match(r"^\s*([A-Za-z][\w.-]*)/([\w.-]+)", server or "")
    if not match:
        return None
    return match.group(1), match.group(2)


async def _web_flow(
    brief: TargetBrief,
    registry: dict[str, Tool],
    scope: Scope,
    log: _ProbeLog,
    findings: list[AgentFinding],
    notes: list[str],
) -> None:
    """Unauth web: http_get -> panel check -> tls_hello -> cve_lookup."""
    for port in brief.ports:
        http_args = {"host": brief.host, "port": port, "path": "/"}
        http_result = await _run(registry, scope, log, "http_get", http_args)
        server = ""
        title = ""
        http_ref_id = ""
        if http_result is not None:
            http_ref_id = log.evidence[-1].id
            if http_result.ok:
                server = str(http_result.data.get("server") or "")
                title = str(http_result.data.get("title") or "")
        panel_args = {
            "host": brief.host, "port": port, "server": server, "title": title,
        }
        panel_result = await _run(
            registry, scope, log, "default_panel_check", panel_args
        )
        if panel_result is not None and panel_result.ok:
            panel_ref_id = log.evidence[-1].id
            matched = panel_result.data.get("matched_panel")
            if matched:
                evidence_ids = [
                    eid for eid in (http_ref_id, panel_ref_id) if eid
                ]
                findings.append(AgentFinding(
                    id=f"AGENT-DEFAULT-PANEL-{len(findings) + 1}",
                    finding_class="DEFAULT-PANEL",
                    host=brief.host,
                    port=port,
                    severity=CLASS_SEVERITY["DEFAULT-PANEL"],
                    title=f"Known admin panel exposed: {matched}",
                    detail=(
                        f"Unauthenticated web interface on {brief.host}:{port} "
                        f"matches the '{matched}' panel signature "
                        f"(server={server or 'unknown'}, "
                        f"title={title or 'unknown'})."
                    ),
                    evidence=evidence_ids,
                    confidence=0.9,
                ))
        if port in TLS_PORTS:
            await _run(
                registry, scope, log, "tls_hello",
                {"host": brief.host, "port": port},
            )
        product_version = _parse_product_version(server)
        if product_version is None:
            version_hint = brief.hints.get("versions", {}).get(str(port))
            service_hint = brief.hints.get("services", {}).get(str(port))
            if version_hint and service_hint:
                product_version = (service_hint, version_hint)
        if product_version is not None:
            product, version = product_version
            cve_result = await _run(
                registry, scope, log, "cve_lookup",
                {"service": product, "version": version},
            )
            if cve_result is not None and cve_result.ok:
                matches = cve_result.data.get("matches") or []
                if matches:
                    cve_ids = ", ".join(str(m.get("cve", "")) for m in matches)
                    notes.append(
                        f"{brief.host}:{port} {product} {version} matches "
                        f"known CVE(s): {cve_ids}"
                    )


async def _unknown_flow(
    brief: TargetBrief,
    registry: dict[str, Tool],
    scope: Scope,
    log: _ProbeLog,
    findings: list[AgentFinding],
) -> None:
    """Unknown port: grab_banner -> http_get -> tls_hello; SERVICE-IDENT."""
    for port in brief.ports:
        service: str | None = None
        evidence_ids: list[str] = []
        banner_result = await _run(
            registry, scope, log, "grab_banner", {"host": brief.host, "port": port}
        )
        if banner_result is not None and banner_result.ok:
            banner_ref_id = log.evidence[-1].id
            banner = str(banner_result.data.get("banner") or "")
            identified = identify_banner(banner)
            if identified:
                service = identified
                evidence_ids.append(banner_ref_id)
        http_result = await _run(
            registry, scope, log, "http_get",
            {"host": brief.host, "port": port, "path": "/"},
        )
        if (
            http_result is not None
            and http_result.ok
            and service is None
            and http_result.data.get("status")
        ):
            service = "http"
            evidence_ids.append(log.evidence[-1].id)
        tls_result = await _run(
            registry, scope, log, "tls_hello", {"host": brief.host, "port": port}
        )
        if (
            tls_result is not None
            and tls_result.ok
            and tls_result.data.get("tls")
            and service is not None
            and service in ("http",)
        ):
            service = "https"
        if service is not None and evidence_ids:
            findings.append(AgentFinding(
                id=f"AGENT-SERVICE-IDENT-{len(findings) + 1}",
                finding_class="SERVICE-IDENT",
                host=brief.host,
                port=port,
                severity=CLASS_SEVERITY["SERVICE-IDENT"],
                title=f"Unknown service on port {port} identified as {service}",
                detail=(
                    f"Banner/HTTP probing of {brief.host}:{port} identifies "
                    f"the previously unknown service as '{service}'."
                ),
                evidence=evidence_ids,
                confidence=0.7,
            ))


async def _ipp_flow(
    brief: TargetBrief,
    registry: dict[str, Tool],
    scope: Scope,
    log: _ProbeLog,
    findings: list[AgentFinding],
) -> None:
    """IPP: ipp_enumerate -> http_get; SENSITIVE-SERVICE when reachable."""
    for port in brief.ports:
        ipp_result = await _run(
            registry, scope, log, "ipp_enumerate",
            {"host": brief.host, "port": port},
        )
        ipp_ref_id = log.evidence[-1].id if ipp_result is not None else ""
        await _run(
            registry, scope, log, "http_get",
            {"host": brief.host, "port": port, "path": "/"},
        )
        if ipp_result is not None and ipp_result.ok:
            printers = ipp_result.data.get("printers") or []
            server_version = str(ipp_result.data.get("server_version") or "")
            findings.append(AgentFinding(
                id=f"AGENT-SENSITIVE-SERVICE-{len(findings) + 1}",
                finding_class="SENSITIVE-SERVICE",
                host=brief.host,
                port=port,
                severity=CLASS_SEVERITY["SENSITIVE-SERVICE"],
                title=f"IPP printing service reachable on port {port}",
                detail=(
                    f"IPP enumeration of {brief.host}:{port} succeeded "
                    f"(server_version={server_version or 'unknown'}, "
                    f"printers={len(printers)})."
                ),
                evidence=[ipp_ref_id] if ipp_ref_id else [],
                confidence=0.85,
            ))


async def _datastore_flow(
    brief: TargetBrief,
    registry: dict[str, Tool],
    scope: Scope,
    log: _ProbeLog,
    findings: list[AgentFinding],
) -> None:
    """Datastore/SMB: grab_banner / smb_probe; confirm sensitive exposure."""
    for port in brief.ports:
        if port in (139, 445):
            smb_result = await _run(
                registry, scope, log, "smb_probe",
                {"host": brief.host, "port": port},
            )
            if smb_result is not None and smb_result.ok and smb_result.data.get("smb"):
                signing = smb_result.data.get("signing_required")
                if signing is False:
                    findings.append(AgentFinding(
                        id=f"AGENT-MISCONFIG-{len(findings) + 1}",
                        finding_class="MISCONFIG",
                        host=brief.host,
                        port=port,
                        severity=CLASS_SEVERITY["MISCONFIG"],
                        title=f"SMB signing not required on {brief.host}:{port}",
                        detail=(
                            "SMB2 NEGOTIATE reports signing_required=false; "
                            "the service accepts unsigned sessions."
                        ),
                        evidence=[log.evidence[-1].id],
                        confidence=0.8,
                    ))
            continue
        banner_result = await _run(
            registry, scope, log, "grab_banner", {"host": brief.host, "port": port}
        )
        if banner_result is not None and banner_result.ok:
            banner = str(banner_result.data.get("banner") or "")
            service = identify_banner(banner)
            if service in ("redis", "mysql"):
                findings.append(AgentFinding(
                    id=f"AGENT-SENSITIVE-SERVICE-{len(findings) + 1}",
                    finding_class="SENSITIVE-SERVICE",
                    host=brief.host,
                    port=port,
                    severity=CLASS_SEVERITY["SENSITIVE-SERVICE"],
                    title=f"Datastore '{service}' reachable on port {port}",
                    detail=(
                        f"Banner grab on {brief.host}:{port} confirms a "
                        f"'{service}' datastore answering without "
                        "authentication challenges."
                    ),
                    evidence=[log.evidence[-1].id],
                    confidence=0.8,
                ))


def _flow_for(brief: TargetBrief) -> str:
    """Map a brief to its playbook flow name."""
    if brief.trigger == "unknown_service":
        return "unknown"
    posture_ids = " ".join(str(pid) for pid in brief.hints.get("posture_ids", []))
    if "IPP" in posture_ids:
        return "ipp"
    if "DATASTORE" in posture_ids or "SMB" in posture_ids:
        return "datastore"
    if brief.trigger == "cve":
        return "cve"
    return "web"


async def investigate_target_playbook(
    brief: TargetBrief,
    registry: dict[str, Tool],
    scope: Scope,
) -> TargetInvestigation:
    """Run the deterministic zero-LLM investigation for one target.

    Fixed tool sequences per trigger class (agent-spec.md section 8).
    Findings cite evidence ids exactly like LLM mode, severities come from
    ``CLASS_SEVERITY``, and status is always ``concluded``. Identical
    inputs produce identical findings (no timestamps inside findings).
    """
    log = _ProbeLog()
    findings: list[AgentFinding] = []
    notes: list[str] = []
    flow = _flow_for(brief)
    if flow == "web":
        await _web_flow(brief, registry, scope, log, findings, notes)
    elif flow == "unknown":
        await _unknown_flow(brief, registry, scope, log, findings)
    elif flow == "ipp":
        await _ipp_flow(brief, registry, scope, log, findings)
    elif flow == "datastore":
        await _datastore_flow(brief, registry, scope, log, findings)
    else:  # cve: re-confirm hinted service/version pairs against the seed
        for port_text, version in brief.hints.get("versions", {}).items():
            service = brief.hints.get("services", {}).get(port_text)
            if service and version:
                await _run(
                    registry, scope, log, "cve_lookup",
                    {"service": service, "version": version},
                )
    summary = (
        f"playbook investigation ({flow}) of {brief.host}:"
        f" {len(log.evidence)} probe(s), {len(findings)} finding(s)."
    )
    if notes:
        summary = f"{summary} " + " ".join(notes)
    return TargetInvestigation(
        host=brief.host,
        ports=brief.ports,
        trigger=brief.trigger,
        status="concluded",
        turns=len(log.evidence),
        summary=summary,
        findings=findings,
        transcript_path="",
    )


__all__ = [
    "BANNER_SERVICES",
    "TLS_PORTS",
    "identify_banner",
    "investigate_target_playbook",
]
