"""Semantic unknown-service identification sub-task (LLM mode).

For targets whose trigger is an unknown/unidentified service, run the
three benign identification probes (grab_banner, http_get, tls_hello),
then make ONE model call asking it to name the service from the probe
excerpts. The model answers strict JSON; a non-null service yields a
grounded SERVICE-IDENT finding (severity from CLASS_SEVERITY, evidence
ids from the probes). Model garbage or "no service" yields None — an
unidentified service is a valid outcome, never a hallucinated one.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from src.loop import strip_code_fences
from src.model_client import ModelClient, ModelUnavailable
from src.models import CLASS_SEVERITY, AgentFinding, EvidenceRef, TargetBrief
from src.scope import Scope, ScopeViolation
from src.tools.base import Tool

SYSTEM_PROMPT = (
    "You are SENTINEL-agent's service identification assistant. Given "
    "probe excerpts from an internal-network port, identify the service. "
    "Use ONLY the provided excerpts; if nothing identifies the service, "
    "answer null. Respond with ONE strict JSON object and nothing else: "
    '{"service": str|null, "version_guess": str|null, '
    '"confidence": 0.0-1.0}.'
)

_PROBE_SEQUENCE = (
    ("grab_banner", lambda host, port: {"host": host, "port": port}),
    ("http_get", lambda host, port: {"host": host, "port": port, "path": "/"}),
    ("tls_hello", lambda host, port: {"host": host, "port": port}),
)


def _build_user_prompt(brief: TargetBrief, evidence: list[EvidenceRef]) -> str:
    """Assemble the identification prompt from probe excerpts."""
    lines = "\n".join(
        f"{ref.id} [{ref.tool} port={ref.args.get('port')}]: {ref.excerpt}"
        for ref in evidence
    )
    return (
        f"TARGET: {brief.host} ports {brief.ports} "
        f"(trigger: {brief.trigger}).\n"
        f"PROBE EXCERPTS:\n{lines}\n\n"
        "Identify the service. Strict JSON only: "
        '{"service": str|null, "version_guess": str|null, '
        '"confidence": 0.0-1.0}.'
    )


def _parse_answer(raw: str) -> dict[str, Any] | None:
    """Parse the model's identification answer; None on any garbage."""
    try:
        data = json.loads(strip_code_fences(raw))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    service = data.get("service")
    if service is not None and not isinstance(service, str):
        return None
    version_guess = data.get("version_guess")
    if version_guess is not None and not isinstance(version_guess, str):
        return None
    return data


async def identify_unknown_service(
    brief: TargetBrief,
    registry: dict[str, Tool],
    client: ModelClient,
    scope: Scope,
) -> AgentFinding | None:
    """Identify the unknown service on a target via probes + one LLM call.

    Runs grab_banner, http_get, and tls_hello per port (via the injected
    registry), concatenates the excerpts, and asks the model once for
    ``{"service", "version_guess", "confidence"}``. Returns a grounded
    SERVICE-IDENT finding citing the probe evidence ids when the model
    names a service; returns None on model unavailability, garbage, or a
    null service. The finding always cites at least one real probe
    evidence id (grounding).
    """
    evidence: list[EvidenceRef] = []
    for port in brief.ports:
        for tool_name, build_args in _PROBE_SEQUENCE:
            tool = registry.get(tool_name)
            if tool is None:
                continue
            args = build_args(brief.host, port)
            try:
                result = await tool.run(args, scope)
            except ScopeViolation:
                excerpt = "error: out of scope"
            except Exception as exc:  # noqa: BLE001 - probe failure is data
                excerpt = f"error: {exc}"
            else:
                excerpt = result.excerpt
            evidence.append(EvidenceRef(
                id=f"E{len(evidence) + 1}",
                tool=tool_name,
                args=args,
                excerpt=excerpt[:600],
                ts=datetime.now(timezone.utc),
            ))
    if not evidence:
        return None
    try:
        raw = await client.complete(
            SYSTEM_PROMPT, _build_user_prompt(brief, evidence)
        )
    except ModelUnavailable:
        return None
    answer = _parse_answer(raw)
    if answer is None:
        return None
    service = answer.get("service")
    if not service:
        return None
    try:
        confidence = float(answer.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = min(max(confidence, 0.0), 1.0)
    version_guess = answer.get("version_guess") or ""
    port = brief.ports[0]
    return AgentFinding(
        id="AGENT-SERVICE-IDENT-1",
        finding_class="SERVICE-IDENT",
        host=brief.host,
        port=port,
        severity=CLASS_SEVERITY["SERVICE-IDENT"],
        title=f"Unknown service on port {port} identified as {service}",
        detail=(
            f"Model-assisted identification of {brief.host}:{port}: "
            f"service='{service}'"
            + (f", version_guess='{version_guess}'" if version_guess else "")
            + "."
        ),
        evidence=[ref.id for ref in evidence],
        confidence=confidence,
    )


__all__ = ["identify_unknown_service"]
