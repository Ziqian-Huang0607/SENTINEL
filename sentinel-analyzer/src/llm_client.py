"""Async Ollama client for LLM-driven SENTINEL analysis.

Calls the Ollama ``/api/generate`` endpoint with the SPEC-pinned model
(``llama3.1:8b``) and generation options, parses the strict-JSON response
and validates it against the ``AnalysisOutput`` contract. On any transport
error, timeout or invalid payload the caller receives ``LLMError`` so the
service can fall back to the rule-based engine.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import asdict
from pathlib import Path

import httpx
from pydantic import ValidationError
from src.attack_chain import CandidateChain, ground_chains
from src.models import (
    OLLAMA_MODEL,
    AnalysisOutput,
    AnalyzerMode,
    ScanInput,
)

logger = logging.getLogger("sentinel-analyzer")

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = OLLAMA_MODEL
# 8B inference on laptop hardware can take several minutes for a rich scan;
# 120s was too aggressive and caused needless mid-request fallback.
DEFAULT_TIMEOUT_SECONDS = 600.0
PROBE_TIMEOUT_SECONDS = 3.0

SYSTEM_PROMPT = (
    "You are a senior threat analyst. ONLY use provided data. "
    "Map to MITRE ATT&CK. No hallucination. No exploit code."
)

# Generation options pinned by SPEC / ollama-config.yaml.
LLM_SEED = 0
GENERATE_OPTIONS: dict[str, int | float] = {
    "num_ctx": 8192,
    "num_gpu": 1,
    "num_thread": 4,
    "temperature": 0.1,
    "top_p": 0.9,
    "top_k": 40,
    "num_predict": 2048,
    "seed": LLM_SEED,
}

# Raw LLM responses are archived for auditability/replay; the location is
# overridable for tests and deployments via SENTINEL_RAW_ARCHIVE_DIR.
DEFAULT_RAW_ARCHIVE_DIR = "raw_llm_archive"

# Output rules appended to the prompt (and the schema reminder) so chain
# construction stays grounded and remediation stays defensive. Introduced
# after an 8B model produced four identical filler chains (uniform T1568,
# 50%/70%) and an "exploit the CUPS service" remediation item on a
# finding-light scan.
ANALYSIS_RULES = (
    "RULES:\n"
    "1. Every attack_chain path entry MUST be an observed host or host:port "
    "from the SCAN JSON above. Invented infrastructure invalidates the "
    "chain.\n"
    "2. mitre_technique MUST match the actual weakness of each chain "
    "(e.g. T1190 for exposed/unauthenticated services, T1040 for cleartext "
    "protocols, T1078 for default credentials). Do NOT reuse one technique "
    "across all chains.\n"
    "3. Remediation items MUST be defensive actions (configure, restrict, "
    "patch, disable, rotate). NEVER instruct exploitation, attacking, or "
    "further compromise.\n"
    "4. When the scan has no vulnerabilities and no posture_findings, "
    "return an empty attack_chains list — do not invent chains."
)

SCHEMA_REMINDER = (
    "SCHEMA REMINDER: your previous reply was not valid. Respond with ONE "
    "strict JSON object and nothing else (no prose, no markdown code "
    "fences). It MUST match the AnalysisOutput schema exactly: "
    '{"attack_chains": [{"path": ["host:port"], "description": "str", '
    '"mitre_technique": "str", "confidence": 0.0-1.0, "impact": 0.0-1.0, '
    '"priority": 1}], "remediation": {"daily": ["str"], "authority": '
    '["str"], "hacker": ["str"], "military": ["str"]}, "risk_score": '
    '0.0-10.0, "observations": ["str"], "analyzer_mode": "llm"}. '
    "If you include any reasoning or explanation keys (e.g. \"reasoning\"), "
    "they MUST appear FIRST in the JSON object, before all schema fields "
    "above. "
) + ANALYSIS_RULES


class LLMError(RuntimeError):
    """Raised when the Ollama call or response validation fails."""


class OllamaClient:
    """Minimal async client for the Ollama generate API."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str = DEFAULT_MODEL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        """Create a client; ``OLLAMA_URL`` overrides the default base URL."""
        self.base_url = (
            base_url or os.environ.get("OLLAMA_URL", DEFAULT_BASE_URL)
        ).rstrip("/")
        self.model = model
        self.timeout = timeout

    async def _generate(self, prompt: str) -> str:
        """POST one generate request and return the raw response text."""
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "options": GENERATE_OPTIONS,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate", json=payload
                )
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise LLMError(f"ollama /api/generate request failed: {exc}") from exc
        text = data.get("response")
        if not isinstance(text, str) or not text.strip():
            raise LLMError("ollama returned an empty 'response' field")
        return text

    async def analyze(
        self, scan: ScanInput, candidates: list[CandidateChain]
    ) -> AnalysisOutput:
        """Run LLM analysis with one schema-reminder retry.

        Raises ``LLMError`` when both attempts fail so the caller can fall
        back to the deterministic rule-based engine.
        """
        base_prompt = build_user_prompt(scan, candidates)
        last_error: LLMError | None = None
        for attempt in range(2):
            prompt = base_prompt if attempt == 0 else (
                f"{base_prompt}\n\n{SCHEMA_REMINDER}"
            )
            try:
                raw = await self._generate(prompt)
            except LLMError as exc:
                # No raw response was produced (transport error/timeout or
                # an empty reply); nothing to archive.
                last_error = exc
                continue
            try:
                analysis = parse_analysis(raw)
            except LLMError as exc:
                self._archive_raw(scan, raw, ok=False, error=str(exc))
                last_error = exc
                continue
            self._archive_raw(scan, raw, ok=True, error=None)
            return finalize_analysis(analysis, scan)
        raise last_error if last_error else LLMError("unknown LLM failure")

    def _archive_raw(
        self,
        scan: ScanInput,
        raw_text: str,
        ok: bool,
        error: str | None,
    ) -> None:
        """Append the raw LLM response to the archive dir (best effort).

        Every raw response — success or parse failure — is written as
        ``{scan_id}_{unix_ts}.raw.json`` for auditability and replay.
        Archiving must NEVER fail analysis, so all errors are swallowed.
        """
        try:
            archive_dir = Path(
                os.environ.get("SENTINEL_RAW_ARCHIVE_DIR", DEFAULT_RAW_ARCHIVE_DIR)
            )
            archive_dir.mkdir(parents=True, exist_ok=True)
            ts = int(time.time())
            scan_id = scan.scan_id or "unknown"
            record = {
                "scan_id": scan_id,
                "model": self.model,
                "options": GENERATE_OPTIONS,
                "raw_text": raw_text,
                "ok": ok,
                "error": error,
                "ts": ts,
            }
            (archive_dir / f"{scan_id}_{ts}.raw.json").write_text(
                json.dumps(record, indent=2)
            )
        except Exception as exc:  # noqa: BLE001 - archive is best-effort
            logger.warning("raw LLM archive write failed: %s", exc)


def pin_deterministic_risk(analysis: AnalysisOutput, scan: ScanInput) -> AnalysisOutput:
    """Override the model's risk_score with the deterministic formula.

    Risk scoring is a deterministic contract of the platform (see SPEC): the
    LLM contributes chains/remediation narrative, never the score. The pinned
    value is max(recomputed from the scan's vulnerabilities, scan.risk_score),
    identical to the fallback engine's policy.
    """
    from src.fallback_analyzer import recompute_risk_score

    pinned = round(max(recompute_risk_score(scan), scan.risk_score), 2)
    return analysis.model_copy(update={"risk_score": pinned})


# Offensive phrasing that must never survive into a remediation plan. The
# analyzer advises the defender; an item telling the operator to "exploit"
# something (observed from an 8B model on a finding-light scan) is dropped.
_OFFENSIVE_REMEDIATION_PATTERNS = (
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


def enforce_defensive_remediation(analysis: AnalysisOutput) -> tuple[AnalysisOutput, int]:
    """Drop remediation items phrased as offensive actions.

    Returns ``(analysis, dropped_count)``. Defensive guidance only — this
    filter is deterministic and applies in LLM mode (fallback remediation
    comes from the curated library and is defensive by construction).
    """
    remediation = analysis.remediation
    dropped = 0
    cleaned: dict[str, list[str]] = {}
    for tier in ("daily", "authority", "hacker", "military"):
        items = getattr(remediation, tier)
        kept_items: list[str] = []
        for item in items:
            lowered = item.lower()
            if any(pattern in lowered for pattern in _OFFENSIVE_REMEDIATION_PATTERNS):
                dropped += 1
            else:
                kept_items.append(item)
        cleaned[tier] = kept_items
    updated = analysis.model_copy(
        update={
            "remediation": remediation.model_copy(update=cleaned),
        }
    )
    return updated, dropped


def finalize_analysis(analysis: AnalysisOutput, scan: ScanInput) -> AnalysisOutput:
    """Post-LLM hardening pipeline, in order:

    1. ground attack chains against observed scan data (drop invented
       hosts/ports, renumber priorities);
    2. drop offensively phrased remediation items;
    3. pin the deterministic risk score;
    4. pass posture findings through for the report layer.

    Every intervention is recorded as an observation so the report shows
    exactly what the model got wrong (auditable LLM behavior, R3).
    """
    kept_chains, dropped_chains = ground_chains(analysis.attack_chains, scan)
    analysis = analysis.model_copy(update={"attack_chains": kept_chains})
    analysis, dropped_offensive = enforce_defensive_remediation(analysis)
    analysis = pin_deterministic_risk(analysis, scan)
    notes: list[str] = []
    if dropped_chains:
        notes.append(
            f"Dropped {dropped_chains} LLM attack chain(s) referencing "
            "hosts/ports absent from the scan (grounding validator)."
        )
    if dropped_offensive:
        notes.append(
            f"Dropped {dropped_offensive} remediation item(s) phrased as "
            "offensive actions; remediation is defender-only."
        )
    if notes:
        analysis = analysis.model_copy(
            update={"observations": [*analysis.observations, *notes]}
        )
    return analysis.model_copy(
        update={"posture_findings": list(scan.posture_findings)}
    )


def build_user_prompt(scan: ScanInput, candidates: list[CandidateChain]) -> str:
    """Build the user prompt embedding scan JSON and candidate chains."""
    candidate_dicts = [asdict(candidate) for candidate in candidates]
    return (
        "Analyze the following vulnerability scan and produce a threat "
        "analysis. Use ONLY the data below.\n\n"
        "SCAN JSON:\n"
        f"{scan.model_dump_json()}\n\n"
        "CANDIDATE ATTACK CHAINS (deterministic rule-based context; verify "
        "against the scan data before using):\n"
        f"{json.dumps(candidate_dicts, indent=2)}\n\n"
        "Respond with STRICT JSON ONLY (no prose, no code fences) matching "
        "this AnalysisOutput schema:\n"
        '{"attack_chains": [{"path": ["host:port"], "description": "str", '
        '"mitre_technique": "str", "confidence": 0.0-1.0, "impact": '
        '0.0-1.0, "priority": 1}], "remediation": {"daily": ["str"], '
        '"authority": ["str"], "hacker": ["str"], "military": ["str"]}, '
        '"risk_score": 0.0-10.0, "observations": ["str"], "analyzer_mode": '
        '"llm"}.\n'
        "If you include any reasoning or explanation keys (e.g. "
        '"reasoning"), they MUST appear FIRST in the JSON object, before '
        "all schema fields above.\n"
        f"{ANALYSIS_RULES}"
    )


def strip_code_fences(text: str) -> str:
    """Remove a surrounding ``` / ```json markdown fence, if present."""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    return stripped


def parse_analysis(text: str) -> AnalysisOutput:
    """Parse and validate an LLM reply as ``AnalysisOutput``.

    Code fences are stripped before ``json.loads``; the result is validated
    with pydantic and the mode is pinned to ``llm``. Raises ``LLMError`` on
    any malformed content.
    """
    cleaned = strip_code_fences(text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise LLMError(f"LLM response is not valid JSON: {exc}") from exc
    try:
        analysis = AnalysisOutput.model_validate(data)
    except ValidationError as exc:
        raise LLMError(f"LLM response failed schema validation: {exc}") from exc
    return analysis.model_copy(update={"analyzer_mode": AnalyzerMode.llm})


async def probe_ollama(
    base_url: str | None = None, timeout: float = PROBE_TIMEOUT_SECONDS
) -> bool:
    """Probe ``/api/tags`` (3s default timeout) to detect Ollama."""
    url = (base_url or os.environ.get("OLLAMA_URL", DEFAULT_BASE_URL)).rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(f"{url}/api/tags")
            return response.status_code == 200
    except httpx.HTTPError:
        return False
