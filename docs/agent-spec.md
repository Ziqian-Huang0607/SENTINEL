# SENTINEL Agent — Interface Specification (sacred)

Single source of truth for the agentic layer. If an implementation and this
file disagree, this file wins. Mirrors the discipline of SPEC.md and
test/contracts.py.

## 0. Position in the pipeline

```
Rust scanner (sweep) -> scan.json
      |
      v
sentinel-agent (Python package, this spec)
      |  for each interesting target: observe -> hypothesize -> probe -> conclude
      v
agent_report.json  --> memory.db (drift) --> analyzer/report (existing, Stage 5)
```

Decisions (2026-08-04): agentic probe loop; **benign probes only** (no
credential attempts, no exploit payloads); local Ollama via a `ModelClient`
interface (API brain pluggable later); deterministic playbook fallback when no
LLM; R8 honesty machinery (grounding, defensive-only, coverage) applies to all
agent output.

## 1. Package layout (mirrors sentinel-analyzer conventions)

```
sentinel-agent/
  requirements.txt            # httpx, pydantic (runtime); pytest, pytest-asyncio, respx (test)
  src/
    __init__.py               # __version__
    models.py                 # pydantic contracts (section 4)
    scope.py                  # Scope guard (section 5)
    model_client.py           # ModelClient interface + OllamaClient + PlaybookClient (section 6)
    tools/
      __init__.py             # TOOL_REGISTRY: name -> Tool
      base.py                 # Tool dataclass + ToolResult compaction
      http_get.py  grab_banner.py  tls_hello.py  ipp_enumerate.py
      mdns_browse.py  smb_probe.py  dns_reverse.py  cve_lookup.py
      default_panel_check.py
    loop.py                   # agent loop (section 7)
    playbook.py               # deterministic fallback investigation (section 8)
    service_id.py             # semantic unknown-service identification sub-task
    memory.py                 # sqlite network memory + drift (section 9)
    report.py                 # agent_report.json assembly
    __main__.py               # CLI entry: cd sentinel-agent && python -m src
  tests/
    unit/  integration/
  data/
    cve_seed.json             # mirror of scanner cve_cache seed (+ SEED_VERSION)
    known_panels.json         # router/admin panel signatures (no credentials)
```

## 2. Tool contracts (all async, all benign)

Every tool is a `Tool` (name, JSON-schema `args_schema`, async `run(args, scope)`
-> `ToolResult`). `ToolResult = {ok: bool, data: dict, excerpt: str}` where
`excerpt` is a compacted, sanitized, <=600-char summary (what the LLM sees);
raw bytes never enter the transcript beyond the excerpt.

| Tool | Args | Returns in `data` | Notes |
|---|---|---|---|
| `http_get` | host, port, path="/", tls=false | status, server, title, headers (allowlisted: server, www-authenticate, location, content-type, set-cookie bool), redirect_location, body_excerpt (<=2KB) | one GET per call |
| `grab_banner` | host, port, payload="\r\n", timeout=3.0 | banner (<=1KB, sanitized printable) | raw TCP |
| `tls_hello` | host, port | tls: bool, cert_subject, cert_issuer, cert_not_after, alpn | stdlib ssl, CERT_NONE |
| `ipp_enumerate` | host, port=631 | server_version, printers: [{name, uri, state}] | single Get-Printer-Attributes POST |
| `mdns_browse` | (none) | services: [{name, type, host, port, addresses}] | subnet-wide, one-shot, 3s listen |
| `smb_probe` | host, port=445 | smb: bool, dialect, signing_required, os_hint | SMB2 NEGOTIATE only, no auth |
| `dns_reverse` | host | hostnames: [str] | PTR lookup |
| `cve_lookup` | service, version | matches: [{cve, cvss, epss, kev, summary}] | reads data/cve_seed.json |
| `default_panel_check` | host, port, server="", title="" | matched_panel: str\|null, vendor_hint: str\|null, evidence | matches data/known_panels.json; NO requests, pure match on already-fetched strings |

Timeouts: every network tool <=5s hard cap. Retries: none inside tools (the
agent decides). Concurrency: tools run one at a time inside a target loop.

## 3. Loop protocol (sacred wire format)

Each turn is ONE LLM completion returning STRICT JSON, either:

```json
{"thought": "<=400 chars", "action": {"tool": "<name>", "args": {}}}
```
or, to conclude the target:
```json
{"thought": "...", "final": {"summary": "<=600 chars",
  "findings": [AgentFinding], "confidence": 0.0}}
```

- System prompt carries: benign-tools-only rule; observed-evidence-only rule
  (every finding MUST cite evidence_ids from this transcript); defensive-only
  framing (no exploitation language — same R8 filter applies on output);
  empty-findings-is-a-valid-result rule.
- User prompt: target brief (host, port(s), scan hints, existing
  posture/CVE findings for the target) + tool menu (name + one-line
  description + args schema) + transcript tail (last 6 turns, excerpts only).
- Invalid JSON / schema violation -> one retry with a schema reminder ->
  target marked `inconclusive` (transcript still recorded).
- Budgets: `max_steps` (default 12), `max_seconds` (default 180) per target.
  Budget exhaustion -> conclude with findings so far + `budget_exhausted: true`.
- The transcript is append-only: `{turn, ts, thought, action|final,
  evidence_ids}`. Raw `ToolResult.data` stored separately; transcript keeps
  `excerpt` + `evidence_id` (E1, E2, ...).

## 4. Findings & report models (pydantic)

```python
class EvidenceRef(BaseModel):
    id: str            # "E1"
    tool: str
    args: dict
    excerpt: str       # <=600 chars
    ts: datetime

class AgentFinding(BaseModel):
    id: str            # "AGENT-<CLASS>-<n>" per target
    finding_class: Literal[
        "SERVICE-IDENT",            # unknown port identified (informational)
        "DEFAULT-PANEL",            # known router/admin panel matched
        "SENSITIVE-SERVICE",        # sensitive service confirmed reachable
        "MISCONFIG",                # other configuration weakness
        "DRIFT",                    # change vs memory (Stage 4)
    ]
    host: str
    port: int = Field(ge=1, le=65535)
    severity: float = Field(ge=0.0, le=10.0)   # from CLASS_SEVERITY, NOT LLM-chosen
    title: str
    detail: str = ""
    evidence: list[str]            # evidence ids; MUST be non-empty except DRIFT
    confidence: float = Field(ge=0.0, le=1.0)

CLASS_SEVERITY = {
    "SERVICE-IDENT": 2.0, "DEFAULT-PANEL": 7.0, "SENSITIVE-SERVICE": 5.5,
    "MISCONFIG": 5.0, "DRIFT": 0.0,   # DRIFT scored via underlying finding
}
```

Agent findings enter the deterministic risk formula exactly like posture
findings (severity as CVSS term, EPSS = 0, no KEV floor, host
exposure/criticality applied). Validation: a finding citing an evidence id
absent from the transcript is rejected (grounding, same as R8).

```python
class TargetInvestigation(BaseModel):
    host: str
    ports: list[int]
    trigger: str                   # why the agent picked this target
    status: Literal["concluded", "inconclusive", "budget_exhausted", "skipped"]
    turns: int
    summary: str = ""
    findings: list[AgentFinding]
    transcript_path: str           # relative path to full transcript JSON

class DriftEvent(BaseModel):
    kind: Literal["NEW_HOST", "GONE_HOST", "NEW_PORT", "CLOSED_PORT",
                  "VERSION_CHANGE", "AUTH_CHANGE"]
    host: str
    port: int | None = None
    before: str = ""
    after: str = ""
    ts: datetime

class AgentReport(BaseModel):      # agent_report.json
    agent_version: str
    scan_id: str
    target: str
    tier: str
    started_at: datetime
    finished_at: datetime
    model: str                     # "ollama/llama3.1:8b" | "playbook"
    investigations: list[TargetInvestigation]
    findings: list[AgentFinding]
    drift: list[DriftEvent]
    risk_score: float              # max over scan+agent findings, same formula
    observations: list[str]
```

## 5. Scope guard (sacred safety rule)

`Scope` wraps the set of in-scope IPs (from scan.json hosts, i.e. what the
operator CONFIRM-gated). Every tool executor receives `scope` and MUST raise
`ScopeViolation` for any host not in it — the agent can never wander outside
the confirmed range, even if the LLM asks. `mdns_browse` is subnet-listen only
(sends no host-directed traffic) and is always allowed. Loopback and RFC1918
only, same as scanner scope rules.

## 6. ModelClient interface

```python
class ModelClient(Protocol):
    name: str
    async def complete(self, system: str, user: str) -> str: ...
```

- `OllamaClient`: POST {ollama_url}/api/generate, model llama3.1:8b,
  options {seed: 42, temperature: 0.1, top_p: 0.9, top_k: 40,
  num_ctx: 8192, num_predict: 1024}; 120s timeout; name "ollama/llama3.1:8b".
- `PlaybookClient`: no LLM — signals the loop to run the deterministic
  playbook instead (section 8); name "playbook".
- Selection: probe Ollama /api/tags (3s); absent -> playbook + observation
  note. `SENTINEL_AGENT_MODEL=playbook` forces playbook.

## 7. Agent loop (`loop.py`)

`investigate_target(target_brief, tools, client, scope, budgets) ->
TargetInvestigation`. Per-target isolation (fresh context per target — 8B
models drown in long transcripts). Target selection is deterministic, NOT
LLM-chosen: interesting = any host with (a) an unauthenticated posture finding,
(b) an unknown/unidentified service, (c) gateway-class exposure, (d) a CVE
finding. Order: gateway first, then unauth, then unknowns, then CVE hosts.
All LLM output passes through the R8 offensive-phrasing filter before it
enters the report.

## 8. Playbook fallback (`playbook.py`)

Zero-LLM deterministic investigation with the same tools, fixed order per
trigger class:
- unauth web target: http_get("/") -> default_panel_check -> tls_hello (if
  443-like) -> cve_lookup(product, version) -> conclude.
- unknown port: grab_banner -> http_get -> tls_hello -> conclude with
  SERVICE-IDENT if any probe identifies the service (banner regex table).
- IPP: ipp_enumerate -> http_get -> conclude.
- datastore/smb: grab_banner / smb_probe -> conclude.
Playbook findings cite evidence the same way; `model` field = "playbook";
observations note the degraded mode (same philosophy as analyzer fallback).

## 9. Memory & drift (`memory.py`)

sqlite at `~/.sentinel/memory.db` (override: SENTINEL_MEMORY_DB):

```sql
CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, ts TEXT, target TEXT,
  tier TEXT, risk_score REAL);
CREATE TABLE IF NOT EXISTS hosts (target TEXT, ip TEXT, hostname TEXT,
  first_seen TEXT, last_seen TEXT, PRIMARY KEY (target, ip));
CREATE TABLE IF NOT EXISTS services (target TEXT, ip TEXT, port INTEGER,
  service TEXT, version TEXT, auth_state TEXT, first_seen TEXT, last_seen TEXT,
  PRIMARY KEY (target, ip, port));
CREATE TABLE IF NOT EXISTS observations (id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT, ip TEXT, port INTEGER, kind TEXT, detail TEXT, ts TEXT);
```

`record_scan(db, scan, agent_report)` upserts hosts/services, appends
observations. `compute_drift(db, target)` diffs the latest state against the
previous scan's: `NEW_HOST`, `GONE_HOST`, `NEW_PORT`, `CLOSED_PORT`,
`VERSION_CHANGE`, `AUTH_CHANGE` (each a DriftEvent {kind, host, port|None,
before, after, ts}). AUTH_CHANGE toward authenticated is good news and says so.

## 10. CLI & gates

`cd sentinel-agent && python -m src --target <cidr> --tier <tier>
[--scanner <path>] [--ollama-url <url>] [--max-steps N] [--max-seconds S]
[--out agent_report.json] [--transcripts-dir agent_transcripts]
[--yes] [--scan-file <scan.json>] [--report] [--analyzer-url <url>]
[--report-formats json,pdf]`:
1. Prints target+tier, requires typing exactly `CONFIRM` (--yes skips,
   tests/CI only), appends to `~/.sentinel/audit.log` (same format as CLI).
2. Runs the scanner binary (default: sentinel-scanner/target/release/...) to
   produce scan.json (temp file). With --scan-file, reuses the given scan.json
   instead — the GUI hand-off path; --scanner is not consulted.
3. Selects targets per section 7, investigates each, writes memory + drift.
4. Writes agent_report.json and prints a 10-line terminal summary.
5. With --report: POSTs scan to the analyzer /analyze, then
   {scan, analysis, agent, formats} to /report (default
   http://localhost:8710) and prints the generated file paths. A hand-off
   failure is non-fatal — agent_report.json is always written.

## 11. Tests (mandatory per module)

- tools: fake asyncio listeners (http server, banner echo, fake SMB
  negotiate bytes); scope guard refusal test (out-of-scope -> ScopeViolation).
- loop: respx-mocked Ollama returning scripted turns; assert real tools
  executed (hit the fake listener), transcript integrity, grounding rejects
  findings citing missing evidence, budget enforcement, retry-then-inconclusive.
- playbook: determinism (two runs -> identical findings), no network beyond
  fakes.
- memory: CRUD + full drift matrix incl. AUTH_CHANGE both directions.
- integration: end-to-end on loopback (fake unauth web + fake unknown
  service) in playbook mode; agent_report.json validates against section 4.
- cve_seed.json sync test: SEED_VERSION and entry count match the scanner's
  embedded seed constants.
