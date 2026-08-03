<p align="center">
  <img src="assets/logo.png" alt="SENTINEL logo" width="220">
</p>

<h1 align="center">SENTINEL</h1>

<p align="center">
  <strong>Production-ready, cross-platform vulnerability assessment platform —
  scan, score, and remediate networks from an 8GB M1 MacBook Air.</strong>
</p>

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/scanner-Rust%201.75+-orange?logo=rust">
  <img alt="Go" src="https://img.shields.io/badge/cli-Go%201.22-00ADD8?logo=go">
  <img alt="Python" src="https://img.shields.io/badge/services-Python%203.12+-3776AB?logo=python">
  <img alt="Qt" src="https://img.shields.io/badge/gui-PySide6-41CD52?logo=qt">
  <img alt="LLM" src="https://img.shields.io/badge/llm-llama3.1%3A8b%20(Ollama)-black">
  <img alt="platform" src="https://img.shields.io/badge/platform-macOS%20%C2%B7%20Linux-lightgrey">
</p>

---

SENTINEL discovers hosts, fingerprints services, matches CVEs with CVSS + EPSS
intelligence, scores risk with a fully deterministic formula, maps attack
chains to MITRE ATT&CK via a local LLM (llama3.1:8b through Ollama) or a
rule-based fallback engine, and renders branded PDF / JSON / SARIF reports
against four operator-selectable security tiers.

## Architecture

```
                          ┌────────────────────────────────────────────┐
                          │                operator                    │
                          │   sentinel-cli (Go)      sentinel-ui (Qt)  │
                          └───────────┬───────────────────┬────────────┘
                                      │                   │ REST :8710
                                      ▼                   ▼
┌──────────────────┐   scan.json   ┌─────────────────────────────────┐
│ sentinel-scanner │──────────────►│      sentinel-analyzer :8710    │
│ (Rust, tokio)    │               │  ┌───────────────────────────┐  │
│ discovery ·      │               │  │ LLM mode    ──► Ollama    │  │
│ port scan ·      │               │  │             llama3.1:8b   │  │
│ fingerprint ·    │               │  │             (:11434)      │  │
│ CVE match/score  │               │  │ fallback  ──► rule-based  │  │
└──────────────────┘               │  │             engine        │  │
                                   │  └───────────────────────────┘  │
                                   │ analysis.json (chains, fixes,   │
                                   │  deterministic risk score)      │
                                   └───────────────┬─────────────────┘
                                                   │ {"scan","analysis",formats}
                                                   ▼
                                   ┌─────────────────────────────────┐
                                   │      sentinel-reports :8711     │
                                   │  WeasyPrint + Jinja2 ──► PDF    │
                                   │  merged JSON · SARIF 2.1.0      │
                                   └─────────────────────────────────┘
```

| Component | Tech | Role |
|-----------|------|------|
| `sentinel-scanner` | Rust (tokio, pnet, rusqlite) | Host discovery, TCP connect scan, service fingerprinting, embedded CVE cache, deterministic scoring |
| `sentinel-analyzer` | Python 3.12, FastAPI :8710 | Attack-chain construction, tiered remediation, Ollama LLM client with automatic rule-based fallback |
| `sentinel-reports` | Python, FastAPI :8711 | Branded PDF, merged JSON, and SARIF 2.1.0 report generation |
| `sentinel-cli` | Go 1.22 (cobra) | Operator entry point with scope CONFIRM gate and audit logging |
| `sentinel-ui` | PySide6 | Dark ops-center desktop GUI driving the same analyzer API |

## Installation

```bash
git clone https://github.com/Ziqian-Huang0607/sentinel.git && cd sentinel

brew install ollama
ollama pull llama3.1:8b

make build   # cargo release build, go build, python venvs
make test    # unit + integration + e2e suites
make up      # docker compose up -d (analyzer :8710, reports :8711)
```

Local (non-Docker) mode: `scripts/services.sh start` always restarts the
uvicorn processes, sweeping any stale listener on :8710/:8711 — so after a
code upgrade a plain `make up` or `make test` can never keep serving an old
build. Use `make down` to stop them.

To run the LLM sidecar in Docker instead of the Homebrew Ollama:

```bash
docker compose --profile llm up -d
docker compose --profile llm exec ollama ollama pull llama3.1:8b
```

**Production deployments:** pin the Ollama backend version (Homebrew:
`brew pin ollama`; Docker: the compose file pins `ollama/ollama` by tag —
never `latest`). Score calibration and the measured LLM performance in
`METHODOLOGY.md` are only reproducible against a pinned backend
(Ollama ≥ 0.19 recommended for the Apple-silicon MLX backend). The analyzer
also pins generation `seed`, `temperature`, and context size, and archives
raw model outputs per scan under `raw_llm_archive/` so determinism claims
stay auditable.

## Running a scan

Every scan passes a scope gate: the CLI prints target + tier and requires the
operator to type `CONFIRM` (`--yes` bypasses it for tests/CI only), and every
run is appended to `~/.sentinel/audit.log`.

```bash
./bin/sentinel-cli scan --target 192.168.1.0/24 --tier hacker --output pdf
```

(`make build` places the operator binary at `bin/sentinel-cli` — the
`sentinel-cli/` directory at the repo root is the Go source tree.)

Other operator flows:

```bash
./bin/sentinel-cli analyze --input scan.json                 # re-analyze an existing scan
./bin/sentinel-cli report --scan scan.json --analysis analysis.json --format sarif
```

### Scanning via Docker Compose

The analyzer and reports services run in containers; the scanner itself runs
best on the host (raw-socket access, real network view). On Linux a
containerized convenience runner is also provided:

```bash
# Linux convenience runner (builds from the mounted checkout on first use)
docker compose --profile cli run --rm scanner \
  --target 192.168.1.0/24 --tier hacker --output /workspace/scan.json \
  --analyzer-url http://localhost:8710

# Recommended everywhere: host-built binary against the containerized analyzer
./sentinel-scanner/target/release/sentinel-scanner \
  --target 192.168.1.0/24 --tier hacker --analyzer-url http://localhost:8710
```

### Fallback (no-LLM) mode

Without Ollama the analyzer automatically switches to its deterministic,
rule-based engine — identical output schema, fully offline:

```bash
docker compose stop ollama
./bin/sentinel-cli scan --target 192.168.1.0/24 --tier hacker --output pdf --no-llm
```

### Desktop GUI

```bash
make ui    # launches the PySide6 ops-center (cd sentinel-ui && python -m sentinel_ui)
```

## Security tiers

| Tier | Threat model | Compliance baseline | Patch SLA (critical) | Risk threshold |
|------|--------------|---------------------|----------------------|----------------|
| daily | worms, script kiddies | CIS Controls v8 L1 | 30 days | < 4.0 |
| authority | organized cybercrime | NIST 800-53 Moderate, ISO 27001 | 7 days | < 2.5 |
| hacker | APT, red teams | NIST 800-53 High, MITRE ATT&CK | 24 hours | < 1.5 |
| military | nation-state | NSA/CSS, CNSSI 1253 (+ physical/emissions-security controls) | immediate / airgap | < 0.5 |

Risk thresholds (4.0 / 2.5 / 1.5 / 0.5) are justified internal engineering
constants — see `METHODOLOGY.md` Ch.8 for the evidence audit. Compliance
references track CISA Binding Operational Directive 26-04 (2026-06-10),
which revoked BOD 22-01.

## Deterministic risk scoring

```
RISK_SCORE = (CVSS * 0.25) + (EPSS * 10 * 0.35)
           + (EXPOSURE * 10 * 0.25) + (CRITICALITY * 10 * 0.15)
```

The scan-level score is the maximum per-vulnerability score (owning host's
exposure/criticality applied), rounded to 2 decimals — identical in the
scanner, analyzer, and reports, and pinned by the test suites.

**KEV escalation:** findings whose CVE is listed on the CISA Known Exploited
Vulnerabilities catalog (`"kev": true` in scan.json) floor at 9.0, mirroring
BOD 26-04 tiered remediation triggers. EPSS values use EPSS v4 semantics
(30-day exploitation window); the weighting (EPSS-dominant) follows the
evidence audit in `METHODOLOGY.md` Ch.8 R1–R2.

| EXPOSURE | weight | | CRITICALITY | weight |
|----------|--------|-|-------------|--------|
| internet | 1.0 | | dc (domain controller) | 1.0 |
| dmz | 0.7 | | app | 0.7 |
| internal | 0.4 | | workstation | 0.4 |
| mgmt | 0.1 | | iot | 0.1 |
| airgap | 0.0 | | | |

## Memory budget — 8GB M1 MacBook Air

Apple silicon runs the full stack, including llama3.1:8b, inside 8 GB of
unified memory. `make test-llm-memory` enforces the LLM rows on real hardware.

| Consumer | Budget (MB) | Notes |
|----------|------------:|-------|
| macOS + WindowServer | 2048 | baseline system footprint |
| Ollama server + llama3.1:8b (Q4) | 5120 | gated by `test/hardware/test_memory.py --max-mb 5120` |
| sentinel-reports (WeasyPrint) | 384 | peak during PDF rendering |
| sentinel-analyzer (FastAPI) | 256 | :8710 |
| sentinel-scanner (Rust) | 128 | 200 concurrent connects, top-1000 ports |
| Headroom | 256 | keeps the system off swap |
| **Total** | **8192** | |

Inference latency on this machine is gated by
`test/hardware/test_inference.py --max-seconds 60`.

## Testing

| Command | What runs |
|---------|-----------|
| `make test` | unit + integration + e2e |
| `make test-unit` | cargo test, go test, pytest for analyzer/reports + contract tests |
| `make test-integration` | compose analyzer+reports, scanner→analyzer pipeline, API contracts |
| `make test-e2e` | CLI scan of 127.0.0.1/32 + output/report validators |
| `make test-llm-memory` | hardware gates (SKIP cleanly when Ollama is absent) |
| `make test-build` | release + cross-compile (darwin/arm64) + docker builds |
| `make lint` / `make fmt` | clippy, ruff, go vet, gofmt |

CI (`.github/workflows/sentinel-scan.yml`) runs the rust, go, and python jobs
in parallel, then the integration and e2e jobs against docker compose services.

## Repository layout

```
sentinel-scanner/    Rust scanner (cargo)
sentinel-analyzer/   FastAPI analyzer :8710
sentinel-reports/    FastAPI report service :8711
sentinel-cli/        Go operator CLI
sentinel-ui/         PySide6 desktop GUI
test/                unit / integration / e2e / hardware suites
docker-compose.yml   service orchestration (profiles: llm, cli)
Makefile             build, test, lint, run entry points
```

## Author

**Ziqian Huang**

- GitHub: [@Ziqian-Huang0607](https://github.com/Ziqian-Huang0607)
- Email: [mlfusion@outlook.com](mailto:mlfusion@outlook.com)

Issues and pull requests are welcome. For security-sensitive reports, please
email instead of opening a public issue.

## Legal disclaimer

SENTINEL is for authorized security testing only. Scanning networks without explicit written permission is illegal under the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent laws worldwide. The tool requires operator confirmation before any scan and logs all activity for audit purposes.
