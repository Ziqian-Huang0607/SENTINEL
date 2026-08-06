"""Validate the scan.json / analysis.json artifacts of a SENTINEL CLI e2e run.

Checks both files against the full ScanInput / AnalysisOutput contracts
(pydantic models mirrored from SPEC.md in test/contracts.py) and recomputes
the deterministic risk score, asserting equality at 2 decimal places.

Artifact fallback: the CLI `scan` command keeps scan.json / analysis.json in
a temporary directory and only persists the merged ./sentinel-report.json.
When ./scan.json (or ./analysis.json) is absent but ./sentinel-report.json
exists, the document is loaded from that report's "scan" (or "analysis") key.
Explicit --scan/--analysis paths are still honored whenever they exist.

Exit codes: 0 = PASS, 1 = validation failure, 2 = usage/dependency error.

Usage: python test/e2e/validate_output.py [--scan scan.json] [--analysis analysis.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # test/ directory

try:
    from contracts import (
        RISK_TOLERANCE,
        AnalysisOutput,
        ScanInput,
        compute_risk_score,
        round2,
    )
    from pydantic import ValidationError
except ImportError as exc:  # pragma: no cover - environment issue, not a test failure
    print(f"ERROR: cannot import contract dependencies: {exc}")
    print("Hint: run `make build` (creates sentinel-analyzer/.venv with pydantic).")
    sys.exit(2)


REPORT_FALLBACK = Path("sentinel-report.json")


def _load_json(path: Path) -> dict:
    if not path.is_file():
        print(f"FAIL: {path} does not exist — run the CLI e2e scan first:")
        print("  ./sentinel-cli scan --target 127.0.0.1/32 --tier daily --output json --yes")
        sys.exit(1)
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        print(f"FAIL: {path} is not valid JSON: {exc}")
        sys.exit(1)


def _load_artifact(path: Path, report_key: str) -> dict:
    """Load a scan/analysis artifact, falling back to ./sentinel-report.json.

    The CLI `scan` command only persists the merged report, so when the
    standalone artifact is absent the payload is read from the report's
    top-level "scan" / "analysis" key.
    """
    if path.is_file():
        return _load_json(path)
    if REPORT_FALLBACK.is_file():
        doc = _load_json(REPORT_FALLBACK)
        if isinstance(doc, dict) and isinstance(doc.get(report_key), dict):
            print(f"OK: {path} not found; using {REPORT_FALLBACK} key {report_key!r}")
            return doc[report_key]
    print(f"FAIL: {path} does not exist — run the CLI e2e scan first:")
    print("  ./sentinel-cli scan --target 127.0.0.1/32 --tier daily --output json --yes")
    sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan", default="scan.json", help="path to scan.json (default: ./scan.json)")
    parser.add_argument(
        "--analysis", default="analysis.json", help="path to analysis.json (default: ./analysis.json)"
    )
    args = parser.parse_args()

    failures: list[str] = []

    try:
        scan = ScanInput.model_validate(_load_artifact(Path(args.scan), "scan"))
        print(f"OK: {args.scan} satisfies the ScanInput contract "
              f"({len(scan.hosts)} hosts, {len(scan.vulnerabilities)} vulnerabilities)")
    except ValidationError as exc:
        print(f"FAIL: {args.scan} violates the ScanInput contract:\n{exc}")
        return 1

    try:
        analysis = AnalysisOutput.model_validate(_load_artifact(Path(args.analysis), "analysis"))
        print(f"OK: {args.analysis} satisfies the AnalysisOutput contract "
              f"(mode={analysis.analyzer_mode}, chains={len(analysis.attack_chains)})")
    except ValidationError as exc:
        print(f"FAIL: {args.analysis} violates the AnalysisOutput contract:\n{exc}")
        return 1

    # round2 keeps every comparison on the scanner's half-up 2dp grid
    # (a decimal-exact 4.805 must compare as 4.81, not banker's 4.80).
    recomputed = compute_risk_score(scan)
    reported_analysis = round2(analysis.risk_score)
    if reported_analysis != recomputed:
        failures.append(
            f"analysis.risk_score={reported_analysis} != deterministic formula result {recomputed}"
        )
    if abs(round2(scan.risk_score) - recomputed) > RISK_TOLERANCE:
        failures.append(
            f"scan.risk_score={scan.risk_score} deviates from formula result {recomputed} "
            f"by more than {RISK_TOLERANCE}"
        )
    if abs(round2(scan.risk_score) - reported_analysis) > RISK_TOLERANCE:
        failures.append(
            f"scan.risk_score={scan.risk_score} and analysis.risk_score={analysis.risk_score} disagree"
        )

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1

    print(f"PASS: contracts valid; deterministic risk score {recomputed} confirmed in both artifacts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
