#!/usr/bin/env python3
"""Validate the sentinel-report.* artifacts of a SENTINEL CLI e2e run.

Always validates ./sentinel-report.json (merged scan+analysis document).
Optionally validates the PDF and SARIF renderings:

  * --pdf   : file must exist, start with %PDF, and be larger than 20 KB
  * --sarif : file must exist and satisfy the SARIF 2.1.0 core structure

Exit codes: 0 = PASS, 1 = validation failure, 2 = usage/dependency error.

Usage: python test/e2e/validate_report.py [--report sentinel-report.json] [--pdf] [--sarif]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # test/ directory

try:
    from pydantic import ValidationError

    from contracts import AnalysisOutput, ScanInput
except ImportError as exc:  # pragma: no cover - environment issue, not a test failure
    print(f"ERROR: cannot import contract dependencies: {exc}")
    print("Hint: run `make build` (creates sentinel-analyzer/.venv with pydantic).")
    sys.exit(2)

PDF_MIN_BYTES = 20 * 1024
SARIF_SCHEMA_MARKER = "sarif-schema-2.1.0"


def _check_report_json(path: Path) -> list[str]:
    if not path.is_file():
        return [f"{path} does not exist — run the CLI e2e scan first"]
    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [f"{path} is not valid JSON: {exc}"]

    errors: list[str] = []
    keys = set(doc)
    if {"scan", "analysis"} <= keys:  # nested form
        try:
            ScanInput.model_validate(doc["scan"])
        except ValidationError as exc:
            errors.append(f"report.scan violates ScanInput contract:\n{exc}")
        try:
            AnalysisOutput.model_validate(doc["analysis"])
        except ValidationError as exc:
            errors.append(f"report.analysis violates AnalysisOutput contract:\n{exc}")
    elif {"scan_id", "attack_chains"} <= keys:  # merged single-document form
        try:
            ScanInput.model_validate({k: v for k, v in doc.items() if k != "attack_chains"})
        except ValidationError as exc:
            errors.append(f"merged report violates ScanInput contract:\n{exc}")
    else:
        errors.append(f"{path} contains neither scan+analysis keys nor merged scan fields: {sorted(keys)}")
    return errors


def _check_pdf(path: Path) -> list[str]:
    if not path.is_file():
        return [f"pdf requested but {path} does not exist"]
    blob = path.read_bytes()
    errors = []
    if not blob.startswith(b"%PDF"):
        errors.append(f"{path} does not start with %PDF header")
    if len(blob) <= PDF_MIN_BYTES:
        errors.append(f"{path} is only {len(blob)} bytes (expected > {PDF_MIN_BYTES})")
    return errors


def _check_sarif(path: Path) -> list[str]:
    if not path.is_file():
        return [f"sarif requested but {path} does not exist"]
    try:
        sarif = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [f"{path} is not valid JSON: {exc}"]
    errors = []
    if sarif.get("version") != "2.1.0":
        errors.append(f"SARIF version is {sarif.get('version')!r}, expected '2.1.0'")
    if SARIF_SCHEMA_MARKER not in sarif.get("$schema", ""):
        errors.append(f"SARIF $schema does not reference {SARIF_SCHEMA_MARKER}")
    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append("SARIF has no runs")
        return errors
    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})
    if not driver.get("name"):
        errors.append("SARIF runs[0].tool.driver.name missing")
    if "rules" in driver and not isinstance(driver["rules"], list):
        errors.append("SARIF tool.driver.rules is not a list")
    if not isinstance(run.get("results", []), list):
        errors.append("SARIF runs[0].results is not a list")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        default="sentinel-report.json",
        help="path to the JSON report (default: ./sentinel-report.json)",
    )
    parser.add_argument("--pdf", nargs="?", const="sentinel-report.pdf", default=None,
                        help="also validate the PDF report (optional path, default ./sentinel-report.pdf)")
    parser.add_argument("--sarif", nargs="?", const="sentinel-report.sarif", default=None,
                        help="also validate the SARIF report (optional path, default ./sentinel-report.sarif)")
    args = parser.parse_args()

    errors = _check_report_json(Path(args.report))
    if not errors:
        print(f"OK: {args.report} parses and contains scan+analysis")
    if args.pdf is not None:
        pdf_errors = _check_pdf(Path(args.pdf))
        errors += pdf_errors
        if not pdf_errors:
            print(f"OK: {args.pdf} has %PDF header and exceeds 20KB")
    if args.sarif is not None:
        sarif_errors = _check_sarif(Path(args.sarif))
        errors += sarif_errors
        if not sarif_errors:
            print(f"OK: {args.sarif} satisfies SARIF 2.1.0 core structure")

    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: report artifacts valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
