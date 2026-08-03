"""SARIF 2.1.0 output validates against the vendored OASIS JSON schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

from src.formatters.sarif_formatter import build_sarif, level_for_cvss
from src.generator import AnalysisOutput, ScanInput

SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "sarif-2.1.0.json"


def test_sarif_validates_against_schema(
    scan_data: dict[str, Any], analysis_data: dict[str, Any]
) -> None:
    """The generated SARIF log conforms to the SARIF 2.1.0 schema."""
    scan = ScanInput.model_validate(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    document = build_sarif(scan, analysis)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=document, schema=schema)

    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")
    run = document["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert set(rules) == {v["cve_id"] for v in scan_data["vulnerabilities"]}
    for rule in rules.values():
        assert rule["helpUri"].startswith("https://nvd.nist.gov/vuln/detail/")
    assert len(run["results"]) == len(scan_data["vulnerabilities"])
    for result in run["results"]:
        location = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        host, _, port = location.rpartition(":")
        assert host and port.isdigit()


def test_sarif_level_mapping() -> None:
    """CVSS >= 9 -> error, >= 7 -> warning, otherwise note."""
    assert level_for_cvss(10.0) == "error"
    assert level_for_cvss(9.0) == "error"
    assert level_for_cvss(8.99) == "warning"
    assert level_for_cvss(7.0) == "warning"
    assert level_for_cvss(6.9) == "note"
    assert level_for_cvss(0.0) == "note"


def test_sarif_result_levels_match_cvss(
    scan_data: dict[str, Any], analysis_data: dict[str, Any]
) -> None:
    """Each finding's SARIF level follows the CVSS mapping."""
    scan = ScanInput.model_validate(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    document = build_sarif(scan, analysis)
    by_cve = {v.cve_id: v for v in scan.vulnerabilities}
    for result in document["runs"][0]["results"]:
        vuln = by_cve[result["ruleId"]]
        assert result["level"] == level_for_cvss(vuln.cvss)
