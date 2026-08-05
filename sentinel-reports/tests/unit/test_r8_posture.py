"""R8: posture findings (exposures without a CVE) and coverage provenance.

The reports service must surface posture findings in every output format
(HTML/PDF template, fpdf2 fallback, SARIF, JSON passthrough) and state the
CVE signature DB coverage so "0 CVE matches" can never read as "no risk".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
from src.formatters import pdf_formatter
from src.formatters.json_formatter import render_json
from src.formatters.sarif_formatter import build_sarif, level_for_cvss
from src.generator import AnalysisOutput, ScanInput

SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "sarif-2.1.0.json"

R8_EXTRAS: dict[str, Any] = {
    "posture_findings": [
        {
            "id": "POSTURE-UNAUTH-WEB-GATEWAY",
            "host": "192.168.1.1",
            "port": 80,
            "severity": 7.5,
            "title": "Unauthenticated web interface on a probable gateway",
            "evidence": 'GET / -> 200; Server: nginx/1.18.0; Title: "Router Admin"',
        },
        {
            "id": "POSTURE-UNAUTH-IPP",
            "host": "192.168.1.45",
            "port": 631,
            "severity": 6.5,
            "title": "Unauthenticated IPP print service",
            "evidence": "GET / -> 200; Server: CUPS/2.4",
        },
    ],
    "cve_db": {"version": "2026.08.1", "signatures": 30},
}


def _r8_scan(scan_data: dict[str, Any]) -> ScanInput:
    """The shared fixture plus R8 posture fields."""
    return ScanInput.model_validate({**scan_data, **R8_EXTRAS})


def test_scan_input_defaults_empty_for_pre_r8_documents(scan_data: dict[str, Any]) -> None:
    """Pre-R8 scan.json files (no posture/cve_db keys) still validate."""
    scan = ScanInput.model_validate(scan_data)
    assert scan.posture_findings == []
    assert scan.cve_db.version == ""
    assert scan.cve_db.signatures == 0


def test_scan_input_parses_r8_fields(scan_data: dict[str, Any]) -> None:
    scan = _r8_scan(scan_data)
    assert [f.id for f in scan.posture_findings] == [
        "POSTURE-UNAUTH-WEB-GATEWAY",
        "POSTURE-UNAUTH-IPP",
    ]
    assert scan.cve_db.version == "2026.08.1"
    assert scan.cve_db.signatures == 30


def test_html_report_shows_exposures_and_coverage(
    scan_data: dict[str, Any], analysis_data: dict[str, Any]
) -> None:
    scan = _r8_scan(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    html = pdf_formatter.render_html(scan, analysis)
    assert "Exposures (No CVE Match)" in html
    assert "POSTURE-UNAUTH-WEB-GATEWAY" in html
    assert "Detection coverage" in html
    assert "2026.08.1" in html
    assert "30 signatures" in html


def test_html_zero_cve_note_when_only_posture(
    scan_data: dict[str, Any], analysis_data: dict[str, Any]
) -> None:
    """With no CVEs but posture findings, the report must say so explicitly."""
    payload = {**scan_data, **R8_EXTRAS, "vulnerabilities": []}
    scan = ScanInput.model_validate(payload)
    analysis = AnalysisOutput.model_validate(analysis_data)
    html = pdf_formatter.render_html(scan, analysis)
    assert "zero CVE matches is not zero risk" in html
    assert "signature coverage, not proof of safety" in html


def test_fpdf_fallback_renders_posture_findings(
    scan_data: dict[str, Any],
    analysis_data: dict[str, Any],
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """The fpdf2 fallback handles posture findings and still emits a valid PDF."""
    monkeypatch.setattr(pdf_formatter, "_weasyprint", None)
    scan = _r8_scan(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    out_path = str(tmp_path / "fallback_r8.pdf")
    pdf_formatter.render_pdf(scan, analysis, out_path)
    payload = Path(out_path).read_bytes()
    assert payload.startswith(b"%PDF")
    assert len(payload) > 20 * 1024


def test_sarif_includes_posture_rules_and_results(
    scan_data: dict[str, Any], analysis_data: dict[str, Any]
) -> None:
    scan = _r8_scan(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    document = build_sarif(scan, analysis)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=document, schema=schema)

    run = document["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert "POSTURE-UNAUTH-WEB-GATEWAY" in rules
    assert "POSTURE-UNAUTH-IPP" in rules
    # Posture rules have no NVD page; CVE rules keep their helpUri.
    assert "helpUri" not in rules["POSTURE-UNAUTH-WEB-GATEWAY"]
    assert "exposure" in rules["POSTURE-UNAUTH-WEB-GATEWAY"]["properties"]["tags"]

    expected = len(scan_data["vulnerabilities"]) + len(R8_EXTRAS["posture_findings"])
    assert len(run["results"]) == expected
    posture_results = {r["ruleId"]: r["level"] for r in run["results"] if r["ruleId"].startswith("POSTURE-")}
    assert posture_results == {
        "POSTURE-UNAUTH-WEB-GATEWAY": "warning",  # severity 7.5 >= 7.0
        "POSTURE-UNAUTH-IPP": "note",  # severity 6.5 < 7.0
    }
    assert level_for_cvss(7.5) == "warning"


def test_json_passthrough_carries_posture_and_coverage(
    scan_data: dict[str, Any], analysis_data: dict[str, Any], tmp_path: Path
) -> None:
    scan = _r8_scan(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    out_path = str(tmp_path / "report.json")
    render_json(scan, analysis, out_path)
    document = json.loads(Path(out_path).read_text(encoding="utf-8"))
    assert document["scan"]["posture_findings"][0]["id"] == "POSTURE-UNAUTH-WEB-GATEWAY"
    assert document["scan"]["cve_db"] == {"version": "2026.08.1", "signatures": 30}
