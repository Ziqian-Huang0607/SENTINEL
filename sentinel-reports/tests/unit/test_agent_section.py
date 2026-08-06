"""Agent Investigation section: the optional agent_report.json third input.

When an agent document is supplied, every output format must surface it:
HTML/PDF section with evidence-cited findings and drift, SARIF rules/results,
JSON passthrough. Without it, reports render exactly as before.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
from src.formatters import pdf_formatter
from src.formatters.json_formatter import render_json
from src.formatters.sarif_formatter import build_sarif
from src.generator import AgentReport, AnalysisOutput, ScanInput

SCHEMA_PATH = Path(__file__).resolve().parent / "schema" / "sarif-2.1.0.json"

AGENT_DOC: dict[str, Any] = {
    "agent_version": "0.1.0",
    "scan_id": "7f3a2b1c-9d4e-4f5a-8b6c-1e2d3c4b5a69",
    "target": "192.168.1.0/24",
    "tier": "hacker",
    "started_at": "2024-06-12T09:17:00+00:00",
    "finished_at": "2024-06-12T09:19:30+00:00",
    "model": "ollama/llama3.1:8b",
    "investigations": [
        {
            "host": "192.168.1.1",
            "ports": [80],
            "trigger": "gateway",
            "status": "concluded",
            "turns": 4,
            "summary": "Router admin panel matches the TP-Link signature.",
            "transcript_path": "agent_transcripts/192.168.1.1_80.json",
        }
    ],
    "findings": [
        {
            "id": "AGENT-DEFAULT-PANEL-1",
            "finding_class": "DEFAULT-PANEL",
            "host": "192.168.1.1",
            "port": 80,
            "severity": 7.0,
            "title": "Admin panel matches TP-Link default signature",
            "detail": "Title and server header match the TP-Link panel family.",
            "evidence": ["E1", "E3"],
            "confidence": 0.82,
        }
    ],
    "drift": [
        {
            "kind": "NEW_PORT",
            "host": "192.168.1.45",
            "port": 9100,
            "before": "",
            "after": "open",
            "ts": "2024-06-12T09:19:00+00:00",
        }
    ],
    "risk_score": 5.75,
    "observations": [],
}


def test_agent_doc_validates() -> None:
    agent = AgentReport.model_validate(AGENT_DOC)
    assert agent.findings[0].id == "AGENT-DEFAULT-PANEL-1"
    assert agent.drift[0].kind == "NEW_PORT"


def test_html_agent_section_renders(
    scan_data: dict[str, Any], analysis_data: dict[str, Any]
) -> None:
    scan = ScanInput.model_validate(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    agent = AgentReport.model_validate(AGENT_DOC)
    html = pdf_formatter.render_html(scan, analysis, agent=agent)
    assert "Agent Investigation" in html
    assert "AGENT-DEFAULT-PANEL-1" in html
    assert "TP-Link default signature" in html
    assert "NEW_PORT" in html
    assert "E1, E3" in html
    assert "ollama/llama3.1:8b" in html


def test_html_without_agent_has_no_section(
    scan_data: dict[str, Any], analysis_data: dict[str, Any]
) -> None:
    scan = ScanInput.model_validate(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    html = pdf_formatter.render_html(scan, analysis)
    assert "Agent Investigation" not in html


def test_fpdf_fallback_renders_agent_section(
    scan_data: dict[str, Any],
    analysis_data: dict[str, Any],
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(pdf_formatter, "_weasyprint", None)
    scan = ScanInput.model_validate(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    agent = AgentReport.model_validate(AGENT_DOC)
    out_path = str(tmp_path / "agent_fallback.pdf")
    pdf_formatter.render_pdf(scan, analysis, out_path, agent=agent)
    payload = Path(out_path).read_bytes()
    assert payload.startswith(b"%PDF")
    assert len(payload) > 20 * 1024


def test_sarif_includes_agent_rules(
    scan_data: dict[str, Any], analysis_data: dict[str, Any]
) -> None:
    scan = ScanInput.model_validate(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    agent = AgentReport.model_validate(AGENT_DOC)
    document = build_sarif(scan, analysis, agent=agent)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.validate(instance=document, schema=schema)
    run = document["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert "AGENT-DEFAULT-PANEL-1" in rules
    assert "agent" in rules["AGENT-DEFAULT-PANEL-1"]["properties"]["tags"]
    agent_results = [r for r in run["results"] if r["ruleId"].startswith("AGENT-")]
    assert len(agent_results) == 1
    assert agent_results[0]["level"] == "warning"  # severity 7.0 >= 7.0
    assert "E1, E3" in agent_results[0]["message"]["text"]


def test_json_carries_agent_document(
    scan_data: dict[str, Any], analysis_data: dict[str, Any], tmp_path: Path
) -> None:
    scan = ScanInput.model_validate(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    agent = AgentReport.model_validate(AGENT_DOC)
    out_path = str(tmp_path / "report.json")
    render_json(scan, analysis, out_path, agent=agent)
    document = json.loads(Path(out_path).read_text(encoding="utf-8"))
    assert document["agent"]["findings"][0]["id"] == "AGENT-DEFAULT-PANEL-1"
    assert document["agent"]["model"] == "ollama/llama3.1:8b"

    out_no_agent = str(tmp_path / "report_no_agent.json")
    render_json(scan, analysis, out_no_agent)
    document = json.loads(Path(out_no_agent).read_text(encoding="utf-8"))
    assert "agent" not in document
