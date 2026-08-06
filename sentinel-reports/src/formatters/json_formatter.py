"""JSON report formatter: merged scan + analysis (+ agent) document."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from src import __version__
from src.generator import AgentReport, AnalysisOutput, ScanInput


def build_document(
    scan: ScanInput, analysis: AnalysisOutput, agent: AgentReport | None = None
) -> dict[str, Any]:
    """Build the merged report document (scan + analysis + report metadata)."""
    document: dict[str, Any] = {
        "report": {
            "generator": "sentinel-reports",
            "generator_version": __version__,
            "generated_at": datetime.now(UTC).isoformat(),
            "scan_id": scan.scan_id,
        },
        "scan": scan.model_dump(mode="json"),
        "analysis": analysis.model_dump(mode="json"),
    }
    if agent is not None:
        document["agent"] = agent.model_dump(mode="json")
    return document


def render_json(
    scan: ScanInput,
    analysis: AnalysisOutput,
    out_path: str,
    agent: AgentReport | None = None,
) -> str:
    """Write the merged scan+analysis (+agent) document as pretty-printed JSON.

    Args:
        scan: Validated scanner output.
        analysis: Validated analyzer output.
        out_path: Destination file path.
        agent: Optional validated agent report.

    Returns:
        The path written to.
    """
    document = build_document(scan, analysis, agent=agent)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return out_path
