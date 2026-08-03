"""JSON report formatter: merged scan + analysis document (pretty JSON)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from src import __version__
from src.generator import AnalysisOutput, ScanInput


def build_document(scan: ScanInput, analysis: AnalysisOutput) -> dict[str, Any]:
    """Build the merged report document (scan + analysis + report metadata)."""
    return {
        "report": {
            "generator": "sentinel-reports",
            "generator_version": __version__,
            "generated_at": datetime.now(UTC).isoformat(),
            "scan_id": scan.scan_id,
        },
        "scan": scan.model_dump(mode="json"),
        "analysis": analysis.model_dump(mode="json"),
    }


def render_json(scan: ScanInput, analysis: AnalysisOutput, out_path: str) -> str:
    """Write the merged scan+analysis document as pretty-printed JSON.

    Args:
        scan: Validated scanner output.
        analysis: Validated analyzer output.
        out_path: Destination file path.

    Returns:
        The path written to.
    """
    document = build_document(scan, analysis)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return out_path
