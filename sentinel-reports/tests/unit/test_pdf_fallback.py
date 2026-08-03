"""The fpdf2 fallback renderer works behind the same interface."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from src.formatters import pdf_formatter
from src.generator import AnalysisOutput, ScanInput


def test_fpdf2_fallback_renderer(
    scan_data: dict[str, Any],
    analysis_data: dict[str, Any],
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    """Forcing WeasyPrint 'unavailable' still yields a valid PDF via fpdf2."""
    monkeypatch.setattr(pdf_formatter, "_weasyprint", None)
    scan = ScanInput.model_validate(scan_data)
    analysis = AnalysisOutput.model_validate(analysis_data)
    out_path = str(tmp_path / "fallback.pdf")
    result = pdf_formatter.render_pdf(scan, analysis, out_path)
    assert result == out_path
    payload = Path(out_path).read_bytes()
    assert payload.startswith(b"%PDF")
    assert len(payload) > 20 * 1024
