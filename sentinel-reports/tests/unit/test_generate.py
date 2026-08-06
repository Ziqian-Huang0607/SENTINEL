"""Tests for generate(): multi-format output, PDF integrity, JSON round-trip."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from src.generator import generate

MIN_PDF_BYTES = 20 * 1024


def test_generate_all_formats(
    scan_data: dict[str, Any], analysis_data: dict[str, Any], tmp_path: Path
) -> None:
    """generate() produces all three formats from the rich fixture."""
    files = generate(scan_data, analysis_data, ["pdf", "json", "sarif"], str(tmp_path))
    assert set(files) == {"pdf", "json", "sarif"}
    for fmt, path in files.items():
        target = Path(path)
        assert target.is_file(), f"missing {fmt} output"
        assert target.suffix == f".{fmt}"
        assert target.stat().st_size > 0
        assert target.parent == tmp_path


def test_generate_pdf_valid_and_non_trivial(
    scan_data: dict[str, Any], analysis_data: dict[str, Any], tmp_path: Path
) -> None:
    """PDF output starts with %PDF and is larger than 20KB."""
    files = generate(scan_data, analysis_data, ["pdf"], str(tmp_path))
    payload = Path(files["pdf"]).read_bytes()
    assert payload.startswith(b"%PDF")
    assert len(payload) > MIN_PDF_BYTES


def test_generate_json_roundtrip(
    scan_data: dict[str, Any], analysis_data: dict[str, Any], tmp_path: Path
) -> None:
    """Merged JSON document round-trips and carries both contract payloads."""
    files = generate(scan_data, analysis_data, ["json"], str(tmp_path))
    with open(files["json"], encoding="utf-8") as fh:
        document = json.load(fh)
    assert "scan" in document
    assert "analysis" in document
    assert document["scan"]["scan_id"] == scan_data["scan_id"]
    assert document["scan"]["target"] == scan_data["target"]
    assert len(document["scan"]["hosts"]) == len(scan_data["hosts"])
    assert len(document["scan"]["vulnerabilities"]) == len(scan_data["vulnerabilities"])
    assert document["analysis"]["analyzer_mode"] == "fallback"
    assert len(document["analysis"]["attack_chains"]) == 2
    for tier in ("daily", "authority", "hacker", "military"):
        assert document["analysis"]["remediation"][tier]
    assert document["report"]["generator"] == "sentinel-reports"


def test_generate_rejects_unknown_format(
    scan_data: dict[str, Any], analysis_data: dict[str, Any], tmp_path: Path
) -> None:
    """Unsupported formats raise ValueError."""
    with pytest.raises(ValueError, match="Unsupported report format"):
        generate(scan_data, analysis_data, ["docx"], str(tmp_path))


def test_generate_validates_contracts(analysis_data: dict[str, Any], tmp_path: Path) -> None:
    """Contract violations in the scan payload raise a pydantic error."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        generate({"target": "192.168.1.0/24"}, analysis_data, ["json"], str(tmp_path))
