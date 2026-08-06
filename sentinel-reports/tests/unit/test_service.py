"""Service tests: GET /health and POST /report via FastAPI TestClient."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from src.service import app

client = TestClient(app)


def test_health() -> None:
    """GET /health returns ok and the active PDF engine."""
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["pdf_engine"] in {"weasyprint", "fpdf2"}


def test_report_endpoint(scan_data: dict[str, Any], analysis_data: dict[str, Any]) -> None:
    """POST /report generates the requested formats and returns file paths."""
    response = client.post(
        "/report",
        json={"scan": scan_data, "analysis": analysis_data, "formats": ["json", "sarif"]},
    )
    assert response.status_code == 200
    files = response.json()["files"]
    assert set(files) == {"json", "sarif"}
    for path in files.values():
        assert Path(path).is_file()


def test_report_endpoint_rejects_bad_scan(analysis_data: dict[str, Any]) -> None:
    """POST /report with a contract-violating scan returns 422."""
    response = client.post(
        "/report",
        json={"scan": {"target": "192.168.1.0/24"}, "analysis": analysis_data},
    )
    assert response.status_code == 422
