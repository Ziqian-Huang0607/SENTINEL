"""sentinel-reports HTTP service (port 8711).

Exposes the report generator over HTTP; sentinel-analyzer's ``/report``
endpoint forwards report jobs here.
"""

from __future__ import annotations

import os
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ValidationError

from src import __version__
from src.formatters.pdf_formatter import pdf_engine
from src.generator import generate

REPORTS_DIR = os.environ.get("SENTINEL_REPORTS_DIR", "/tmp/sentinel-reports")

app = FastAPI(
    title="sentinel-reports",
    version=__version__,
    description="SENTINEL report generation service (PDF / JSON / SARIF).",
)


class ReportRequest(BaseModel):
    """POST /report payload (mirrors the analyzer /report contract)."""

    scan: dict[str, Any]
    analysis: dict[str, Any]
    formats: list[Literal["pdf", "json", "sarif"]] = Field(
        default_factory=lambda: ["pdf", "json", "sarif"], min_length=1
    )


class ReportResponse(BaseModel):
    """POST /report response: mapping of format to generated file path."""

    files: dict[str, str]


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness probe; reports which PDF engine is active."""
    return {"status": "ok", "version": __version__, "pdf_engine": pdf_engine()}


@app.post("/report", response_model=ReportResponse)
def report(request: ReportRequest) -> ReportResponse:
    """Generate the requested report formats for a scan + analysis pair."""
    try:
        files = generate(request.scan, request.analysis, list(request.formats), REPORTS_DIR)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ReportResponse(files=files)
