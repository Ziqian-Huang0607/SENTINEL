"""CLI -> analyzer/reports hand-off (--report) contract tests.

The analyzer owns Ollama analysis; the agent only forwards scan + agent doc.
Both HTTP calls are mocked with respx — no services are started.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from src.__main__ import hand_off_to_reports

SCAN = {"scan_id": "s1", "target": "127.0.0.1/32", "hosts": []}
AGENT = {"agent_version": "0.1.0", "scan_id": "s1", "findings": [], "drift": []}


@pytest.mark.asyncio
@respx.mock
async def test_handoff_posts_scan_then_full_body():
    seen: list[dict] = []
    respx.post("http://analyzer.test/analyze").mock(
        return_value=httpx.Response(200, json={"risk_score": 4.73, "chains": []})
    )

    def capture(request):
        seen.append(__import__("json").loads(request.content))
        return httpx.Response(200, json={"outputs": {"pdf": "/out/r.pdf"}})

    respx.post("http://analyzer.test/report").mock(side_effect=capture)

    out = await hand_off_to_reports(
        "http://analyzer.test/", SCAN, AGENT, ["pdf", "json"]
    )

    assert out == {"outputs": {"pdf": "/out/r.pdf"}}
    body = seen[0]
    assert body["scan"] == SCAN
    assert body["agent"] == AGENT
    assert body["analysis"]["risk_score"] == 4.73
    assert body["formats"] == ["pdf", "json"]


@pytest.mark.asyncio
@respx.mock
async def test_handoff_raises_on_report_http_error():
    respx.post("http://analyzer.test/analyze").mock(
        return_value=httpx.Response(200, json={})
    )
    respx.post("http://analyzer.test/report").mock(
        return_value=httpx.Response(502, json={"detail": "reports down"})
    )
    with pytest.raises(httpx.HTTPStatusError):
        await hand_off_to_reports("http://analyzer.test", SCAN, AGENT, ["json"])
