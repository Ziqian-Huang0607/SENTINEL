"""Tests for the deterministic playbook fallback (agent-spec.md section 8).

Uses fake asyncio listeners on loopback (an HTTP admin page and a banner
echo service) plus test-local Tool stubs — never the real TOOL_REGISTRY.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from src.models import CLASS_SEVERITY, TargetBrief
from src.playbook import investigate_target_playbook
from src.scope import Scope
from src.tools.base import Tool, ToolResult

HOST = "127.0.0.1"
SCOPE = Scope({HOST})


def stub_tool(
    name: str,
    handler: Any = None,
    result: ToolResult | None = None,
) -> Tool:
    """A recording stub Tool; handler overrides the canned result."""

    async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
        if "host" in args:
            scope.check(str(args["host"]))
        if handler is not None:
            return await handler(args)
        return result or ToolResult(ok=True, data={}, excerpt=f"{name} ok")

    return Tool(
        name=name,
        description=f"stub {name}",
        args_schema={"properties": {"host": {"type": "string"}}},
        run=run,
    )


async def start_http_admin() -> tuple[asyncio.AbstractServer, int]:
    """A minimal HTTP listener serving an admin page with a Server header."""
    body = b"<html><head><title>TestRouter Admin</title></head></html>"

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.read(4096)
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: TestRouter/1.2\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, HOST, 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def start_banner_echo(banner: bytes) -> tuple[asyncio.AbstractServer, int]:
    """A listener that sends a fixed banner on connect, then closes."""

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writer.write(banner)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, HOST, 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def real_http_get(args: dict[str, Any]) -> ToolResult:
    """A minimal real http_get-shaped stub: one GET over asyncio streams."""
    host, port = str(args["host"]), int(args["port"])
    path = str(args.get("path", "/"))
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5.0
        )
    except (OSError, asyncio.TimeoutError) as exc:
        return ToolResult.failure(f"connect failed: {exc}")
    try:
        writer.write(f"GET {path} HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(4096), timeout=5.0)
    except (OSError, asyncio.TimeoutError) as exc:
        return ToolResult.failure(f"read failed: {exc}")
    finally:
        writer.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1]) if len(lines) > 0 else 0
    headers = {}
    for line in lines[1:]:
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    server = headers.get("server", "")
    title = ""
    text = body.decode("latin-1")
    if "<title>" in text:
        title = text.split("<title>", 1)[1].split("</title>", 1)[0]
    excerpt = f"GET {path} -> {status}; Server: {server}; title: {title}"
    return ToolResult(
        ok=True,
        data={"status": status, "server": server, "title": title},
        excerpt=excerpt[:600],
    )


async def real_grab_banner(args: dict[str, Any]) -> ToolResult:
    """A minimal real grab_banner-shaped stub over asyncio streams."""
    host, port = str(args["host"]), int(args["port"])
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5.0
        )
        writer.write(b"\r\n")
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(1024), timeout=3.0)
        writer.close()
    except (OSError, asyncio.TimeoutError) as exc:
        return ToolResult.failure(f"banner failed: {exc}")
    banner = raw.decode("latin-1").strip()
    return ToolResult(
        ok=True, data={"banner": banner}, excerpt=f"banner: {banner}"[:600]
    )


def panel_check_tool() -> Tool:
    """default_panel_check stub: matches the TestRouter admin signature."""

    async def check(args: dict[str, Any]) -> ToolResult:
        title = str(args.get("title", ""))
        if "TestRouter" in title:
            return ToolResult(
                ok=True,
                data={
                    "matched_panel": "TestRouter Admin",
                    "vendor_hint": "TestRouter",
                    "evidence": f"title={title}",
                },
                excerpt=f"matched panel TestRouter Admin (title={title})",
            )
        return ToolResult(
            ok=True,
            data={"matched_panel": None, "vendor_hint": None, "evidence": ""},
            excerpt="no known panel matched",
        )

    return stub_tool("default_panel_check", handler=check)


def cve_lookup_tool(matches: list[dict[str, Any]] | None = None) -> Tool:
    """cve_lookup stub with a canned (empty by default) match list."""
    return stub_tool(
        "cve_lookup",
        result=ToolResult(
            ok=True, data={"matches": matches or []},
            excerpt=f"{len(matches or [])} CVE match(es)",
        ),
    )


def tls_hello_tool(tls: bool = False) -> Tool:
    """tls_hello stub."""
    return stub_tool(
        "tls_hello",
        result=ToolResult(
            ok=True, data={"tls": tls}, excerpt=f"tls: {tls}"
        ),
    )


@pytest.mark.asyncio
async def test_playbook_unauth_web_against_real_http_listener() -> None:
    """Unauth web flow on a real loopback HTTP admin page -> DEFAULT-PANEL."""
    server, port = await start_http_admin()
    try:
        registry = {
            "http_get": stub_tool("http_get", handler=real_http_get),
            "default_panel_check": panel_check_tool(),
            "tls_hello": tls_hello_tool(),
            "cve_lookup": cve_lookup_tool(),
        }
        brief = TargetBrief(
            host=HOST,
            ports=[port],
            trigger="unauth_posture",
            hints={"posture_ids": ["POSTURE-UNAUTH-WEB"]},
        )
        investigation = await investigate_target_playbook(brief, registry, SCOPE)
    finally:
        server.close()
        await server.wait_closed()
    assert investigation.status == "concluded"
    assert len(investigation.findings) == 1
    finding = investigation.findings[0]
    assert finding.finding_class == "DEFAULT-PANEL"
    assert finding.severity == CLASS_SEVERITY["DEFAULT-PANEL"] == 7.0
    assert finding.port == port
    assert "TestRouter Admin" in finding.title
    assert len(finding.evidence) == 2  # http_get + default_panel_check


@pytest.mark.asyncio
async def test_playbook_unknown_port_banner_identifies_service() -> None:
    """Unknown port flow on a banner echo listener -> SERVICE-IDENT (ssh)."""
    server, port = await start_banner_echo(b"SSH-2.0-OpenSSH_9.2\r\n")
    try:
        registry = {
            "grab_banner": stub_tool("grab_banner", handler=real_grab_banner),
            "http_get": stub_tool(
                "http_get", result=ToolResult.failure("not http")
            ),
            "tls_hello": tls_hello_tool(),
        }
        brief = TargetBrief(
            host=HOST, ports=[port], trigger="unknown_service", hints={}
        )
        investigation = await investigate_target_playbook(brief, registry, SCOPE)
    finally:
        server.close()
        await server.wait_closed()
    assert investigation.status == "concluded"
    assert len(investigation.findings) == 1
    finding = investigation.findings[0]
    assert finding.finding_class == "SERVICE-IDENT"
    assert finding.severity == CLASS_SEVERITY["SERVICE-IDENT"] == 2.0
    assert "ssh" in finding.title
    assert finding.evidence  # grounded in the banner evidence


@pytest.mark.asyncio
async def test_playbook_determinism_two_runs_identical() -> None:
    """Identical inputs produce identical findings (no timestamps inside)."""
    registry = {
        "http_get": stub_tool(
            "http_get",
            result=ToolResult(
                ok=True,
                data={"status": 200, "server": "TestRouter/1.2",
                      "title": "TestRouter Admin"},
                excerpt="GET / -> 200; Server: TestRouter/1.2",
            ),
        ),
        "default_panel_check": panel_check_tool(),
        "tls_hello": tls_hello_tool(),
        "cve_lookup": cve_lookup_tool(),
    }
    brief = TargetBrief(
        host=HOST,
        ports=[8443],
        trigger="gateway",
        hints={"posture_ids": ["POSTURE-UNAUTH-WEB-GATEWAY"]},
    )
    first = await investigate_target_playbook(brief, registry, SCOPE)
    second = await investigate_target_playbook(brief, registry, SCOPE)
    assert [f.model_dump() for f in first.findings] == [
        f.model_dump() for f in second.findings
    ]
    assert first.findings  # the determinism check is not vacuous
    assert first.status == second.status == "concluded"


@pytest.mark.asyncio
async def test_playbook_datastore_banner_confirms_sensitive_service() -> None:
    """Datastore flow: a redis-ish banner -> SENSITIVE-SERVICE finding."""
    server, port = await start_banner_echo(
        b"-NOAUTH Authentication required.\r\n"
    )
    try:
        registry = {
            "grab_banner": stub_tool("grab_banner", handler=real_grab_banner),
            "smb_probe": stub_tool(
                "smb_probe",
                result=ToolResult(ok=True, data={"smb": False}, excerpt="no smb"),
            ),
        }
        brief = TargetBrief(
            host=HOST,
            ports=[port],
            trigger="unauth_posture",
            hints={"posture_ids": ["POSTURE-UNAUTH-DATASTORE"]},
        )
        investigation = await investigate_target_playbook(brief, registry, SCOPE)
    finally:
        server.close()
        await server.wait_closed()
    assert investigation.status == "concluded"
    assert len(investigation.findings) == 1
    finding = investigation.findings[0]
    assert finding.finding_class == "SENSITIVE-SERVICE"
    assert finding.severity == CLASS_SEVERITY["SENSITIVE-SERVICE"] == 5.5
    assert "redis" in finding.title


@pytest.mark.asyncio
async def test_playbook_ipp_flow_confirms_sensitive_service() -> None:
    """IPP flow: ipp_enumerate success -> SENSITIVE-SERVICE finding."""
    registry = {
        "ipp_enumerate": stub_tool(
            "ipp_enumerate",
            result=ToolResult(
                ok=True,
                data={
                    "server_version": "CUPS 2.4",
                    "printers": [{"name": "office", "uri": "ipp://x", "state": 3}],
                },
                excerpt="IPP server CUPS 2.4; printers: office",
            ),
        ),
        "http_get": stub_tool(
            "http_get",
            result=ToolResult(
                ok=True, data={"status": 200, "server": "CUPS/2.4"},
                excerpt="GET / -> 200",
            ),
        ),
    }
    brief = TargetBrief(
        host=HOST,
        ports=[631],
        trigger="unauth_posture",
        hints={"posture_ids": ["POSTURE-UNAUTH-IPP"]},
    )
    investigation = await investigate_target_playbook(brief, registry, SCOPE)
    assert investigation.status == "concluded"
    assert len(investigation.findings) == 1
    finding = investigation.findings[0]
    assert finding.finding_class == "SENSITIVE-SERVICE"
    assert finding.evidence == ["E1"]
