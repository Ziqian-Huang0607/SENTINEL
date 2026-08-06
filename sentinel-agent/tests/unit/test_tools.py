"""Unit tests for the nine benign probe tools (agent-spec.md sections 2/5/11).

Fake asyncio listeners on 127.0.0.1:0 stand in for real services. Every
network tool is also exercised against the scope guard and against a closed
ephemeral port (failure path, no exception).
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import socket
import ssl
import struct
import subprocess
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any

import pytest
from src.scope import Scope, ScopeViolation
from src.tools import TOOL_REGISTRY
from src.tools.base import EXCERPT_LIMIT
from src.tools.mdns_browse import MDNS_QUERY, extract_service_names

LOOPBACK = "127.0.0.1"
IN_SCOPE = Scope({LOOPBACK})
OUT_OF_SCOPE = Scope({"192.168.1.5"})

EXPECTED_TOOLS = {
    "http_get",
    "grab_banner",
    "tls_hello",
    "ipp_enumerate",
    "mdns_browse",
    "smb_probe",
    "dns_reverse",
    "cve_lookup",
    "default_panel_check",
}


# --------------------------------------------------------------------------
# Fake listeners
# --------------------------------------------------------------------------


@asynccontextmanager
async def serve(handler: Any, **kwargs: Any) -> AsyncIterator[tuple[str, int]]:
    """Run handler on 127.0.0.1 port 0; yield (host, port)."""
    server = await asyncio.start_server(handler, LOOPBACK, 0, **kwargs)
    port = server.sockets[0].getsockname()[1]
    try:
        yield LOOPBACK, port
    finally:
        server.close()
        await server.wait_closed()


@contextmanager
def closed_port() -> Any:
    """Yield an ephemeral TCP port that is immediately closed."""
    sock = socket.socket()
    sock.bind((LOOPBACK, 0))
    port = sock.getsockname()[1]
    sock.close()
    yield port


_HTML = (
    b"<html><head><title>Router Admin</title></head>"
    b"<body>admin panel login</body></html>"
)
_HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n"
    b"Set-Cookie: sess=abc\r\nContent-Length: "
    + str(len(_HTML)).encode()
    + b"\r\nConnection: close\r\n\r\n"
    + _HTML
)


async def _http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = await reader.read(4096)
            if not chunk:
                return  # peer closed without sending a request
            request += chunk
        writer.write(_HTTP_RESPONSE)
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"


async def _banner_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await reader.read(64)  # swallow the payload first
        writer.write(_BANNER)
        await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


def _smb2_negotiate_response() -> bytes:
    """Canned SMB2 NEGOTIATE response: dialect 3.1.1, signing required."""
    header = b"\xfeSMB" + struct.pack("<H", 64) + b"\x00" * 58
    body = struct.pack("<HHH", 65, 0x03, 0x0311) + b"\x00" * 58
    packet = header + body
    return b"\x00\x00" + len(packet).to_bytes(2, "big") + packet


async def _smb_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await reader.read(256)  # swallow the negotiate request
        writer.write(_smb2_negotiate_response())
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


def _attr(tag: int, name: str, value: bytes) -> bytes:
    name_b = name.encode("ascii")
    return (
        bytes([tag])
        + struct.pack(">H", len(name_b))
        + name_b
        + struct.pack(">H", len(value))
        + value
    )


def _ipp_response_body() -> bytes:
    """Minimal IPP/1.1 Get-Printer-Attributes response with one printer."""
    body = b"\x01\x01\x00\x00" + struct.pack(">I", 1)
    body += b"\x01"  # operation-attributes-tag
    body += _attr(0x47, "attributes-charset", b"utf-8")
    body += b"\x04"  # printer-attributes-tag
    body += _attr(0x23, "printer-state", struct.pack(">I", 3))
    body += _attr(0x42, "printer-name", b"Office-Laser")
    body += _attr(0x45, "printer-uri-supported", b"ipp://127.0.0.1:631/printers/Office-Laser")
    body += b"\x03"
    return body


async def _ipp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request = await reader.read(4096)
        match = re.search(rb"[Cc]ontent-[Ll]ength: (\d+)", request)
        if match and b"\r\n\r\n" in request:
            have = len(request.split(b"\r\n\r\n", 1)[1])
            missing = int(match.group(1)) - have
            if missing > 0:
                await reader.readexactly(missing)
        body = _ipp_response_body()
        writer.write(
            b"HTTP/1.1 200 OK\r\nServer: CUPS/2.4\r\nContent-Type: application/ipp\r\n"
            + b"Content-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError):
        pass
    finally:
        writer.close()


# --------------------------------------------------------------------------
# Registry / data-file sync
# --------------------------------------------------------------------------


def test_registry_contains_all_nine_tools() -> None:
    assert set(TOOL_REGISTRY) == EXPECTED_TOOLS
    for name, tool in TOOL_REGISTRY.items():
        assert tool.name == name
        assert tool.description
        assert "properties" in tool.args_schema
        assert name in tool.menu_line()


def test_cve_seed_sync() -> None:
    """cve_seed.json must mirror the scanner's embedded seed exactly."""
    repo_root = Path(__file__).resolve().parents[3]
    rust_source = (repo_root / "sentinel-scanner" / "src" / "vuln" / "cve_cache.rs").read_text()
    version_match = re.search(r'pub const SEED_VERSION: &str = "([^"]+)"', rust_source)
    assert version_match, "SEED_VERSION not found in cve_cache.rs"
    rust_cves = set(re.findall(r'\("(CVE-[^"]+)"', rust_source))

    seed = json.loads(
        (Path(__file__).resolve().parents[2] / "data" / "cve_seed.json").read_text()
    )
    assert seed["version"] == version_match.group(1)
    assert len(seed["entries"]) == len(rust_cves)
    assert {entry["cve"] for entry in seed["entries"]} == rust_cves


# --------------------------------------------------------------------------
# http_get
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_get_basic() -> None:
    async with serve(_http_handler) as (host, port):
        result = await TOOL_REGISTRY["http_get"].run(
            {"host": host, "port": port, "path": "/", "tls": False}, IN_SCOPE
        )
    assert result.ok
    assert result.data["status"] == 200
    assert result.data["server"] == "nginx/1.18.0"
    assert result.data["title"] == "Router Admin"
    assert result.data["headers"]["set-cookie"] is True
    assert result.data["redirect_location"] is None
    assert "admin panel" in result.data["body_excerpt"]
    assert len(result.data["body_excerpt"]) <= 2048
    assert len(result.excerpt) <= EXCERPT_LIMIT


@pytest.mark.asyncio
async def test_http_get_scope_violation() -> None:
    with pytest.raises(ScopeViolation):
        await TOOL_REGISTRY["http_get"].run(
            {"host": LOOPBACK, "port": 80}, OUT_OF_SCOPE
        )


@pytest.mark.asyncio
async def test_http_get_closed_port_fails_cleanly() -> None:
    with closed_port() as port:
        result = await TOOL_REGISTRY["http_get"].run(
            {"host": LOOPBACK, "port": port}, IN_SCOPE
        )
    assert not result.ok
    assert result.error
    assert len(result.excerpt) <= EXCERPT_LIMIT


# --------------------------------------------------------------------------
# grab_banner
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_grab_banner_reads_banner() -> None:
    async with serve(_banner_handler) as (host, port):
        result = await TOOL_REGISTRY["grab_banner"].run(
            {"host": host, "port": port}, IN_SCOPE
        )
    assert result.ok
    assert "OpenSSH_8.9p1" in result.data["banner"]
    assert len(result.data["banner"]) <= 1024
    assert len(result.excerpt) <= EXCERPT_LIMIT


@pytest.mark.asyncio
async def test_grab_banner_scope_violation() -> None:
    with pytest.raises(ScopeViolation):
        await TOOL_REGISTRY["grab_banner"].run(
            {"host": LOOPBACK, "port": 22}, OUT_OF_SCOPE
        )


@pytest.mark.asyncio
async def test_grab_banner_closed_port_fails_cleanly() -> None:
    with closed_port() as port:
        result = await TOOL_REGISTRY["grab_banner"].run(
            {"host": LOOPBACK, "port": port}, IN_SCOPE
        )
    assert not result.ok
    assert result.error


# --------------------------------------------------------------------------
# tls_hello
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tls_hello_plaintext_port_is_ok_not_failure() -> None:
    async with serve(_banner_handler) as (host, port):
        result = await TOOL_REGISTRY["tls_hello"].run(
            {"host": host, "port": port}, IN_SCOPE
        )
    assert result.ok
    assert result.data["tls"] is False
    assert len(result.excerpt) <= EXCERPT_LIMIT


@pytest.mark.asyncio
async def test_tls_hello_scope_violation() -> None:
    with pytest.raises(ScopeViolation):
        await TOOL_REGISTRY["tls_hello"].run(
            {"host": LOOPBACK, "port": 443}, OUT_OF_SCOPE
        )


@pytest.mark.asyncio
async def test_tls_hello_closed_port_fails_cleanly() -> None:
    with closed_port() as port:
        result = await TOOL_REGISTRY["tls_hello"].run(
            {"host": LOOPBACK, "port": port}, IN_SCOPE
        )
    assert not result.ok


@pytest.mark.asyncio
@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl CLI unavailable")
async def test_tls_hello_and_https_get_against_real_cert(tmp_path: Path) -> None:
    """Self-signed cert served over TLS: tls=True, cert fields populated."""
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    await asyncio.to_thread(
        subprocess.run,
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key), "-out", str(cert),
            "-days", "1", "-nodes", "-subj", "/CN=sentinel-test/O=SENTINEL",
        ],
        check=True,
        capture_output=True,
    )
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    async with serve(_http_handler, ssl=server_ctx) as (host, port):
        hello = await TOOL_REGISTRY["tls_hello"].run(
            {"host": host, "port": port}, IN_SCOPE
        )
        assert hello.ok
        assert hello.data["tls"] is True
        assert "sentinel-test" in hello.data["cert_subject"]
        assert hello.data["cert_not_after"]
        assert len(hello.excerpt) <= EXCERPT_LIMIT

        page = await TOOL_REGISTRY["http_get"].run(
            {"host": host, "port": port, "tls": True}, IN_SCOPE
        )
        assert page.ok
        assert page.data["status"] == 200
        assert page.data["title"] == "Router Admin"


# --------------------------------------------------------------------------
# ipp_enumerate
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ipp_enumerate_parses_printer() -> None:
    async with serve(_ipp_handler) as (host, port):
        result = await TOOL_REGISTRY["ipp_enumerate"].run(
            {"host": host, "port": port}, IN_SCOPE
        )
    assert result.ok
    assert result.data["server_version"] == "CUPS/2.4"
    assert len(result.data["printers"]) == 1
    printer = result.data["printers"][0]
    assert printer["name"] == "Office-Laser"
    assert printer["state"] == "idle"
    assert "ipp://" in printer["uri"]
    assert len(result.excerpt) <= EXCERPT_LIMIT


@pytest.mark.asyncio
async def test_ipp_enumerate_non_ipp_response_is_ok() -> None:
    async with serve(_http_handler) as (host, port):
        result = await TOOL_REGISTRY["ipp_enumerate"].run(
            {"host": host, "port": port}, IN_SCOPE
        )
    assert result.ok
    assert result.data["printers"] == []
    assert "not recognized as IPP" in result.data["note"]
    assert len(result.excerpt) <= EXCERPT_LIMIT


@pytest.mark.asyncio
async def test_ipp_enumerate_scope_violation() -> None:
    with pytest.raises(ScopeViolation):
        await TOOL_REGISTRY["ipp_enumerate"].run(
            {"host": LOOPBACK, "port": 631}, OUT_OF_SCOPE
        )


@pytest.mark.asyncio
async def test_ipp_enumerate_closed_port_fails_cleanly() -> None:
    with closed_port() as port:
        result = await TOOL_REGISTRY["ipp_enumerate"].run(
            {"host": LOOPBACK, "port": port}, IN_SCOPE
        )
    assert not result.ok


# --------------------------------------------------------------------------
# mdns_browse
# --------------------------------------------------------------------------


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def test_mdns_extract_service_names_lenient() -> None:
    packet = (
        MDNS_QUERY
        + _encode_name("_http._tcp.local")
        + b"\x00\x0c\x00\x01"
        + _encode_name("My Printer._ipp._tcp.local")
        + b"\x00\x0c\x00\x01"
        + b"random \x00\xff\x01 garbage"
    )
    names = extract_service_names(packet)
    assert "_http._tcp.local" in names
    assert "My Printer._ipp._tcp.local" in names
    assert "_services._dns-sd._udp.local" in names


@pytest.mark.asyncio
async def test_mdns_browse_one_shot() -> None:
    """Sandbox may block multicast: either way the result is ok with a list."""
    result = await TOOL_REGISTRY["mdns_browse"].run({}, Scope(set()))
    assert result.ok
    assert isinstance(result.data["services"], list)
    for service in result.data["services"]:
        assert set(service) == {"name", "type", "host", "port", "addresses"}
    assert len(result.excerpt) <= EXCERPT_LIMIT


# --------------------------------------------------------------------------
# smb_probe
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_smb_probe_parses_dialect_and_signing() -> None:
    async with serve(_smb_handler) as (host, port):
        result = await TOOL_REGISTRY["smb_probe"].run(
            {"host": host, "port": port}, IN_SCOPE
        )
    assert result.ok
    assert result.data["smb"] is True
    assert result.data["dialect"] == "3.1.1"
    assert result.data["signing_required"] is True
    assert len(result.excerpt) <= EXCERPT_LIMIT


async def _garbage_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        writer.write(b"NOTSMB this is not an SMB server\r\n")
        await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()


@pytest.mark.asyncio
async def test_smb_probe_non_smb_response() -> None:
    async with serve(_garbage_handler) as (host, port):
        result = await TOOL_REGISTRY["smb_probe"].run(
            {"host": host, "port": port}, IN_SCOPE
        )
    assert result.ok
    assert result.data["smb"] is False


@pytest.mark.asyncio
async def test_smb_probe_scope_violation() -> None:
    with pytest.raises(ScopeViolation):
        await TOOL_REGISTRY["smb_probe"].run(
            {"host": LOOPBACK, "port": 445}, OUT_OF_SCOPE
        )


@pytest.mark.asyncio
async def test_smb_probe_closed_port_fails_cleanly() -> None:
    with closed_port() as port:
        result = await TOOL_REGISTRY["smb_probe"].run(
            {"host": LOOPBACK, "port": port}, IN_SCOPE
        )
    assert not result.ok


# --------------------------------------------------------------------------
# dns_reverse
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dns_reverse_loopback() -> None:
    result = await TOOL_REGISTRY["dns_reverse"].run({"host": LOOPBACK}, IN_SCOPE)
    assert result.ok
    assert isinstance(result.data["hostnames"], list)
    assert all(isinstance(name, str) for name in result.data["hostnames"])
    assert len(result.excerpt) <= EXCERPT_LIMIT


@pytest.mark.asyncio
async def test_dns_reverse_no_ptr_is_empty_not_error() -> None:
    scope = Scope({"192.168.1.5"})
    result = await TOOL_REGISTRY["dns_reverse"].run({"host": "192.168.1.5"}, scope)
    # Unresolvable PTR: empty list with ok=True (a resolver hang would be a
    # clean timeout failure — either way, no exception escapes).
    if result.ok:
        assert result.data["hostnames"] == []
    assert len(result.excerpt) <= EXCERPT_LIMIT


@pytest.mark.asyncio
async def test_dns_reverse_scope_violation() -> None:
    with pytest.raises(ScopeViolation):
        await TOOL_REGISTRY["dns_reverse"].run({"host": LOOPBACK}, OUT_OF_SCOPE)


# --------------------------------------------------------------------------
# cve_lookup
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cve_lookup_nginx_1_18_matches() -> None:
    result = await TOOL_REGISTRY["cve_lookup"].run(
        {"service": "nginx", "version": "1.18.0"}, Scope(set())
    )
    assert result.ok
    cves = {match["cve"] for match in result.data["matches"]}
    assert "CVE-2021-23017" in cves
    for match in result.data["matches"]:
        assert set(match) == {"cve", "cvss", "epss", "kev", "summary"}
        assert 0.0 <= match["cvss"] <= 10.0
        assert 0.0 <= match["epss"] <= 1.0
    assert len(result.excerpt) <= EXCERPT_LIMIT


@pytest.mark.asyncio
async def test_cve_lookup_case_insensitive_service() -> None:
    result = await TOOL_REGISTRY["cve_lookup"].run(
        {"service": "NGINX", "version": "1.18.0"}, Scope(set())
    )
    assert result.ok
    assert any(m["cve"] == "CVE-2021-23017" for m in result.data["matches"])


@pytest.mark.asyncio
async def test_cve_lookup_version_out_of_range() -> None:
    result = await TOOL_REGISTRY["cve_lookup"].run(
        {"service": "nginx", "version": "9.9.9"}, Scope(set())
    )
    assert result.ok
    assert result.data["matches"] == []


@pytest.mark.asyncio
async def test_cve_lookup_unknown_service_empty() -> None:
    result = await TOOL_REGISTRY["cve_lookup"].run(
        {"service": "gopher", "version": "1.0"}, Scope(set())
    )
    assert result.ok
    assert result.data["matches"] == []
    assert len(result.excerpt) <= EXCERPT_LIMIT


# --------------------------------------------------------------------------
# default_panel_check
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_panel_check_tplink_title() -> None:
    result = await TOOL_REGISTRY["default_panel_check"].run(
        {"host": LOOPBACK, "port": 80, "server": "", "title": "TP-LINK Wireless Router"},
        IN_SCOPE,
    )
    assert result.ok
    assert result.data["matched_panel"] == "tp-link-router"
    assert result.data["vendor_hint"] == "TP-Link"
    assert "tp-link" in result.data["evidence"]
    assert len(result.excerpt) <= EXCERPT_LIMIT


@pytest.mark.asyncio
async def test_default_panel_check_generic_router_admin() -> None:
    result = await TOOL_REGISTRY["default_panel_check"].run(
        {
            "host": LOOPBACK,
            "port": 80,
            "server": "nginx/1.18.0",
            "title": "Router Admin",
        },
        IN_SCOPE,
    )
    assert result.ok
    assert result.data["matched_panel"] == "generic-router-admin"
    assert result.data["vendor_hint"] == "generic"


@pytest.mark.asyncio
async def test_default_panel_check_openwrt_server_header() -> None:
    result = await TOOL_REGISTRY["default_panel_check"].run(
        {"host": LOOPBACK, "port": 80, "server": "uHTTPd", "title": ""},
        IN_SCOPE,
    )
    assert result.ok
    assert result.data["matched_panel"] == "openwrt-luci"
    assert result.data["vendor_hint"] == "OpenWrt"


@pytest.mark.asyncio
async def test_default_panel_check_no_match() -> None:
    result = await TOOL_REGISTRY["default_panel_check"].run(
        {
            "host": LOOPBACK,
            "port": 80,
            "server": "nginx/1.18.0",
            "title": "Welcome to Example",
        },
        IN_SCOPE,
    )
    assert result.ok
    assert result.data["matched_panel"] is None
    assert result.data["vendor_hint"] is None
    assert len(result.excerpt) <= EXCERPT_LIMIT


@pytest.mark.asyncio
async def test_default_panel_check_scope_violation() -> None:
    with pytest.raises(ScopeViolation):
        await TOOL_REGISTRY["default_panel_check"].run(
            {"host": LOOPBACK, "port": 80}, OUT_OF_SCOPE
        )
