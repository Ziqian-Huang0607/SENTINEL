"""ipp_enumerate — minimal IPP/1.1 Get-Printer-Attributes (agent-spec.md s2).

Sends one canned binary IPP POST to /ipp and leniently parses printer-name,
printer-uri and printer-state attributes out of the response. If the
response is not recognizable as IPP the result is ok=True with an empty
printer list and a note — never an exception.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from typing import Any

from src.scope import Scope
from src.tools.base import EXCERPT_LIMIT, Tool, ToolResult, sanitize

HARD_TIMEOUT = 5.0
_MAX_RESPONSE = 65536
_STATE_NAMES = {3: "idle", 4: "processing", 5: "stopped"}


def _attr(tag: int, name: str, value: str) -> bytes:
    """Encode one IPP attribute (tag, name, value)."""
    name_b = name.encode("ascii")
    value_b = value.encode("ascii")
    return (
        bytes([tag])
        + struct.pack(">H", len(name_b))
        + name_b
        + struct.pack(">H", len(value_b))
        + value_b
    )


def _build_ipp_body(host: str, port: int) -> bytes:
    """Canned IPP/1.1 Get-Printer-Attributes request body."""
    attrs = b"\x01"  # operation-attributes-tag
    attrs += _attr(0x47, "attributes-charset", "utf-8")
    attrs += _attr(0x48, "attributes-natural-language", "en")
    attrs += _attr(0x45, "printer-uri", f"ipp://{host}:{port}/ipp")
    attrs += b"\x03"  # end-of-attributes-tag
    return b"\x01\x01" + b"\x00\x0b" + struct.pack(">I", 1) + attrs


def _parse_ipp_attributes(body: bytes) -> list[tuple[int, str, bytes]] | None:
    """Leniently walk IPP attribute groups; None if not IPP-looking."""
    if len(body) < 8 or body[0] not in (0x01, 0x02):
        return None
    attrs: list[tuple[int, str, bytes]] = []
    i = 8  # version(2) status(2) request-id(4)
    while i < len(body):
        tag = body[i]
        if tag == 0x03:  # end-of-attributes
            break
        if 0x01 <= tag <= 0x0F:  # delimiter (group) tag
            i += 1
            continue
        if i + 3 > len(body):
            break
        name_len = int.from_bytes(body[i + 1 : i + 3], "big")
        name_start = i + 3
        name_end = name_start + name_len
        if name_end + 2 > len(body):
            break
        name = body[name_start:name_end].decode("ascii", "replace")
        value_len = int.from_bytes(body[name_end : name_end + 2], "big")
        value_start = name_end + 2
        value_end = value_start + value_len
        if value_end > len(body):
            break
        attrs.append((tag, name, body[value_start:value_end]))
        i = value_end
    return attrs


def _extract_printers(attrs: list[tuple[int, str, bytes]]) -> list[dict[str, str]]:
    """Turn a flat IPP attribute list into printer dicts."""
    names = [v for _t, n, v in attrs if n == "printer-name"]
    uris = [
        v for _t, n, v in attrs if n in ("printer-uri", "printer-uri-supported")
    ]
    state = ""
    for tag, name, value in attrs:
        if name == "printer-state" and tag == 0x23 and len(value) == 4:
            state = _STATE_NAMES.get(
                int.from_bytes(value, "big"), f"unknown({int.from_bytes(value, 'big')})"
            )
            break
    uri = uris[0].decode("utf-8", "replace") if uris else ""
    printers = []
    for name_b in names:
        printers.append(
            {
                "name": sanitize(name_b.decode("utf-8", "replace"), 200),
                "uri": sanitize(uri, 300),
                "state": state,
            }
        )
    return printers


async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
    """POST one Get-Printer-Attributes request and summarize the printers."""
    host = str(args.get("host", ""))
    port = int(args.get("port", 631))
    scope.check(host)  # ScopeViolation propagates — never caught.
    body = _build_ipp_body(host, port)
    request = (
        f"POST /ipp HTTP/1.1\r\nHost: {host}:{port}\r\n"
        f"Content-Type: application/ipp\r\nContent-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii") + body

    async def _probe() -> bytes:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            writer.write(request)
            await writer.drain()
            return await reader.read(_MAX_RESPONSE)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    try:
        raw = await asyncio.wait_for(_probe(), timeout=HARD_TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — spec: any network error -> failure
        return ToolResult.failure(str(exc) or type(exc).__name__)

    head, _, ipp_body = raw.partition(b"\r\n\r\n")
    header_lines = head.decode("latin-1", "replace").split("\r\n")
    status = header_lines[0] if header_lines and header_lines[0] else ""
    server_version = ""
    for line in header_lines[1:]:
        if line.lower().startswith("server:"):
            server_version = sanitize(line.split(":", 1)[1].strip(), 200)
            break

    attrs = _parse_ipp_attributes(ipp_body)
    printers: list[dict[str, str]] = []
    note = ""
    if attrs is None:
        note = "response not recognized as IPP"
    else:
        printers = _extract_printers(attrs)
        if not printers:
            note = "IPP response contained no printers"

    data: dict[str, Any] = {
        "server_version": server_version,
        "printers": printers,
    }
    if note:
        data["note"] = note
    summary = (
        f"{len(printers)} printer(s): "
        + ", ".join(f"{p['name']} ({p['state'] or 'state unknown'})" for p in printers)
        if printers
        else note
    )
    excerpt = sanitize(
        f"IPP {host}:{port} {status} server={server_version!r} {summary}",
        EXCERPT_LIMIT,
    )
    return ToolResult(ok=True, data=data, excerpt=excerpt)


TOOL = Tool(
    name="ipp_enumerate",
    description="One IPP Get-Printer-Attributes POST; list printers and state.",
    args_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "port": {"type": "integer", "default": 631},
        },
        "required": ["host"],
    },
    run=run,
)
