"""smb_probe — SMB2 NEGOTIATE only, no auth (agent-spec.md section 2).

Sends the well-known SMB2 NEGOTIATE request and parses the dialect
revision and signing-required flag from the response. SMB1-style
\\xffSMB responses are recognized too. Parsing is lenient: any trouble
degrades to an `smb` bool derived from whether the reply carried SMB
magic bytes.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from typing import Any

from src.scope import Scope
from src.tools.base import EXCERPT_LIMIT, Tool, ToolResult, sanitize

HARD_TIMEOUT = 5.0
_DIALECT_NAMES = {
    0x0202: "2.0.2",
    0x0210: "2.1",
    0x0300: "3.0",
    0x0302: "3.0.2",
    0x0311: "3.1.1",
}


def _build_negotiate() -> bytes:
    """SMB2 NEGOTIATE request wrapped in a NetBIOS session header."""
    header = (
        b"\xfeSMB"  # protocol id
        + struct.pack("<H", 64)  # structure size
        + b"\x00\x00"  # credit charge
        + b"\x00" * 4  # channel sequence / status
        + struct.pack("<H", 0)  # command: NEGOTIATE
        + struct.pack("<H", 1)  # credit request
        + b"\x00" * 4  # flags
        + b"\x00" * 4  # next command
        + b"\x00" * 8  # message id
        + b"\x00" * 4  # reserved
        + b"\x00" * 4  # tree id
        + b"\x00" * 8  # session id
        + b"\x00" * 16  # signature
    )
    body = (
        struct.pack("<H", 36)  # structure size
        + struct.pack("<H", 2)  # dialect count
        + struct.pack("<H", 1)  # security mode: signing enabled
        + b"\x00\x00"  # reserved
        + b"\x00" * 4  # capabilities
        + b"\x00" * 16  # client guid
        + b"\x00" * 8  # negotiate context / start time
        + struct.pack("<HH", 0x0202, 0x0210)  # dialects
    )
    packet = header + body
    return b"\x00\x00" + len(packet).to_bytes(2, "big") + packet


def _parse_response(smb: bytes) -> dict[str, Any]:
    """Parse an SMB payload (NetBIOS header already stripped)."""
    if smb.startswith(b"\xfeSMB"):
        result: dict[str, Any] = {"smb": True, "os_hint": ""}
        # Negotiate response: StructureSize(2) at 64, SecurityMode(2) at 66,
        # DialectRevision(2) at 68.
        if len(smb) >= 70:
            security_mode = struct.unpack("<H", smb[66:68])[0]
            dialect_revision = struct.unpack("<H", smb[68:70])[0]
            result["dialect"] = _DIALECT_NAMES.get(
                dialect_revision, f"unknown(0x{dialect_revision:04x})"
            )
            result["signing_required"] = bool(security_mode & 0x02)
        else:
            result["dialect"] = "unknown"
            result["signing_required"] = False
        return result
    if smb.startswith(b"\xffSMB"):
        return {
            "smb": True,
            "dialect": "SMB1",
            "signing_required": False,
            "os_hint": "",
        }
    return {"smb": False, "dialect": "", "signing_required": False, "os_hint": ""}


async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
    """Send one SMB2 NEGOTIATE to host:port and summarize the dialect."""
    host = str(args.get("host", ""))
    port = int(args.get("port", 445))
    scope.check(host)  # ScopeViolation propagates — never caught.

    async def _probe() -> bytes:
        reader, writer = await asyncio.open_connection(host, port)
        try:
            writer.write(_build_negotiate())
            await writer.drain()
            netbios = await reader.readexactly(4)
            length = int.from_bytes(netbios[2:4], "big")
            if length > 16384:
                return b""  # implausible: not an SMB server
            return await reader.readexactly(length)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    try:
        smb = await asyncio.wait_for(_probe(), timeout=HARD_TIMEOUT)
    except Exception as exc:  # noqa: BLE001 — spec: any network error -> failure
        return ToolResult.failure(str(exc) or type(exc).__name__)

    data = _parse_response(smb)
    if data["smb"]:
        excerpt = sanitize(
            f"SMB {host}:{port} dialect={data['dialect']} "
            f"signing_required={data['signing_required']} "
            f"os_hint={data['os_hint']!r}",
            EXCERPT_LIMIT,
        )
    else:
        excerpt = sanitize(f"{host}:{port} no SMB response", EXCERPT_LIMIT)
    return ToolResult(ok=True, data=data, excerpt=excerpt)


TOOL = Tool(
    name="smb_probe",
    description="SMB2 NEGOTIATE only: dialect revision and signing flag, no auth.",
    args_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "port": {"type": "integer", "default": 445},
        },
        "required": ["host"],
    },
    run=run,
)
