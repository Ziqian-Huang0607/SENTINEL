"""mdns_browse — one-shot subnet mDNS service enumeration (agent-spec.md s2).

Sends a single multicast query for _services._dns-sd._udp.local and listens
for ~3s. Parsing is deliberately lenient: readable DNS-encoded names that
look like service types/instances are extracted; full DNS parsing is out of
scope. mDNS is subnet-listen only (no host-directed traffic), so it is
always allowed regardless of scope. Any socket error (sandbox, multicast
blocked) yields ok=True with an empty service list and a note.
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Any

from src.scope import Scope
from src.tools.base import EXCERPT_LIMIT, Tool, ToolResult, sanitize

HARD_TIMEOUT = 5.0
LISTEN_SECONDS = 3.0
MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353


def _encode_name(name: str) -> bytes:
    """DNS-encode a dotted name into length-prefixed labels."""
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


# Single question: _services._dns-sd._udp.local, type PTR, class IN.
MDNS_QUERY = (
    b"\x00\x00"  # transaction id
    b"\x00\x00"  # flags
    b"\x00\x01"  # qdcount
    b"\x00\x00\x00\x00\x00\x00"  # an/ns/ar counts
    + _encode_name("_services._dns-sd._udp.local")
    + b"\x00\x0c\x00\x01"  # QTYPE=PTR, QCLASS=IN
)


def _try_decode_name(packet: bytes, offset: int, depth: int = 0) -> str | None:
    """Attempt to decode a DNS name at offset; None on anything irregular."""
    labels: list[str] = []
    i = offset
    while i < len(packet) and depth < 8:
        length = packet[i]
        if length == 0:
            return ".".join(labels) if labels else None
        if length & 0xC0 == 0xC0:  # compression pointer
            if i + 1 >= len(packet):
                return None
            pointer = ((length & 0x3F) << 8) | packet[i + 1]
            rest = _try_decode_name(packet, pointer, depth + 1)
            if rest:
                labels.append(rest)
            return ".".join(labels) if labels else None
        if length & 0xC0 or length > 63:
            return None
        i += 1
        if i + length > len(packet):
            return None
        label = packet[i : i + length]
        if not label or not all(32 <= b < 127 for b in label):
            return None
        labels.append(label.decode("ascii"))
        i += length
    return None


def _looks_like_service(name: str) -> bool:
    """True for mDNS service-ish names (a leading-underscore label)."""
    return name.endswith(".local") and any(
        label.startswith("_") for label in name.split(".")
    )


def extract_service_names(packet: bytes) -> set[str]:
    """Scan a packet for readable mDNS service names (lenient)."""
    found: set[str] = set()
    for offset in range(len(packet)):
        name = _try_decode_name(packet, offset)
        if name and _looks_like_service(name):
            found.add(name)
    return found


def _browse_sync(duration: float) -> list[str]:
    """Blocking multicast query + listen loop (run in a thread)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", MDNS_PORT))
        except OSError:
            sock.bind(("", 0))  # port busy: replies may still reach us
        try:
            membership = socket.inet_aton(MDNS_GROUP) + socket.inet_aton("0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        except OSError:
            pass
        sock.settimeout(0.25)
        sock.sendto(MDNS_QUERY, (MDNS_GROUP, MDNS_PORT))
        names: set[str] = set()
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            try:
                data, _addr = sock.recvfrom(65535)
            except TimeoutError:
                continue
            names.update(extract_service_names(data))
        return sorted(names)
    finally:
        sock.close()


def _service_entry(name: str) -> dict[str, Any]:
    """Shape one service dict; _services enumeration yields types, so
    host/port/addresses stay empty (honest, observed-evidence-only)."""
    transport = ""
    if "._tcp." in name:
        transport = "_tcp"
    elif "._udp." in name:
        transport = "_udp"
    return {
        "name": sanitize(name, 300),
        "type": transport,
        "host": "",
        "port": 0,
        "addresses": [],
    }


async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
    """Multicast one DNS-SD enumeration query and collect service names."""
    del args, scope  # subnet-listen only: no host, always allowed (spec s5)
    try:
        names = await asyncio.wait_for(
            asyncio.to_thread(_browse_sync, LISTEN_SECONDS), timeout=HARD_TIMEOUT
        )
    except Exception as exc:  # noqa: BLE001 — spec: any socket error -> ok, empty
        data: dict[str, Any] = {
            "services": [],
            "note": sanitize(f"mDNS unavailable: {exc}", 300),
        }
        excerpt = sanitize(f"mDNS browse unavailable: {exc}", EXCERPT_LIMIT)
        return ToolResult(ok=True, data=data, excerpt=excerpt)

    services = [_service_entry(name) for name in names]
    data = {"services": services}
    summary = (
        ", ".join(s["name"] for s in services) if services else "no services heard"
    )
    excerpt = sanitize(
        f"mDNS browse ({LISTEN_SECONDS:.0f}s listen): {len(services)} service(s): "
        f"{summary}",
        EXCERPT_LIMIT,
    )
    return ToolResult(ok=True, data=data, excerpt=excerpt)


TOOL = Tool(
    name="mdns_browse",
    description="One-shot subnet mDNS/DNS-SD service enumeration (3s listen).",
    args_schema={"type": "object", "properties": {}},
    run=run,
)
