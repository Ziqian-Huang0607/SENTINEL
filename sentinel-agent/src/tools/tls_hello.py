"""tls_hello — TLS handshake probe (agent-spec.md section 2).

Attempts a stdlib ssl handshake (CERT_NONE — internal tool talking to
self-signed device UIs) and reports whether TLS is offered plus certificate
subject/issuer/expiry and the negotiated ALPN protocol. A plaintext port is
a normal result (tls=False, ok=True), not a failure.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import tempfile
from typing import Any

from src.scope import Scope
from src.tools.base import EXCERPT_LIMIT, Tool, ToolResult, sanitize

HARD_TIMEOUT = 5.0


def _format_name(rdn_sequence: Any) -> str:
    """Render an ssl cert subject/issuer RDN sequence as 'CN=x, O=y'."""
    parts = []
    for rdn in rdn_sequence or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def _decode_cert(der: bytes | None) -> dict[str, str]:
    """Best-effort decode of a DER cert to subject/issuer/not_after strings."""
    if not der:
        return {}
    pem = ssl.DER_cert_to_PEM_cert(der)
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=True) as fh:
            fh.write(pem)
            fh.flush()
            decoded = ssl._ssl._test_decode_cert(fh.name)  # stdlib helper
    except Exception:  # noqa: BLE001 — best-effort decode, never fatal
        return {}
    return {
        "cert_subject": _format_name(decoded.get("subject")),
        "cert_issuer": _format_name(decoded.get("issuer")),
        "cert_not_after": str(decoded.get("notAfter", "")),
    }


async def run(args: dict[str, Any], scope: Scope) -> ToolResult:
    """Try a TLS handshake against host:port and summarize the outcome."""
    host = str(args.get("host", ""))
    port = int(args.get("port", 0))
    scope.check(host)  # ScopeViolation propagates — never caught.

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(ssl.SSLError, ValueError):
        ctx.set_alpn_protocols(["h2", "http/1.1"])

    async def _probe() -> ssl.SSLObject | None:
        _reader, writer = await asyncio.open_connection(
            host, port, ssl=ctx, server_hostname=None
        )
        try:
            return writer.get_extra_info("ssl_object")
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    try:
        sslobj = await asyncio.wait_for(_probe(), timeout=HARD_TIMEOUT)
    except (ssl.SSLError, ConnectionResetError) as exc:
        # Handshake rejected: almost always a plaintext port.
        data = {"tls": False, "note": sanitize(str(exc), 200)}
        excerpt = sanitize(
            f"{host}:{port} no TLS (handshake failed: {exc})", EXCERPT_LIMIT
        )
        return ToolResult(ok=True, data=data, excerpt=excerpt)
    except Exception as exc:  # noqa: BLE001 — spec: any network error -> failure
        return ToolResult.failure(str(exc) or type(exc).__name__)

    data: dict[str, Any] = {"tls": sslobj is not None}
    alpn = ""
    if sslobj is not None:
        with contextlib.suppress(Exception):
            alpn = sslobj.selected_alpn_protocol() or ""
        with contextlib.suppress(Exception):
            data.update(_decode_cert(sslobj.getpeercert(binary_form=True)))
    data.setdefault("cert_subject", "")
    data.setdefault("cert_issuer", "")
    data.setdefault("cert_not_after", "")
    data["alpn"] = alpn
    excerpt = sanitize(
        f"{host}:{port} TLS yes subject={data['cert_subject']!r} "
        f"issuer={data['cert_issuer']!r} not_after={data['cert_not_after']!r} "
        f"alpn={alpn!r}",
        EXCERPT_LIMIT,
    )
    return ToolResult(ok=True, data=data, excerpt=excerpt)


TOOL = Tool(
    name="tls_hello",
    description="Attempt a TLS handshake; report cert subject/issuer/expiry and ALPN.",
    args_schema={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "port": {"type": "integer"},
        },
        "required": ["host", "port"],
    },
    run=run,
)
