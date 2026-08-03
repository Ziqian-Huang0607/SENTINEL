"""Pure validation helpers for operator input.

Kept free of Qt imports so the scope gate and target validation logic can be
unit-tested without instantiating a QApplication.
"""

from __future__ import annotations

import ipaddress

CONFIRM_PHRASE = "CONFIRM"
LEGAL_NOTICE = "Authorized security testing only."


def validate_confirm(text: str) -> bool:
    """Return True only when the operator typed exactly ``CONFIRM``.

    Mirrors the CLI scope gate: the match is exact and case-sensitive.
    """
    return text == CONFIRM_PHRASE


def validate_target(text: str) -> bool:
    """Return True when ``text`` is a valid IPv4/IPv6 CIDR or single address.

    Single addresses are accepted and treated as a /32 (or /128) scope,
    matching the scanner's scope parser.
    """
    candidate = text.strip()
    if not candidate:
        return False
    try:
        ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        return False
    return True


def normalize_target(text: str) -> str:
    """Return the canonical network form of a validated target string."""
    return str(ipaddress.ip_network(text.strip(), strict=False))


def cvss_severity(cvss: float) -> str:
    """Map a CVSS base score to a severity label used for color coding."""
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0.0:
        return "low"
    return "none"
