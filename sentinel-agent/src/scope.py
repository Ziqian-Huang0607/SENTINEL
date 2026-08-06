"""Scope guard — the sacred safety rule (agent-spec.md section 5).

Every tool executor receives a Scope and MUST refuse targets outside it.
The set of in-scope IPs comes from scan.json — i.e. exactly what the operator
confirmed at the CONFIRM gate. Even if the LLM asks for an out-of-scope host,
the tool raises ScopeViolation. Loopback and RFC1918 only, matching the
scanner's scope rules.
"""

from __future__ import annotations

import ipaddress

_PRIVATE_NETWORKS = [
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")
]


class ScopeViolation(Exception):
    """Raised when a tool is asked to touch an out-of-scope host."""


class Scope:
    """The confirmed set of in-scope IP addresses."""

    def __init__(self, ips: list[str] | set[str] | frozenset[str]):
        self._ips: frozenset[str] = frozenset(str(ip) for ip in ips)

    def __contains__(self, ip: str) -> bool:
        return ip in self._ips

    def __len__(self) -> int:
        return len(self._ips)

    @property
    def ips(self) -> frozenset[str]:
        return self._ips

    @staticmethod
    def is_private_or_loopback(ip: str) -> bool:
        """True for RFC1918 and loopback addresses (scanner scope rules)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in _PRIVATE_NETWORKS)

    def check(self, host: str) -> None:
        """Raise ScopeViolation unless host is in-scope and private/loopback."""
        if host not in self._ips:
            raise ScopeViolation(f"{host} is outside the confirmed scan scope")
        if not self.is_private_or_loopback(host):
            raise ScopeViolation(f"{host} is not a private or loopback address")

    @classmethod
    def from_scan(cls, scan: dict) -> Scope:
        """Build the scope from a scan.json document (its discovered hosts)."""
        return cls({host["ip"] for host in scan.get("hosts", [])})
