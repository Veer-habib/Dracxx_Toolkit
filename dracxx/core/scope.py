"""Strict scope control. Never expands beyond authorized targets."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List

_DOMAIN_RE = re.compile(r"^(\*\.)?([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")


@dataclass
class Scope:
    allowed_domains: List[str] = field(default_factory=list)
    allowed_cidrs: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    confirmed: bool = False

    def is_domain_allowed(self, domain: str) -> bool:
        domain = domain.lower().strip().rstrip(".")
        if any(domain == e or domain.endswith("." + e) for e in self.exclusions):
            return False
        for allowed in self.allowed_domains:
            allowed = allowed.lower().lstrip("*.")
            if domain == allowed or domain.endswith("." + allowed):
                return True
        return False

    def is_ip_allowed(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if ip in self.exclusions:
            return False
        for cidr in self.allowed_cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def is_target_allowed(self, target: str) -> bool:
        target = target.strip()
        # CIDR
        try:
            ipaddress.ip_network(target, strict=False)
            return any(
                ipaddress.ip_network(target, strict=False).subnet_of(
                    ipaddress.ip_network(c, strict=False)
                )
                for c in self.allowed_cidrs
            )
        except ValueError:
            pass
        # Single IP
        try:
            ipaddress.ip_address(target)
            return self.is_ip_allowed(target)
        except ValueError:
            pass
        # URL -> extract host
        m = re.match(r"^[a-zA-Z]+://([^/]+)", target)
        host = m.group(1).split(":")[0] if m else target
        if _DOMAIN_RE.match(host):
            return self.is_domain_allowed(host)
        return False


def build_scope_from_targets(targets: List[str]) -> Scope:
    """Auto-derive a scope object from explicitly provided targets (self-authorized)."""
    domains, cidrs = [], []
    for t in targets:
        t = t.strip()
        try:
            import ipaddress as ip
            ip.ip_network(t, strict=False)
            cidrs.append(t)
            continue
        except ValueError:
            pass
        # Extract host from URL so https://example.com/path scopes correctly
        m = re.match(r"^[a-zA-Z]+://([^/]+)", t)
        if m:
            host = m.group(1).split(":")[0]
            domains.append(host)
        else:
            domains.append(t)
    return Scope(allowed_domains=domains, allowed_cidrs=cidrs, confirmed=True)
