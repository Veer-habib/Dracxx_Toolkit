"""amass adapter - passive OSINT asset/subdomain enumeration."""
from __future__ import annotations
from typing import List
from dracxx.integrations.base import ToolAdapter


class AmassAdapter(ToolAdapter):
    binary_name = "amass"
    display_name = "Amass"

    async def enumerate(self, domain: str, passive: bool = True) -> List[str]:
        args = ["enum", "-passive" if passive else "-active", "-d", domain, "-silent"]
        r = await self.run(args, timeout=300)
        if not r.ok or not r.stdout:
            return []
        return sorted(set(l.strip() for l in r.stdout.splitlines() if l.strip()))
