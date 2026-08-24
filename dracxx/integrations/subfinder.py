"""subfinder adapter - passive subdomain enumeration."""
from __future__ import annotations
from typing import List
from dracxx.integrations.base import ToolAdapter


class SubfinderAdapter(ToolAdapter):
    binary_name = "subfinder"
    display_name = "Subfinder"

    async def enumerate(self, domain: str) -> List[str]:
        r = await self.run(["-d", domain, "-silent"], timeout=120)
        if not r.ok or not r.stdout:
            return []
        return sorted(set(l.strip() for l in r.stdout.splitlines() if l.strip()))
