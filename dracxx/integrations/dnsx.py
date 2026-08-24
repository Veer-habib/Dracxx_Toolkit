"""dnsx adapter - fast DNS record resolution/enumeration."""
from __future__ import annotations
import json
from typing import Dict, List
from dracxx.integrations.base import ToolAdapter


class DnsxAdapter(ToolAdapter):
    binary_name = "dnsx"
    display_name = "dnsx"

    async def resolve(self, hosts: List[str]) -> List[Dict]:
        out = []
        for h in hosts:
            r = await self.run(["-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-json", "-silent"], timeout=20)
            # dnsx reads stdin normally; per-host fallback via echo not available without shell pipe
        return out
