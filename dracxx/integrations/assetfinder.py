"""assetfinder adapter - passive subdomain discovery."""
from __future__ import annotations
from typing import List
from dracxx.integrations.base import ToolAdapter


class AssetfinderAdapter(ToolAdapter):
    binary_name = "assetfinder"
    display_name = "Assetfinder"

    async def enumerate(self, domain: str) -> List[str]:
        r = await self.run(["--subs-only", domain], timeout=90)
        if not r.ok or not r.stdout:
            return []
        return sorted(set(l.strip() for l in r.stdout.splitlines() if l.strip()))
