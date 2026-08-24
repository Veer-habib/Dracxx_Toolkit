"""katana adapter - web crawler for URL/endpoint discovery (passive crawling only)."""
from __future__ import annotations
from typing import List
from dracxx.integrations.base import ToolAdapter


class KatanaAdapter(ToolAdapter):
    binary_name = "katana"
    display_name = "Katana"

    async def crawl(self, url: str, depth: int = 2) -> List[str]:
        r = await self.run(["-u", url, "-d", str(depth), "-silent", "-jc"], timeout=180)
        if not r.ok or not r.stdout:
            return []
        return sorted(set(l.strip() for l in r.stdout.splitlines() if l.strip()))
