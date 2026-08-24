"""nikto adapter - web server safe misconfiguration scanning."""
from __future__ import annotations
from dracxx.integrations.base import ToolAdapter


class NiktoAdapter(ToolAdapter):
    binary_name = "nikto"
    display_name = "Nikto"

    async def scan(self, url: str) -> str:
        r = await self.run(["-h", url, "-Format", "txt", "-output", "-"], timeout=300)
        return r.stdout if r.ok else ""
