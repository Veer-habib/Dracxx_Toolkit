"""testssl.sh adapter - TLS/SSL configuration analysis (non-destructive)."""
from __future__ import annotations
from dracxx.integrations.base import ToolAdapter


class TestSSLAdapter(ToolAdapter):
    binary_name = "testssl.sh"
    display_name = "testssl.sh"

    async def scan(self, host: str) -> str:
        r = await self.run(["--quiet", "--color", "0", host], timeout=180)
        return r.stdout if r.ok else ""
