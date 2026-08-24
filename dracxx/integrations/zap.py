"""OWASP ZAP adapter - passive/baseline scanning via zap-baseline.py style
invocation. Active-attack ZAP modes are never enabled."""
from __future__ import annotations
from dracxx.integrations.base import ToolAdapter


class ZapAdapter(ToolAdapter):
    binary_name = "zap-baseline.py"
    display_name = "OWASP ZAP (baseline)"

    async def scan(self, url: str) -> str:
        r = await self.run(["-t", url, "-J", "-"], timeout=600)
        return r.stdout if r.ok else ""
