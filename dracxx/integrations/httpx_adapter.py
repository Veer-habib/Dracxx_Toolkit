"""httpx (projectdiscovery) adapter - web fingerprinting, status, title, tech."""
from __future__ import annotations

import json
from typing import List

from dracxx.integrations.base import ToolAdapter
from dracxx.models.schema import WebEndpoint


class HttpxAdapter(ToolAdapter):
    binary_name = "httpx"
    display_name = "httpx"

    async def probe(self, targets: List[str]) -> List[WebEndpoint]:
        args = ["-silent", "-json", "-title", "-tech-detect", "-status-code", "-follow-redirects"]
        result = await self.run(["-l", "/dev/stdin"] + args, timeout=120) if len(targets) > 1 else None
        # Fallback: run per-target if stdin piping isn't practical in this environment
        out: List[WebEndpoint] = []
        for t in targets:
            r = await self.run([t] + args, timeout=30)
            if not r.ok or not r.stdout:
                continue
            for line in r.stdout.strip().splitlines():
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                out.append(WebEndpoint(
                    url=d.get("url", t),
                    status_code=d.get("status_code"),
                    title=d.get("title"),
                    technologies=d.get("tech", []) or [],
                    headers=d.get("header", {}) or {},
                    source="httpx",
                ))
        return out
