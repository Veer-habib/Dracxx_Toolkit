"""naabu adapter - fast port discovery (detection only, no exploitation)."""
from __future__ import annotations
from typing import List
from dracxx.integrations.base import ToolAdapter


class NaabuAdapter(ToolAdapter):
    binary_name = "naabu"
    display_name = "naabu"

    async def scan(self, target: str, top_ports: int = 1000) -> List[int]:
        r = await self.run(["-host", target, "-top-ports", str(top_ports), "-silent"], timeout=120)
        if not r.ok or not r.stdout:
            return []
        ports = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if ":" in line:
                try:
                    ports.append(int(line.split(":")[-1]))
                except ValueError:
                    continue
        return sorted(set(ports))
