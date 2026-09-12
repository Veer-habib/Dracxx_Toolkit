"""dnsx adapter - fast DNS record resolution."""
from __future__ import annotations
import asyncio
import json
import tempfile
from pathlib import Path
from typing import Dict, List
from dracxx.integrations.base import ToolAdapter


class DnsxAdapter(ToolAdapter):
    binary_name = "dnsx"
    display_name = "dnsx"

    async def resolve(self, hosts: List[str]) -> List[Dict]:
        if not self.is_installed() or not hosts:
            return []
        out: List[Dict] = []
        # Write hosts to temp list file
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
                fh.write("\n".join(hosts[:500]))
                path = fh.name
            r = await self.run(
                ["-l", path, "-a", "-aaaa", "-cname", "-resp", "-json", "-silent"],
                timeout=120,
            )
            Path(path).unlink(missing_ok=True)
            if not r.ok or not r.stdout:
                return []
            for line in r.stdout.splitlines():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        except Exception:
            return []
        return out
