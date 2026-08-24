"""ffuf adapter - content discovery. Read-only enumeration, no destructive
payloads, no auth bypass fuzzing."""
from __future__ import annotations
import json
from typing import List, Dict
from dracxx.integrations.base import ToolAdapter


class FfufAdapter(ToolAdapter):
    binary_name = "ffuf"
    display_name = "ffuf"

    async def discover(self, url: str, wordlist: str, extensions: str = "") -> List[Dict]:
        target = url.rstrip("/") + "/FUZZ"
        args = ["-u", target, "-w", wordlist, "-of", "json", "-o", "-", "-s"]
        if extensions:
            args += ["-e", extensions]
        r = await self.run(args, timeout=300)
        if not r.ok or not r.stdout:
            return []
        try:
            data = json.loads(r.stdout)
            return data.get("results", [])
        except json.JSONDecodeError:
            return []
