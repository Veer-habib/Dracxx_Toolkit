"""nuclei adapter - template-based vulnerability DETECTION only.
Only safe tags are used; intrusive/exploit templates are never executed.
Supports fast mode for quick scans.
"""
from __future__ import annotations
import json
from typing import List, Dict
from dracxx.integrations.base import ToolAdapter

SAFE_TAGS = "cve,exposure,misconfig,tech,default-login-detect,ssl"
EXCLUDED_TAGS = "dos,fuzz,intrusive,rce-exec"


class NucleiAdapter(ToolAdapter):
    binary_name = "nuclei"
    display_name = "Nuclei"

    async def scan(
        self,
        target: str,
        severity: str = "",
        fast: bool = False,
        timeout: int | None = None,
    ) -> List[Dict]:
        """Run nuclei detection scan.

        fast=True → critical,high,medium only + shorter timeout + rate limit
        """
        args = [
            "-u", target,
            "-jsonl",
            "-silent",
            "-tags", SAFE_TAGS,
            "-etags", EXCLUDED_TAGS,
            "-no-color",
        ]
        if fast:
            # Quick pass: higher severity only, limited concurrency
            args += ["-severity", severity or "critical,high,medium"]
            args += ["-c", "25", "-rl", "150"]
            timeout = timeout or 120
        else:
            if severity:
                args += ["-severity", severity]
            args += ["-c", "50", "-rl", "300"]
            timeout = timeout or 300

        r = await self.run(args, timeout=timeout)
        if not r.ok or not r.stdout:
            return []
        out = []
        for line in r.stdout.strip().splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
