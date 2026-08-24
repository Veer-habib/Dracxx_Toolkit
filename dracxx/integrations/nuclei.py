"""nuclei adapter - template-based vulnerability DETECTION only.
Only 'exposure', 'misconfiguration', 'vulnerability'-detection, 'cve' and
'technologies' template tags are used for identification; no intrusive
or exploit-tagged templates are ever executed."""
from __future__ import annotations
import json
from typing import List, Dict
from dracxx.integrations.base import ToolAdapter

SAFE_TAGS = "cve,exposure,misconfig,tech,default-login-detect,ssl"
EXCLUDED_TAGS = "dos,fuzz,intrusive,rce-exec"


class NucleiAdapter(ToolAdapter):
    binary_name = "nuclei"
    display_name = "Nuclei"

    async def scan(self, target: str, severity: str = "") -> List[Dict]:
        args = ["-u", target, "-jsonl", "-silent", "-tags", SAFE_TAGS, "-etags", EXCLUDED_TAGS]
        if severity:
            args += ["-severity", severity]
        r = await self.run(args, timeout=600)
        if not r.ok or not r.stdout:
            return []
        out = []
        for line in r.stdout.strip().splitlines():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
