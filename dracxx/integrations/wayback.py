"""waybackurls / gau adapter — historical URL discovery (passive, read-only)."""
from __future__ import annotations
from typing import List
from dracxx.integrations.base import ToolAdapter


class WaybackAdapter(ToolAdapter):
    """Prefer waybackurls; fall back to gau if available."""
    binary_name = "waybackurls"
    display_name = "waybackurls"

    def is_installed(self) -> bool:
        import shutil
        return shutil.which("waybackurls") is not None or shutil.which("gau") is not None

    async def fetch(self, domain: str, limit: int = 200) -> List[str]:
        import shutil
        urls: List[str] = []
        if shutil.which("waybackurls"):
            # waybackurls reads domain from stdin
            r = await self._run_stdin("waybackurls", domain, timeout=90)
            if r:
                urls.extend(r)
        elif shutil.which("gau"):
            from dracxx.integrations.base import ToolAdapter as TA
            # use gau as one-shot
            import asyncio, shutil as sh
            proc = await asyncio.create_subprocess_exec(
                "gau", domain, "--subs",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
                urls.extend(out.decode(errors="ignore").splitlines())
            except Exception:
                pass
        cleaned = []
        for u in urls:
            u = u.strip()
            if u.startswith("http") and domain in u:
                cleaned.append(u)
            if len(cleaned) >= limit:
                break
        return sorted(set(cleaned))

    async def _run_stdin(self, binary: str, data: str, timeout: int = 90) -> List[str]:
        import asyncio
        try:
            proc = await asyncio.create_subprocess_exec(
                binary,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await asyncio.wait_for(
                proc.communicate(input=data.encode()), timeout=timeout
            )
            return [l.strip() for l in out.decode(errors="ignore").splitlines() if l.strip()]
        except Exception:
            return []
