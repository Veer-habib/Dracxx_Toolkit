"""Base class for all external tool adapters. Graceful degradation if a
tool binary is missing -- DRACXX must never crash because an optional
tool is absent."""
from __future__ import annotations

import asyncio
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ToolResult:
    tool: str
    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None
    skipped_reason: Optional[str] = None


class ToolAdapter:
    """Subclass per external tool. All adapters are read-only / detection
    only. No adapter here may issue exploit, brute-force, or destructive
    commands. EXPLOITATION: DISABLED."""

    binary_name: str = ""
    display_name: str = ""
    optional: bool = True

    def is_installed(self) -> bool:
        return shutil.which(self.binary_name) is not None

    def version(self) -> Optional[str]:
        if not self.is_installed():
            return None
        try:
            out = subprocess.run(
                [self.binary_name, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            return (out.stdout or out.stderr).strip().splitlines()[0]
        except Exception:
            return None

    async def run(self, args: List[str], timeout: int = 60) -> ToolResult:
        if not self.is_installed():
            return ToolResult(
                tool=self.binary_name, ok=False,
                skipped_reason=f"{self.display_name or self.binary_name} not installed",
            )
        cmd = [self.binary_name] + args
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                return ToolResult(tool=self.binary_name, ok=False, skipped_reason="timeout")
            return ToolResult(
                tool=self.binary_name,
                ok=proc.returncode == 0,
                stdout=stdout.decode(errors="ignore"),
                stderr=stderr.decode(errors="ignore"),
                returncode=proc.returncode,
            )
        except FileNotFoundError:
            return ToolResult(tool=self.binary_name, ok=False, skipped_reason="binary not found")
        except Exception as e:
            return ToolResult(tool=self.binary_name, ok=False, skipped_reason=str(e))
