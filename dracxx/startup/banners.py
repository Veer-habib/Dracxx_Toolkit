"""Randomized cosmetic startup banners. Randomization NEVER affects
target, scope, scan safety, or security logic -- purely visual."""
from __future__ import annotations

import random
import string
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

BANNERS = [
r"""
╔════════════════════════════════════════════╗
║                 D R A C X X                 ║
║                                              ║
║   AI RECONNAISSANCE & VULNERABILITY ENGINE  ║
║                                              ║
║               MADE BY DRACXX                ║
╚════════════════════════════════════════════╝
""",
r"""
   ____  ____   _    ______  __  __
  |  _ \|  _ \ / \  / ___\ \/ /_ \
  | | | | |_) / _ \| |    \  / \ \/
  | |_| |  _ < ___ \ |___ /  \_/\ \
  |____/|_| \_\_/ \_\____/_/\_\ \_/

     RECON . INTEL . RISK . REPORT
          MADE BY DRACXX
""",
r"""
[ D R A C X X ]────────────────────────────
   >> AI-Driven Recon & Vuln Intelligence
   >> Passive & Active Reconnaissance
   >> CVE / CPE / CVSS / EPSS / KEV Fusion
   >> MADE BY DRACXX
────────────────────────────────────────────
""",
r"""
     .:: DRACXX ::.
   ╭──────────────────────╮
   │  RECON INTELLIGENCE   │
   │  VULNERABILITY ENGINE │
   │  MADE BY DRACXX       │
   ╰──────────────────────╯
""",
r"""
#############################################
#   D R A C X X   S E C U R I T Y   C O N   #
#   Reconnaissance | Intelligence | Risk    #
#              MADE BY DRACXX               #
#############################################
""",
]

TAGLINES = [
    "Precision reconnaissance. Zero exploitation.",
    "Intelligence before action.",
    "See everything. Exploit nothing.",
    "Recon-driven risk intelligence.",
    "Know the surface. Own the intel.",
]

TIPS = [
    "Tip: use 'dracxx-vuln doctor' to verify tool/API availability.",
    "Tip: scan profiles range from PASSIVE to DEEP — start light.",
    "Tip: EPSS estimates exploitation likelihood, not proof.",
    "Tip: CISA KEV membership always boosts risk priority.",
    "Tip: use 'console' for an interactive Metasploit-style workflow.",
]

LOADING_STEPS = [
    "Recon Engine",
    "Vulnerability Engine",
    "CVE Intelligence",
    "AI Engine",
    "Reporting Engine",
]


def _session_id() -> str:
    date = datetime.utcnow().strftime("%Y%m%d")
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"DRX-{date}-{suffix}"


def render_startup(console: Console) -> str:
    banner = random.choice(BANNERS)
    tagline = random.choice(TAGLINES)
    tip = random.choice(TIPS)
    session_id = _session_id()

    console.print(Text(banner, style="bold magenta"))
    console.print(Text(f"  {tagline}", style="italic cyan"))
    console.print()
    for step in LOADING_STEPS:
        console.print(f"[+] {step:.<32} [bold green]OK[/bold green]")
    console.print()
    console.print(f"[bold]Session:[/bold] {session_id}")
    console.print("[bold red]Exploitation: DISABLED[/bold red]")
    console.print(f"[dim]{tip}[/dim]\n")
    return session_id
