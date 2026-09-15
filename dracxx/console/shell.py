"""DRACXX interactive security console — Metasploit-style workflow feel,
original DRACXX branding and functionality."""
from __future__ import annotations

import asyncio
import cmd
import shlex

from rich.console import Console

from dracxx.config.config import ensure_config, load_config
from dracxx.core.scope import build_scope_from_targets
from dracxx.core.workflow import WorkflowEngine
from dracxx.database.db import init_db
from dracxx.models.schema import ScanProfile
from dracxx.reporting import report as reporting
from dracxx.startup.banners import render_startup

console = Console()

HELP_TEXT = """
DRACXX Console Commands:
  help                    Show this help
  status                  Show session status
  set target <t>          Set current target
  set profile <p>         Set scan profile (PASSIVE/LIGHT/STANDARD/DEEP)
  show target             Show current target
  show profile            Show current profile
  recon                   Run recon against current target
  scan                    Run vulnerability scan against current target
  workflow                Run full automated workflow
  cve <product> [version] Look up CVE correlation
  findings [summary]      Show detailed findings (or summary counts only)
  tools                   Show tool availability
  doctor                  Run system health checks
  config                  Show config path
  history                 Show scan session history
  ai <question>           Ask the AI engine about current findings
  exit / quit             Exit the console
"""


class DracxxShell(cmd.Cmd):
    intro = ""
    prompt = "dracxx > "

    def __init__(self):
        super().__init__()
        self.target = None
        self.profile = ScanProfile.STANDARD
        self.last_findings = []
        self.cfg = load_config()

    def do_help(self, arg):
        console.print(HELP_TEXT)

    def do_status(self, arg):
        console.print(f"Target: {self.target}\nProfile: {self.profile.value}\n"
                       f"Findings cached: {len(self.last_findings)}\nExploitation: DISABLED")

    def do_set(self, arg):
        parts = shlex.split(arg)
        if len(parts) < 2:
            console.print("Usage: set target <t> | set profile <p>")
            return
        key, value = parts[0], parts[1]
        if key == "target":
            self.target = value
            console.print(f"Target set: {value}")
        elif key == "profile":
            try:
                self.profile = ScanProfile(value.upper())
                console.print(f"Profile set: {self.profile.value}")
            except ValueError:
                console.print("Invalid profile. Use PASSIVE/LIGHT/STANDARD/DEEP/CUSTOM")
        else:
            console.print(f"Unknown key: {key}")

    def do_show(self, arg):
        if arg.strip() == "target":
            console.print(self.target or "(none)")
        elif arg.strip() == "profile":
            console.print(self.profile.value)
        else:
            console.print("Usage: show target | show profile")

    def _check_target(self) -> bool:
        if not self.target:
            console.print("[red]No target set. Use 'set target <t>' first.[/red]")
            return False
        scope = build_scope_from_targets([self.target])
        if not scope.is_target_allowed(self.target):
            console.print("[red]Target not in authorized scope.[/red]")
            return False
        return True

    def do_recon(self, arg):
        if not self._check_target():
            return
        from dracxx.integrations.subfinder import SubfinderAdapter
        from dracxx.integrations.nmap import NmapAdapter

        async def _run():
            sub = SubfinderAdapter()
            subs = await sub.enumerate(self.target) if sub.is_installed() else []
            console.print(f"Subdomains: {len(subs)}")
            nmap = NmapAdapter()
            if nmap.is_installed():
                ports = await nmap.scan(self.target, deep=(self.profile == ScanProfile.DEEP))
                console.print(f"Open ports: {len(ports)}")
                for p in ports:
                    console.print(f"  {p.port}/{p.protocol} {p.product or ''} {p.version or ''}")
            else:
                console.print("[!] nmap unavailable")

        asyncio.run(_run())

    def do_scan(self, arg):
        if not self._check_target():
            return
        from dracxx.integrations.nuclei import NucleiAdapter
        nuclei = NucleiAdapter()
        if not nuclei.is_installed():
            console.print("[!] nuclei unavailable")
            return

        async def _run():
            results = await nuclei.scan(self.target)
            console.print(f"Detections: {len(results)}")

        asyncio.run(_run())

    def do_workflow(self, arg):
        if not self._check_target():
            return

        def progress(msg):
            console.print(f"[cyan]{msg}[/cyan]")

        engine = WorkflowEngine(self.cfg, progress_cb=progress)
        self.last_findings = asyncio.run(engine.run(self.target, self.profile))
        console.print(reporting.to_terminal_summary(self.last_findings))
        console.print()
        console.print(reporting.to_terminal_detail(self.last_findings))
        # Persist for CLI report/findings commands
        self._save_findings_to_db()

    def do_cve(self, arg):
        parts = shlex.split(arg)
        if not parts:
            console.print("Usage: cve <product> [version]")
            return
        product = parts[0]
        version = parts[1] if len(parts) > 1 else None
        from dracxx.engines.cve.engine import CVEIntelligenceEngine
        eng = CVEIntelligenceEngine(nvd_api_key=self.cfg.apis.get("nvd_api_key", ""))
        matches = asyncio.run(eng.correlate(product, version))
        if not matches:
            console.print("No matches found.")
            return
        for m in matches:
            console.print(f"{m.cve_id} | {m.match_status} | CVSS {m.cvss_score} | EPSS {m.epss_score} | KEV {m.kev}")

    def do_findings(self, arg):
        if not self.last_findings:
            console.print("No findings cached — run 'workflow' first.")
            return
        mode = (arg or "").strip().lower()
        if mode in ("summary", "sum", "s"):
            console.print(reporting.to_terminal_summary(self.last_findings))
        else:
            # Full detail by default
            console.print(reporting.to_terminal_detail(self.last_findings))

    def do_tools(self, arg):
        from dracxx.cli.main import ALL_ADAPTERS
        for a in ALL_ADAPTERS:
            mark = "✓" if a.is_installed() else "✗"
            console.print(f"  [{mark}] {a.display_name or a.binary_name}")

    def do_doctor(self, arg):
        from dracxx.cli.main import doctor as doctor_cmd
        try:
            doctor_cmd()
        except SystemExit:
            pass

    def do_config(self, arg):
        from dracxx.config.config import CONFIG_PATH
        console.print(str(CONFIG_PATH))

    def do_history(self, arg):
        from dracxx.database.db import get_session, ScanSessionRow
        session = get_session()
        try:
            rows = session.query(ScanSessionRow).order_by(ScanSessionRow.started_at.desc()).limit(10).all()
            for r in rows:
                console.print(f"{r.session_id}  {r.target}  {r.profile}  {r.started_at}")
            if not rows:
                console.print("No history yet.")
        finally:
            session.close()

    def do_ai(self, arg):
        if not arg.strip():
            console.print("Usage: ai <question>")
            return
        from dracxx.providers.ai import build_provider
        provider = build_provider(self.cfg.ai)
        payload = [f.model_dump() for f in self.last_findings] if self.last_findings else []

        async def _run():
            answer = await provider.analyze(payload, arg)
            console.print(answer)

        asyncio.run(_run())


    def _save_findings_to_db(self):
        """Persist last_findings so CLI report/findings can use them."""
        if not self.last_findings:
            return
        import json
        from dracxx.database.db import get_session, FindingRow
        session = get_session()
        try:
            for f in self.last_findings:
                row = FindingRow(
                    session_id="console",
                    finding_id=f.finding_id,
                    title=f.title,
                    severity=f.severity.value,
                    confidence=f.confidence.value,
                    target=f.target,
                    asset=f.asset,
                    port=f.port,
                    protocol=f.protocol,
                    technology=f.technology,
                    version=f.version,
                    cpe=f.cpe,
                    cwe=f.cwe,
                    evidence=f.evidence,
                    scanner=f.scanner,
                    references_json=json.dumps(f.references or []),
                    remediation=f.remediation,
                    cves_json=json.dumps([c.model_dump() for c in (f.cves or [])], default=str),
                    risk_score=f.risk_score,
                )
                session.add(row)
            session.commit()
            console.print(f"[dim]Saved {len(self.last_findings)} finding(s) to database.[/dim]")
        except Exception as e:
            console.print(f"[dim]Could not persist findings: {e}[/dim]")
        finally:
            session.close()

    def do_exit(self, arg):
        console.print("Exiting DRACXX console.")
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

    def default(self, line):
        console.print(f"Unknown command: {line}. Type 'help' for commands.")


def run_console():
    ensure_config()
    init_db()
    session_id = render_startup(console)
    console.print(f"[dim]Type 'help' to see available commands.[/dim]\n")
    DracxxShell().cmdloop()
