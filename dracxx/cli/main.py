"""DRACXX CLI - Typer based entrypoint."""
from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from dracxx import __version__
from dracxx.config.config import ensure_config, load_config
from dracxx.core.scope import build_scope_from_targets
from dracxx.core.workflow import WorkflowEngine
from dracxx.database.db import init_db, get_session, ScanSessionRow, FindingRow
from dracxx.integrations.amass import AmassAdapter
from dracxx.integrations.assetfinder import AssetfinderAdapter
from dracxx.integrations.ffuf import FfufAdapter
from dracxx.integrations.httpx_adapter import HttpxAdapter
from dracxx.integrations.katana import KatanaAdapter
from dracxx.integrations.naabu import NaabuAdapter
from dracxx.integrations.nikto import NiktoAdapter
from dracxx.integrations.nmap import NmapAdapter
from dracxx.integrations.nuclei import NucleiAdapter
from dracxx.integrations.subfinder import SubfinderAdapter
from dracxx.integrations.testssl import TestSSLAdapter
from dracxx.integrations.zap import ZapAdapter
from dracxx.models.schema import ScanProfile
from dracxx.reporting import report as reporting
from dracxx.startup.banners import render_startup

app = typer.Typer(help="DRACXX — AI-Driven Reconnaissance & Vulnerability Intelligence Framework")
console = Console()

ALL_ADAPTERS = [
    NmapAdapter(), NucleiAdapter(), SubfinderAdapter(), AmassAdapter(),
    AssetfinderAdapter(), HttpxAdapter(), KatanaAdapter(), FfufAdapter(),
    NiktoAdapter(), TestSSLAdapter(), NaabuAdapter(), ZapAdapter(),
]


def _version_callback(value: bool):
    if value:
        console.print(f"DRACXX v{__version__} — MADE BY DRACXX")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(None, "--version", callback=_version_callback, is_eager=True),
):
    ensure_config()
    init_db()
    if ctx.invoked_subcommand is None:
        render_startup(console)
        console.print("Run 'dracxx-vuln --help' for commands, or 'dracxx-vuln console' for the interactive shell.")


@app.command()
def recon(target: str, profile: ScanProfile = ScanProfile.STANDARD):
    """Run passive+active reconnaissance only (no vuln scanning)."""
    scope = build_scope_from_targets([target])
    if not scope.is_target_allowed(target):
        console.print("[red]Target not in authorized scope.[/red]")
        raise typer.Exit(1)
    console.print(f"[bold]Recon:[/bold] {target} (profile={profile.value})")

    async def _run():
        sub = SubfinderAdapter()
        subs = await sub.enumerate(target) if sub.is_installed() else []
        console.print(f"Subdomains found: {len(subs)}")
        for s in subs[:20]:
            console.print(f"  - {s}")
        nmap = NmapAdapter()
        if nmap.is_installed():
            ports = await nmap.scan(target, deep=(profile == ScanProfile.DEEP))
            console.print(f"Open ports: {len(ports)}")
            for p in ports:
                console.print(f"  - {p.port}/{p.protocol} {p.service or ''} {p.product or ''} {p.version or ''}")
        else:
            console.print("[!] nmap not installed, skipping port scan")

    asyncio.run(_run())


@app.command()
def scan(
    target: str,
    fast: bool = typer.Option(True, "--fast/--full", help="Fast = critical/high/medium only (default)"),
    output: Optional[Path] = typer.Option(None, help="Optional JSON output path"),
    ai: bool = typer.Option(False, "--ai", help="Run AI analysis on findings after scan"),
    limit: int = typer.Option(50, help="Max findings to print"),
):
    """Vulnerability scan with full detail (Nuclei safe templates only)."""
    from dracxx.core.scope import build_scope_from_targets
    from rich.panel import Panel
    from rich.markdown import Markdown

    scope = build_scope_from_targets([target])
    if not scope.is_target_allowed(target):
        console.print("[red]Target not in authorized scope.[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Vulnerability scan:[/bold] {target}  ({'FAST' if fast else 'FULL'})")
    nuclei = NucleiAdapter()
    if not nuclei.is_installed():
        console.print("[!] nuclei not installed — cannot run vulnerability scan")
        raise typer.Exit(1)

    async def _run():
        results = await nuclei.scan(target, fast=fast)
        console.print(f"[green]Detections: {len(results)}[/green]\n")

        for i, r in enumerate(results[:limit], 1):
            info = r.get("info", {}) if isinstance(r, dict) else {}
            sev = str(info.get("severity", "info")).upper()
            name = info.get("name", "Unknown finding")
            desc = (info.get("description") or "").strip()
            matched = r.get("matched-at") or r.get("host") or r.get("url") or target
            template_id = r.get("template-id") or r.get("templateID") or ""
            curl = r.get("curl-command") or ""
            refs = info.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]
            classification = info.get("classification") or {}
            cve_list = classification.get("cve-id") or info.get("cve-id") or []
            if isinstance(cve_list, str):
                cve_list = [cve_list]
            remediation = info.get("remediation") or ""

            sev_color = {
                "CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow",
                "LOW": "blue", "INFO": "dim",
            }.get(sev, "white")

            console.print(Panel.fit(
                f"[bold]{name}[/bold]",
                title=f"[{sev_color}]#{i} {sev}[/{sev_color}]",
                border_style="cyan",
            ))
            console.print(f"  [bold]Affected URL:[/bold]  {matched}")
            if template_id:
                console.print(f"  [bold]Template:[/bold]     {template_id}")
            if cve_list:
                console.print(f"  [bold]CVE(s):[/bold]       {', '.join(cve_list)}")
            if desc:
                # truncate very long descriptions
                short = desc if len(desc) <= 500 else desc[:500] + "..."
                console.print(f"  [bold]Description:[/bold]  {short}")
            if remediation:
                console.print(f"  [bold]Remediation:[/bold]  {remediation}")
            if refs:
                console.print(f"  [bold]References:[/bold]   {', '.join(str(x) for x in refs[:5])}")
            if curl:
                console.print(f"  [dim]Evidence curl: {curl[:120]}[/dim]")
            console.print()

        if output:
            import json as _json
            output.write_text(_json.dumps(results, indent=2, default=str))
            console.print(f"[green]Full JSON written to {output}[/green]")

        if ai and results:
            console.print("\n[bold cyan]AI analysis (advisory only)...[/bold cyan]")
            cfg = load_config()
            from dracxx.providers.ai import build_provider
            provider = build_provider(cfg.ai)
            # Feed structured summary to AI
            summary = []
            for r in results[:25]:
                info = r.get("info", {}) if isinstance(r, dict) else {}
                summary.append({
                    "name": info.get("name"),
                    "severity": info.get("severity"),
                    "matched_at": r.get("matched-at") or r.get("host"),
                    "description": (info.get("description") or "")[:300],
                    "cve": (info.get("classification") or {}).get("cve-id"),
                })
            analysis = await provider.analyze(
                summary,
                "Explain each finding briefly, rank by real-world risk, "
                "flag likely false positives, and give a prioritized remediation plan. "
                "Do not suggest exploits or attack commands.",
            )
            console.print(Panel(analysis, title="AI Analysis", border_style="magenta"))

    asyncio.run(_run())


@app.command()
def workflow(target: str, profile: ScanProfile = ScanProfile.STANDARD,
             output: Optional[Path] = typer.Option(None, help="Write JSON report to path")):
    """Run the full automated DRACXX pipeline end-to-end."""
    cfg = load_config()
    scope = build_scope_from_targets([target])
    if not scope.is_target_allowed(target):
        console.print("[red]Target not in authorized scope.[/red]")
        raise typer.Exit(1)

    def progress(msg: str):
        console.print(f"[cyan]{msg}[/cyan]")

    engine = WorkflowEngine(cfg, progress_cb=progress)
    findings = asyncio.run(engine.run(target, profile))

    console.print(reporting.to_terminal_summary(findings))
    console.print()
    console.print(reporting.to_terminal_detail(findings))

    session = get_session()
    try:
        for f in findings:
            row = FindingRow(
                session_id="adhoc", finding_id=f.finding_id, title=f.title,
                severity=f.severity.value, confidence=f.confidence.value,
                target=f.target, asset=f.asset, port=f.port, protocol=f.protocol,
                technology=f.technology, version=f.version, cpe=f.cpe,
                cwe=f.cwe, evidence=f.evidence, scanner=f.scanner,
                references_json=json.dumps(f.references),
                remediation=f.remediation,
                cves_json=json.dumps([c.model_dump() for c in f.cves], default=str),
                risk_score=f.risk_score,
            )
            session.add(row)
        session.commit()
    finally:
        session.close()

    if output:
        meta = {"target": target, "profile": profile.value, "session_id": "adhoc"}
        output.write_text(reporting.to_json(findings, meta))
        console.print(f"Report written to {output}")


@app.command()
def cve(product: str, version: str = typer.Option(None, "--version")):
    """Look up CVE correlation for a product/version."""
    from dracxx.engines.cve.engine import CVEIntelligenceEngine
    cfg = load_config()
    eng = CVEIntelligenceEngine(nvd_api_key=cfg.apis.get("nvd_api_key", ""))
    matches = asyncio.run(eng.correlate(product, version))
    if not matches:
        console.print("No CVE matches found (or product/CPE unrecognized).")
        return
    table = Table(title=f"CVE matches for {product} {version or ''}")
    table.add_column("CVE"); table.add_column("Status"); table.add_column("CVSS")
    table.add_column("EPSS"); table.add_column("KEV")
    for m in matches:
        table.add_row(m.cve_id, m.match_status, str(m.cvss_score), str(m.epss_score), str(m.kev))
    console.print(table)


@app.command()
def assets():
    """List discovered assets from the database."""
    console.print("Asset listing — run a workflow first to populate assets.")


@app.command()
def findings(
    summary: bool = typer.Option(False, "--summary", help="Show counts only"),
    limit: int = typer.Option(50, help="Max findings to load from DB"),
):
    """Show detailed vulnerability findings from the database."""
    from dracxx.models.schema import Finding, Confidence, Severity, CVEMatch
    session = get_session()
    try:
        rows = session.query(FindingRow).order_by(FindingRow.risk_score.desc()).limit(limit).all()
        if not rows:
            console.print("No findings stored yet. Run a workflow or scan first.")
            return
        findings_list = []
        for r in rows:
            try:
                cves = [CVEMatch(**c) for c in json.loads(r.cves_json or "[]")]
            except Exception:
                cves = []
            try:
                conf = Confidence(r.confidence)
            except Exception:
                conf = Confidence.INFO
            try:
                sev = Severity(r.severity)
            except Exception:
                sev = Severity.INFO
            findings_list.append(Finding(
                finding_id=r.finding_id, title=r.title, severity=sev,
                confidence=conf, target=r.target or "", asset=r.asset or "",
                port=r.port, protocol=r.protocol, technology=r.technology,
                version=r.version, cpe=r.cpe, cwe=r.cwe, evidence=r.evidence,
                scanner=r.scanner or "unknown",
                references=json.loads(r.references_json or "[]"),
                remediation=r.remediation, cves=cves, risk_score=r.risk_score,
            ))
        if summary:
            console.print(reporting.to_terminal_summary(findings_list))
        else:
            console.print(reporting.to_terminal_detail(findings_list))
    finally:
        session.close()


@app.command()
def report(fmt: str = typer.Option("markdown", help="json|csv|markdown|html"),
           output: Path = typer.Option(...)):
    """Generate a report from stored findings."""
    from dracxx.models.schema import Finding, Confidence, Severity, CVEMatch
    session = get_session()
    try:
        rows = session.query(FindingRow).all()
    finally:
        session.close()
    findings_list = []
    for r in rows:
        cves = [CVEMatch(**c) for c in json.loads(r.cves_json or "[]")]
        findings_list.append(Finding(
            finding_id=r.finding_id, title=r.title, severity=Severity(r.severity),
            confidence=Confidence(r.confidence), target=r.target, asset=r.asset,
            port=r.port, protocol=r.protocol, technology=r.technology, version=r.version,
            cpe=r.cpe, cwe=r.cwe, evidence=r.evidence, scanner=r.scanner,
            references=json.loads(r.references_json or "[]"), remediation=r.remediation,
            cves=cves, risk_score=r.risk_score,
        ))
    meta = {"target": "multiple", "session_id": "combined", "profile": "N/A"}
    content = {
        "json": reporting.to_json, "csv": lambda f, m: reporting.to_csv(f),
        "markdown": reporting.to_markdown, "html": reporting.to_html,
    }[fmt](findings_list, meta)
    output.write_text(content)
    console.print(f"Report written to {output}")


@app.command()
def modules():
    """List available DRACXX engine modules."""
    mods = ["recon", "network-enum", "web-recon", "vuln-scan", "cve-engine",
            "risk-engine", "ai-engine", "reporting"]
    for m in mods:
        console.print(f"  - {m}")


@app.command()
def tools():
    """Show installed/missing external tool status."""
    table = Table(title="DRACXX Tool Status")
    table.add_column("Tool"); table.add_column("Status")
    for a in ALL_ADAPTERS:
        status = "[green]✓ Installed[/green]" if a.is_installed() else "[red]✗ Missing[/red]"
        table.add_row(a.display_name or a.binary_name, status)
    console.print(table)


@app.command()
def doctor():
    """Run system/dependency/database/API health checks."""
    console.print("[bold]DRACXX Doctor[/bold]")
    import sys
    console.print(f"Python: {sys.version.split()[0]} {'✓' if sys.version_info >= (3, 11) else '✗ (need 3.11+)'}")
    try:
        path = init_db()
        console.print(f"Database: OK ({path})")
    except Exception as e:
        console.print(f"[red]Database error: {e}[/red]")
    cfg_path = ensure_config()
    console.print(f"Config: OK ({cfg_path})")
    cfg = load_config()
    console.print(f"AI mode: {cfg.ai.mode} ({cfg.ai.provider if cfg.ai.mode=='api' else cfg.ai.local_model})")
    console.print("\nExternal tools:")
    for a in ALL_ADAPTERS:
        mark = "✓" if a.is_installed() else "✗ (optional)"
        console.print(f"  [{mark}] {a.display_name or a.binary_name}")
    console.print("\n[bold red]Exploitation: DISABLED (by design)[/bold red]")


@app.command()
def config(show: bool = typer.Option(False, "--show")):
    """View or edit configuration."""
    cfg_path = ensure_config()
    if show:
        console.print(Path(cfg_path).read_text())
    else:
        console.print(f"Config file: {cfg_path}")


@app.command()
def history():
    """Show scan session history."""
    session = get_session()
    try:
        rows = session.query(ScanSessionRow).order_by(ScanSessionRow.started_at.desc()).limit(20).all()
        if not rows:
            console.print("No scan sessions recorded yet.")
            return
        table = Table(title="Scan History")
        table.add_column("Session"); table.add_column("Target"); table.add_column("Profile"); table.add_column("Started")
        for r in rows:
            table.add_row(r.session_id, r.target, r.profile, str(r.started_at))
        console.print(table)
    finally:
        session.close()


@app.command()
def console_cmd():
    """Launch the interactive DRACXX console."""
    from dracxx.console.shell import run_console
    run_console()


app.command(name="console")(console_cmd)


if __name__ == "__main__":
    app()
