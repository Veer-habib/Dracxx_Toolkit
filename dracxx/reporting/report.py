"""Multi-format report generation: terminal, JSON, CSV, Markdown, HTML."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import List

from dracxx.models.schema import Finding

BRAND_FOOTER = "DRACXX Security Assessment — MADE BY DRACXX"


def _summary(findings: List[Finding]) -> dict:
    by_sev = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    return by_sev


def to_json(findings: List[Finding], meta: dict) -> str:
    return json.dumps({
        "meta": meta,
        "summary": _summary(findings),
        "findings": [f.model_dump() for f in findings],
        "exploitation": "DISABLED",
        "brand": BRAND_FOOTER,
    }, indent=2, default=str)


def to_csv(findings: List[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["finding_id", "title", "severity", "confidence", "asset", "port",
                      "technology", "version", "cpe", "cves", "risk_score", "scanner"])
    for f in findings:
        writer.writerow([
            f.finding_id, f.title, f.severity.value, f.confidence.value, f.asset,
            f.port or "", f.technology or "", f.version or "", f.cpe or "",
            ";".join(c.cve_id for c in f.cves), f.risk_score or "", f.scanner,
        ])
    return buf.getvalue()


def to_markdown(findings: List[Finding], meta: dict) -> str:
    lines = [
        "# DRACXX Security Assessment",
        "**MADE BY DRACXX**\n",
        f"- Target: {meta.get('target')}",
        f"- Session: {meta.get('session_id')}",
        f"- Profile: {meta.get('profile')}",
        f"- Generated: {datetime.utcnow().isoformat()}Z",
        "- Exploitation: DISABLED\n",
        "## Executive Summary",
        f"Total findings: {len(findings)}",
    ]
    sev = _summary(findings)
    for k, v in sev.items():
        lines.append(f"- {k}: {v}")
    lines.append("\n## Findings\n")
    for f in sorted(findings, key=lambda x: x.risk_score or 0, reverse=True):
        lines.append(f"### [{f.severity.value}] {f.title} ({f.finding_id})")
        lines.append(f"- Asset: {f.asset}  Port: {f.port or 'N/A'}")
        lines.append(f"- Technology: {f.technology or 'N/A'} {f.version or ''}")
        lines.append(f"- Confidence: {f.confidence.value}")
        lines.append(f"- Risk score: {f.risk_score}")
        if f.cves:
            for c in f.cves:
                lines.append(f"  - {c.cve_id} | CVSS {c.cvss_score} | EPSS {c.epss_score} | KEV {c.kev} | {c.match_status}")
        if f.evidence:
            lines.append(f"- Evidence: {f.evidence}")
        if f.remediation:
            lines.append(f"- Remediation: {f.remediation}")
        lines.append("")
    lines.append(f"\n---\n{BRAND_FOOTER}")
    return "\n".join(lines)


def to_html(findings: List[Finding], meta: dict) -> str:
    rows = "".join(
        f"<tr><td>{f.severity.value}</td><td>{f.title}</td><td>{f.asset}</td>"
        f"<td>{f.port or ''}</td><td>{','.join(c.cve_id for c in f.cves)}</td>"
        f"<td>{f.risk_score}</td><td>{f.confidence.value}</td></tr>"
        for f in sorted(findings, key=lambda x: x.risk_score or 0, reverse=True)
    )
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>DRACXX Security Assessment</title>
<style>
body{{font-family:Consolas,monospace;background:#0d1117;color:#c9d1d9;padding:2em}}
h1{{color:#ff2e6b}} table{{width:100%;border-collapse:collapse;margin-top:1em}}
th,td{{border:1px solid #30363d;padding:6px 10px;text-align:left;font-size:13px}}
th{{background:#161b22}} .footer{{margin-top:2em;color:#8b949e;font-size:12px}}
</style></head><body>
<h1>DRACXX Security Assessment</h1>
<p>Target: {meta.get('target')} | Session: {meta.get('session_id')} | Exploitation: DISABLED</p>
<table><tr><th>Severity</th><th>Title</th><th>Asset</th><th>Port</th><th>CVEs</th><th>Risk</th><th>Confidence</th></tr>
{rows}
</table>
<div class="footer">{BRAND_FOOTER}</div>
</body></html>"""


def to_terminal_summary(findings: List[Finding]) -> str:
    sev = _summary(findings)
    lines = ["DRACXX Findings Summary", "-" * 30]
    for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if k in sev:
            lines.append(f"{k:<10} {sev[k]}")
    lines.append("-" * 30)
    lines.append(f"Total: {len(findings)}")
    return "\n".join(lines)


def to_terminal_detail(findings: List[Finding]) -> str:
    """Full per-finding detail for console/CLI display."""
    if not findings:
        return "No findings."
    sev = _summary(findings)
    lines = [
        "DRACXX Findings — Detailed View",
        "=" * 60,
        "Summary:",
    ]
    for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if k in sev:
            lines.append(f"  {k:<10} {sev[k]}")
    lines.append(f"  TOTAL: {len(findings)}")
    lines.append("=" * 60)

    ordered = sorted(
        findings,
        key=lambda x: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                x.severity.value, 5
            ),
            -(x.risk_score or 0),
        ),
    )
    for i, f in enumerate(ordered, 1):
        lines.append("")
        lines.append(f"#{i}  [{f.severity.value}]  {f.title}")
        lines.append("-" * 60)
        lines.append(f"  Finding ID : {f.finding_id}")
        lines.append(f"  Asset      : {f.asset}")
        lines.append(f"  Target     : {f.target}")
        if f.port:
            lines.append(f"  Port       : {f.port}/{f.protocol or 'tcp'}")
        if f.technology:
            lines.append(f"  Technology : {f.technology} {f.version or ''}".rstrip())
        if f.cpe:
            lines.append(f"  CPE        : {f.cpe}")
        lines.append(f"  Confidence : {f.confidence.value}")
        lines.append(f"  Risk score : {f.risk_score if f.risk_score is not None else 'N/A'}")
        lines.append(f"  Scanner    : {f.scanner}")
        if f.cwe:
            lines.append(f"  CWE        : {f.cwe}")
        if f.evidence:
            ev = f.evidence if len(f.evidence) <= 300 else f.evidence[:300] + "..."
            lines.append(f"  Evidence   : {ev}")
        if f.cves:
            lines.append("  CVEs:")
            for c in f.cves:
                lines.append(
                    f"    - {c.cve_id} | status={c.match_status} | "
                    f"CVSS={c.cvss_score} | EPSS={c.epss_score} | KEV={c.kev}"
                )
        if f.references:
            refs = ", ".join(str(r) for r in f.references[:5])
            lines.append(f"  References : {refs}")
        if f.remediation:
            rem = f.remediation if len(f.remediation) <= 400 else f.remediation[:400] + "..."
            lines.append(f"  Remediation: {rem}")
    lines.append("")
    lines.append("=" * 60)
    lines.append(BRAND_FOOTER)
    return "\n".join(lines)
