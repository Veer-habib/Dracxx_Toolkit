"""Automated workflow orchestrator wiring recon -> vuln -> CVE -> risk ->
report. Falls back gracefully when optional tools are unavailable."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Callable, List, Optional

from dracxx.correlation.dedup import deduplicate
from dracxx.engines.cve.engine import CVEIntelligenceEngine
from dracxx.engines.risk.engine import compute_risk_score, risk_band
from dracxx.engines.vulnerability.confidence import score_confidence
from dracxx.integrations.httpx_adapter import HttpxAdapter
from dracxx.integrations.nmap import NmapAdapter
from dracxx.integrations.nuclei import NucleiAdapter
from dracxx.integrations.subfinder import SubfinderAdapter
from dracxx.models.schema import (Confidence, CVEMatch, Finding, ScanProfile,
                                   Severity)

NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH,
    "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
}


def new_session_id() -> str:
    return f"DRX-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"


class WorkflowEngine:
    def __init__(self, config, offline: bool = False, progress_cb: Optional[Callable[[str], None]] = None):
        self.config = config
        self.offline = offline
        self.progress = progress_cb or (lambda msg: None)
        self.cve_engine = CVEIntelligenceEngine(
            nvd_api_key=config.apis.get("nvd_api_key", ""), offline=offline
        )

    async def run(self, target: str, profile: ScanProfile = ScanProfile.STANDARD) -> List[Finding]:
        session_id = new_session_id()
        findings: List[Finding] = []

        self.progress(f"[{session_id}] Passive recon: subdomains")
        subdomains = await self._passive_recon(target)

        self.progress(f"[{session_id}] Network enumeration: ports/services")
        ports = await self._network_enum(target, profile)
        for p in ports:
            if p.product:
                findings.extend(await self._correlate_cves(target, p.product, p.version, p.port))

        self.progress(f"[{session_id}] Web/API recon")
        web_findings = await self._web_recon([target] + subdomains[:5], profile)
        findings.extend(web_findings)

        self.progress(f"[{session_id}] Deduplicating findings")
        findings = deduplicate(findings)

        self.progress(f"[{session_id}] Risk scoring")
        for f in findings:
            top_cve = max(f.cves, key=lambda c: (c.kev, c.cvss_score or 0)) if f.cves else None
            f.risk_score = compute_risk_score(
                cvss_score=top_cve.cvss_score if top_cve else None,
                epss_score=top_cve.epss_score if top_cve else None,
                kev=top_cve.kev if top_cve else False,
                internet_exposed=True,
                confidence=f.confidence,
            )

        self.progress(f"[{session_id}] Workflow complete: {len(findings)} findings")
        return findings

    async def _passive_recon(self, target: str) -> List[str]:
        sub = SubfinderAdapter()
        if not sub.is_installed():
            self.progress("[!] Subfinder unavailable, continuing with available capabilities")
            return []
        return await sub.enumerate(target)

    async def _network_enum(self, target: str, profile: ScanProfile):
        nmap = NmapAdapter()
        if not nmap.is_installed():
            self.progress("[!] Nmap unavailable, continuing with available capabilities")
            return []
        deep = profile == ScanProfile.DEEP
        return await nmap.scan(target, deep=deep)

    async def _web_recon(self, targets: List[str], profile: ScanProfile) -> List[Finding]:
        findings: List[Finding] = []
        nuclei = NucleiAdapter()
        if not nuclei.is_installed():
            self.progress("[!] Nuclei unavailable, continuing with available capabilities")
            return findings
        for t in targets:
            results = await nuclei.scan(t)
            for r in results:
                info = r.get("info", {})
                sev = NUCLEI_SEVERITY_MAP.get(info.get("severity", "info"), Severity.INFO)
                cve_ids = info.get("classification", {}).get("cve-id", []) or []
                findings.append(Finding(
                    finding_id=f"NUC-{uuid.uuid4().hex[:8]}",
                    title=info.get("name", "Nuclei detection"),
                    severity=sev,
                    confidence=Confidence.LIKELY,
                    target=t,
                    asset=t,
                    technology=info.get("tags", [None])[0] if info.get("tags") else None,
                    evidence=r.get("matched-at"),
                    scanner="nuclei",
                    references=info.get("reference", []) or [],
                    remediation=info.get("remediation"),
                ))
        return findings

    async def _correlate_cves(self, target: str, product: str, version: Optional[str], port: int) -> List[Finding]:
        cve_matches = await self.cve_engine.correlate(product, version)
        if not cve_matches:
            return []
        confidence = score_confidence(
            version_matched=bool(version),
            cpe_matched=True,
            scanner_count=1,
            has_vendor_advisory=False,
            has_cve_range_match=any(c.match_status == "AFFECTED" for c in cve_matches),
            has_config_evidence=False,
        )
        top_sev = Severity.HIGH if any(c.cvss_score and c.cvss_score >= 7 for c in cve_matches) else Severity.MEDIUM
        return [Finding(
            finding_id=f"CVE-COR-{uuid.uuid4().hex[:8]}",
            title=f"{product} {version or ''} — potential CVE matches",
            severity=top_sev,
            confidence=confidence,
            target=target,
            asset=target,
            port=port,
            technology=product,
            version=version,
            cpe=cve_matches[0].cpe,
            cves=cve_matches,
            scanner="cve-engine",
            references=[r for c in cve_matches for r in c.references][:10],
            remediation="Upgrade to a patched version per vendor advisory; verify via changelog.",
        )]
