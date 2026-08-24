"""Automated workflow orchestrator: recon → vuln → CVE → risk → report.

Falls back gracefully when optional tools are unavailable.
EXPLOITATION: PERMANENTLY DISABLED.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Callable, List, Optional

from dracxx.correlation.dedup import deduplicate
from dracxx.engines.cve.engine import CVEIntelligenceEngine
from dracxx.engines.risk.engine import compute_risk_score
from dracxx.engines.vulnerability.confidence import score_confidence
from dracxx.integrations.amass import AmassAdapter
from dracxx.integrations.httpx_adapter import HttpxAdapter
from dracxx.integrations.nmap import NmapAdapter
from dracxx.integrations.nuclei import NucleiAdapter
from dracxx.integrations.subfinder import SubfinderAdapter
from dracxx.models.schema import Confidence, Finding, ScanProfile, Severity

NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def new_session_id() -> str:
    return f"DRX-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"


class WorkflowEngine:
    """End-to-end orchestrator with concurrent tool execution and graceful degradation."""

    def __init__(
        self,
        config,
        offline: bool = False,
        progress_cb: Optional[Callable[[str], None]] = None,
    ):
        self.config = config
        self.offline = offline
        self.progress = progress_cb or (lambda msg: None)
        self.cve_engine = CVEIntelligenceEngine(
            nvd_api_key=config.apis.get("nvd_api_key", ""),
            offline=offline,
        )
        self.session_id = new_session_id()

    async def run(
        self, target: str, profile: ScanProfile = ScanProfile.STANDARD
    ) -> List[Finding]:
        findings: List[Finding] = []
        sid = self.session_id

        # ── Phase 1: Passive recon (concurrent) ──────────────────────────
        self.progress(f"[{sid}] Phase 1 — Passive recon (subdomains)")
        subdomains = await self._passive_recon(target)
        self.progress(f"[{sid}]   → {len(subdomains)} subdomain(s) discovered")

        # ── Phase 2: Network enumeration ────────────────────────────────
        self.progress(f"[{sid}] Phase 2 — Network enumeration (ports/services)")
        ports = await self._network_enum(target, profile)
        self.progress(f"[{sid}]   → {len(ports)} open port(s)")

        # Correlate CVEs for discovered products
        cve_tasks = [
            self._correlate_cves(target, p.product, p.version, p.port)
            for p in ports
            if p.product
        ]
        if cve_tasks:
            cve_results = await asyncio.gather(*cve_tasks, return_exceptions=True)
            for res in cve_results:
                if isinstance(res, list):
                    findings.extend(res)

        # ── Phase 3: Web / technology detection ─────────────────────────
        web_targets = [target] + subdomains[:8]
        self.progress(f"[{sid}] Phase 3 — Web & technology recon ({len(web_targets)} target(s))")
        web_findings = await self._web_recon(web_targets, profile)
        findings.extend(web_findings)

        # ── Phase 4: Vulnerability detection (Nuclei) ───────────────────
        if profile != ScanProfile.PASSIVE:
            self.progress(f"[{sid}] Phase 4 — Vulnerability detection (safe templates only)")
            vuln_findings = await self._vuln_scan(web_targets, profile)
            findings.extend(vuln_findings)

        # ── Phase 5: Dedup + Risk scoring ───────────────────────────────
        self.progress(f"[{sid}] Phase 5 — Deduplication & risk scoring")
        findings = deduplicate(findings)

        for f in findings:
            top_cve = (
                max(f.cves, key=lambda c: (c.kev, c.cvss_score or 0))
                if f.cves
                else None
            )
            f.risk_score = compute_risk_score(
                cvss_score=top_cve.cvss_score if top_cve else None,
                epss_score=top_cve.epss_score if top_cve else None,
                kev=top_cve.kev if top_cve else False,
                internet_exposed=True,
                confidence=f.confidence,
            )

        self.progress(f"[{sid}] Workflow complete — {len(findings)} finding(s)")
        return findings

    # ── Internal helpers ────────────────────────────────────────────────

    async def _passive_recon(self, target: str) -> List[str]:
        """Run subdomain enumeration tools concurrently and merge results."""
        adapters = []
        sub = SubfinderAdapter()
        amass = AmassAdapter()
        if sub.is_installed():
            adapters.append(("subfinder", sub.enumerate(target)))
        else:
            self.progress("[!] Subfinder unavailable — skipping")
        if amass.is_installed() and hasattr(amass, "enumerate"):
            adapters.append(("amass", amass.enumerate(target)))
        else:
            self.progress("[!] Amass unavailable — skipping")

        if not adapters:
            return []

        results = await asyncio.gather(
            *[coro for _, coro in adapters], return_exceptions=True
        )
        seen: set[str] = set()
        for res in results:
            if isinstance(res, list):
                for s in res:
                    if isinstance(s, str) and s.strip():
                        seen.add(s.strip().lower())
        return sorted(seen)

    async def _network_enum(self, target: str, profile: ScanProfile):
        nmap = NmapAdapter()
        if not nmap.is_installed():
            self.progress("[!] Nmap unavailable — continuing without port data")
            return []
        deep = profile in (ScanProfile.DEEP, ScanProfile.STANDARD)
        return await nmap.scan(target, deep=deep)

    async def _web_recon(
        self, targets: List[str], profile: ScanProfile
    ) -> List[Finding]:
        """Technology detection via httpx (when available)."""
        findings: List[Finding] = []
        httpx_ad = HttpxAdapter()
        if not httpx_ad.is_installed():
            self.progress("[!] httpx unavailable — skipping tech detection")
            return findings

        # Run httpx against multiple targets concurrently (bounded)
        sem = asyncio.Semaphore(5)

        async def _probe(t: str):
            async with sem:
                if hasattr(httpx_ad, "probe"):
                    return await httpx_ad.probe([t])
                if hasattr(httpx_ad, "scan"):
                    return await httpx_ad.scan(t)
                return []

        results = await asyncio.gather(
            *[_probe(t) for t in targets], return_exceptions=True
        )
        for t, res in zip(targets, results):
            if isinstance(res, Exception) or not res:
                continue
            items = res if isinstance(res, list) else [res]
            for item in items:
                tech = None
                evidence = str(item)[:500]
                if hasattr(item, "technologies"):  # WebEndpoint model
                    tech = ", ".join(item.technologies) if item.technologies else None
                    evidence = f"{getattr(item, 'url', t)} status={getattr(item, 'status_code', '?')} title={getattr(item, 'title', '')}"
                elif isinstance(item, dict):
                    tech = item.get("tech") or item.get("technologies")
                    if isinstance(tech, list):
                        tech = ", ".join(tech) if tech else None
                findings.append(
                    Finding(
                        finding_id=f"TECH-{uuid.uuid4().hex[:8]}",
                        title=f"Technology detected on {t}",
                        severity=Severity.INFO,
                        confidence=Confidence.LIKELY,
                        target=t,
                        asset=t,
                        technology=str(tech) if tech else None,
                        evidence=evidence,
                        scanner="httpx",
                    )
                )
        return findings

    async def _vuln_scan(
        self, targets: List[str], profile: ScanProfile
    ) -> List[Finding]:
        """Nuclei detection only — safe tags, no exploit templates."""
        findings: List[Finding] = []
        nuclei = NucleiAdapter()
        if not nuclei.is_installed():
            self.progress("[!] Nuclei unavailable — skipping vulnerability detection")
            return findings

        sem = asyncio.Semaphore(3)

        async def _scan_one(t: str):
            async with sem:
                return await nuclei.scan(t)

        results = await asyncio.gather(
            *[_scan_one(t) for t in targets], return_exceptions=True
        )

        for t, res in zip(targets, results):
            if isinstance(res, Exception) or not res:
                continue
            for r in res:
                info = r.get("info", {}) if isinstance(r, dict) else {}
                sev = NUCLEI_SEVERITY_MAP.get(
                    str(info.get("severity", "info")).lower(), Severity.INFO
                )
                findings.append(
                    Finding(
                        finding_id=f"NUC-{uuid.uuid4().hex[:8]}",
                        title=info.get("name", "Nuclei detection"),
                        severity=sev,
                        confidence=Confidence.LIKELY,
                        target=t,
                        asset=t,
                        technology=(
                            info.get("tags", [None])[0] if info.get("tags") else None
                        ),
                        evidence=r.get("matched-at") if isinstance(r, dict) else None,
                        scanner="nuclei",
                        references=info.get("reference", []) or [],
                        remediation=info.get("remediation"),
                    )
                )
        return findings

    async def _correlate_cves(
        self,
        target: str,
        product: str,
        version: Optional[str],
        port: int,
    ) -> List[Finding]:
        cve_matches = await self.cve_engine.correlate(product, version)
        if not cve_matches:
            return []

        confidence = score_confidence(
            version_matched=bool(version),
            cpe_matched=True,
            scanner_count=1,
            has_vendor_advisory=False,
            has_cve_range_match=any(
                c.match_status == "AFFECTED" for c in cve_matches
            ),
            has_config_evidence=False,
        )
        top_sev = (
            Severity.HIGH
            if any(c.cvss_score and c.cvss_score >= 7 for c in cve_matches)
            else Severity.MEDIUM
        )
        return [
            Finding(
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
                remediation=(
                    "Upgrade to a patched version per vendor advisory; "
                    "verify via changelog."
                ),
            )
        ]
