"""Automated workflow orchestrator: recon → vuln → CVE → risk → report.

Speed-focused design:
  FAST     → nuclei + httpx only on main target (~1-3 min)
  LIGHT    → + quick nmap + subfinder
  STANDARD → balanced concurrent pipeline
  DEEP     → includes Amass + deeper nmap

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
from dracxx.integrations.assetfinder import AssetfinderAdapter
from dracxx.integrations.katana import KatanaAdapter
from dracxx.integrations.wayback import WaybackAdapter
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


def _normalize_target(target: str) -> str:
    """Strip scheme/path so tools get a clean host when useful."""
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/")[0].split(":")[0]
    return t or target.strip()


class WorkflowEngine:
    """End-to-end orchestrator optimized for speed + graceful degradation."""

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
        host = _normalize_target(target)

        # ── FAST path: max speed vulnerability scan ─────────────────────
        if profile == ScanProfile.FAST:
            self.progress(f"[{sid}] FAST mode — quick vuln scan on {host}")
            findings.extend(await self._vuln_scan([target], profile, fast=True))
            findings.extend(await self._web_recon([target], profile))
            findings = deduplicate(findings)
            self._score(findings)
            self.progress(f"[{sid}] FAST complete — {len(findings)} finding(s)")
            return findings

        # ── Phase 1: Passive recon (Subfinder only; Amass only on DEEP) ──
        self.progress(f"[{sid}] Phase 1 — Passive recon")
        subdomains = await self._passive_recon(host, profile)
        self.progress(f"[{sid}]   → {len(subdomains)} subdomain(s)")

        # ── Phase 2: Network enum (skip on PASSIVE) ─────────────────────
        ports = []
        if profile != ScanProfile.PASSIVE:
            self.progress(f"[{sid}] Phase 2 — Network enumeration")
            ports = await self._network_enum(host, profile)
            self.progress(f"[{sid}]   → {len(ports)} open port(s)")
            cve_tasks = [
                self._correlate_cves(host, p.product, p.version, p.port)
                for p in ports if p.product
            ]
            if cve_tasks:
                for res in await asyncio.gather(*cve_tasks, return_exceptions=True):
                    if isinstance(res, list):
                        findings.extend(res)

        # ── Phase 3: Web tech + passive URL discovery ───────────────────
        web_targets = [target]
        limit = 3 if profile == ScanProfile.LIGHT else (8 if profile != ScanProfile.DEEP else 15)
        web_targets += subdomains[:limit]
        self.progress(f"[{sid}] Phase 3 — Web/tech recon ({len(web_targets)} target(s))")
        findings.extend(await self._web_recon(web_targets, profile))

        if profile in (ScanProfile.STANDARD, ScanProfile.DEEP) and profile != ScanProfile.FAST:
            self.progress(f"[{sid}] Phase 3b — Passive URL / crawl discovery")
            extra_urls = await self._url_discovery(host, profile)
            if extra_urls:
                self.progress(f"[{sid}]   → {len(extra_urls)} historical/crawl URL(s)")
                # Feed a sample of discovered URLs into nuclei later via web_targets
                for u in extra_urls[:10]:
                    if u not in web_targets:
                        web_targets.append(u)

        # ── Phase 4: Vulnerability detection ────────────────────────────
        if profile != ScanProfile.PASSIVE:
            self.progress(f"[{sid}] Phase 4 — Vulnerability detection (safe templates)")
            findings.extend(await self._vuln_scan(web_targets, profile))

        # ── Phase 5: Dedup + risk ───────────────────────────────────────
        self.progress(f"[{sid}] Phase 5 — Dedup & risk scoring")
        findings = deduplicate(findings)
        self._score(findings)
        self.progress(f"[{sid}] Workflow complete — {len(findings)} finding(s)")
        return findings

    def _score(self, findings: List[Finding]) -> None:
        for f in findings:
            top_cve = (
                max(f.cves, key=lambda c: (c.kev, c.cvss_score or 0))
                if f.cves else None
            )
            f.risk_score = compute_risk_score(
                cvss_score=top_cve.cvss_score if top_cve else None,
                epss_score=top_cve.epss_score if top_cve else None,
                kev=top_cve.kev if top_cve else False,
                internet_exposed=True,
                confidence=f.confidence,
            )

    async def _passive_recon(self, target: str, profile: ScanProfile) -> List[str]:
        """Subfinder + Assetfinder; Amass only on DEEP. Hard timeouts."""
        seen: set[str] = set()
        tasks = []

        sub = SubfinderAdapter()
        if sub.is_installed():
            tasks.append(self._timed(sub.enumerate(target), 90, "Subfinder"))
        else:
            self.progress("[!] Subfinder unavailable — skipping")

        af = AssetfinderAdapter()
        if af.is_installed() and hasattr(af, "enumerate"):
            tasks.append(self._timed(af.enumerate(target), 60, "Assetfinder"))
        elif af.is_installed():
            # some adapters use different method names
            pass

        if profile == ScanProfile.DEEP:
            amass = AmassAdapter()
            if amass.is_installed():
                tasks.append(self._timed(amass.enumerate(target, passive=True), 120, "Amass"))
            else:
                self.progress("[!] Amass unavailable — skipping")
        else:
            self.progress("[*] Amass skipped (use --profile DEEP to enable)")

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, list):
                for s in res:
                    if isinstance(s, str) and s.strip():
                        seen.add(s.strip().lower())
        # Cap subdomain fan-out for production speed
        max_subs = 50
        try:
            max_subs = int(self.config.scan.get("max_subdomains", 50))
        except Exception:
            pass
        ordered = sorted(seen)
        if len(ordered) > max_subs:
            self.progress(f"[*] Capping subdomains {len(ordered)} → {max_subs}")
            ordered = ordered[:max_subs]
        return ordered

    async def _timed(self, coro, seconds: float, name: str):
        try:
            return await asyncio.wait_for(coro, timeout=seconds)
        except asyncio.TimeoutError:
            self.progress(f"[!] {name} timed out after {seconds}s — continuing")
            return []
        except Exception as e:
            self.progress(f"[!] {name} error: {e}")
            return []

    async def _network_enum(self, target: str, profile: ScanProfile):
        nmap = NmapAdapter()
        if not nmap.is_installed():
            self.progress("[!] Nmap unavailable — skipping")
            return []
        fast = profile in (ScanProfile.LIGHT, ScanProfile.FAST)
        deep = profile == ScanProfile.DEEP
        return await nmap.scan(target, deep=deep, fast=fast)

    async def _web_recon(self, targets: List[str], profile: ScanProfile) -> List[Finding]:
        findings: List[Finding] = []
        httpx_ad = HttpxAdapter()
        if not httpx_ad.is_installed():
            self.progress("[!] httpx unavailable — skipping tech detection")
            return findings

        sem = asyncio.Semaphore(8)

        async def _probe(t: str):
            async with sem:
                try:
                    return await asyncio.wait_for(httpx_ad.probe([t]), timeout=25)
                except Exception:
                    return []

        results = await asyncio.gather(*[_probe(t) for t in targets], return_exceptions=True)
        for t, res in zip(targets, results):
            if isinstance(res, Exception) or not res:
                continue
            items = res if isinstance(res, list) else [res]
            for item in items:
                tech = None
                evidence = str(item)[:500]
                if hasattr(item, "technologies"):
                    tech = ", ".join(item.technologies) if item.technologies else None
                    evidence = (
                        f"{getattr(item, 'url', t)} "
                        f"status={getattr(item, 'status_code', '?')} "
                        f"title={getattr(item, 'title', '')}"
                    )
                elif isinstance(item, dict):
                    tech = item.get("tech") or item.get("technologies")
                    if isinstance(tech, list):
                        tech = ", ".join(tech) if tech else None
                findings.append(Finding(
                    finding_id=f"TECH-{uuid.uuid4().hex[:8]}",
                    title=f"Technology detected on {t}",
                    severity=Severity.INFO,
                    confidence=Confidence.LIKELY,
                    target=t,
                    asset=t,
                    technology=str(tech) if tech else None,
                    evidence=evidence,
                    scanner="httpx",
                ))
        return findings

    async def _vuln_scan(
        self, targets: List[str], profile: ScanProfile, fast: bool = False
    ) -> List[Finding]:
        findings: List[Finding] = []
        nuclei = NucleiAdapter()
        if not nuclei.is_installed():
            self.progress("[!] Nuclei unavailable — skipping vulnerability detection")
            return findings

        fast = fast or profile in (ScanProfile.FAST, ScanProfile.LIGHT)
        sem = asyncio.Semaphore(4)

        async def _scan_one(t: str):
            async with sem:
                try:
                    return await nuclei.scan(t, fast=fast)
                except Exception:
                    return []

        results = await asyncio.gather(*[_scan_one(t) for t in targets], return_exceptions=True)
        for t, res in zip(targets, results):
            if isinstance(res, Exception) or not res:
                continue
            for r in res:
                info = r.get("info", {}) if isinstance(r, dict) else {}
                sev = NUCLEI_SEVERITY_MAP.get(
                    str(info.get("severity", "info")).lower(), Severity.INFO
                )
                matched = None
                host = t
                if isinstance(r, dict):
                    matched = r.get("matched-at") or r.get("host") or r.get("url")
                    host = r.get("host") or r.get("ip") or t
                    if not matched and r.get("url"):
                        matched = r.get("url")
                # Prefer matched URL as asset when it is a full URL
                asset_val = matched if (matched and str(matched).startswith("http")) else (host or t)
                findings.append(Finding(
                    finding_id=f"NUC-{uuid.uuid4().hex[:8]}",
                    title=info.get("name", "Nuclei detection"),
                    severity=sev,
                    confidence=Confidence.LIKELY,
                    target=t,
                    asset=str(asset_val),
                    technology=(info.get("tags", [None])[0] if info.get("tags") else None),
                    evidence=str(matched) if matched else str(t),
                    scanner="nuclei",
                    references=info.get("reference", []) or [],
                    remediation=info.get("remediation"),
                ))
        return findings


    async def _url_discovery(self, domain: str, profile: ScanProfile) -> List[str]:
        """Passive historical URLs + optional Katana crawl (detection only)."""
        found: set[str] = set()
        try:
            wb = WaybackAdapter()
            if wb.is_installed():
                urls = await self._timed(wb.fetch(domain, limit=150), 90, "waybackurls/gau")
                if isinstance(urls, list):
                    found.update(u for u in urls if isinstance(u, str) and u.strip())
            else:
                self.progress("[!] waybackurls/gau unavailable — skipping historical URLs")
        except Exception as e:
            self.progress(f"[!] URL discovery (wayback) error: {e}")

        if profile == ScanProfile.DEEP:
            try:
                katana = KatanaAdapter()
                if katana.is_installed():
                    crawled = await self._timed(
                        katana.crawl(f"https://{domain}", depth=2), 120, "Katana"
                    )
                    if isinstance(crawled, list):
                        found.update(u for u in crawled if isinstance(u, str) and u.strip())
                else:
                    self.progress("[!] Katana unavailable — skipping crawl")
            except Exception as e:
                self.progress(f"[!] Katana error: {e}")
        return sorted(found)[:200]

    async def _correlate_cves(
        self, target: str, product: str, version: Optional[str], port: int
    ) -> List[Finding]:
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
        top_sev = (
            Severity.HIGH
            if any(c.cvss_score and c.cvss_score >= 7 for c in cve_matches)
            else Severity.MEDIUM
        )
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
