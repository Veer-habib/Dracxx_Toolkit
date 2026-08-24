"""CVE/CPE intelligence engine.

Pipeline: Product -> Vendor -> Product -> Version -> CPE -> Affected Range
-> CVE -> CVSS -> EPSS -> KEV -> Evidence -> Confidence.

A product-name match ALONE is never treated as proof of vulnerability;
evaluate_affected() from utils.version performs real range evaluation.
"""
from __future__ import annotations

import asyncio
from typing import Dict, List, Optional

import httpx

from dracxx.models.schema import CVEMatch
from dracxx.utils.version import MatchStatus, evaluate_affected

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Small curated CPE table as a fallback when the full NVD CPE dictionary
# API is not reachable (offline-friendly). Real deployments should hit
# the NVD CPE API with an API key for full coverage.
CURATED_CPE_TABLE: Dict[str, str] = {
    "apache": "cpe:2.3:a:apache:http_server",
    "nginx": "cpe:2.3:a:nginx:nginx",
    "openssh": "cpe:2.3:a:openbsd:openssh",
    "wordpress": "cpe:2.3:a:wordpress:wordpress",
    "php": "cpe:2.3:a:php:php",
    "mysql": "cpe:2.3:a:oracle:mysql",
    "postgresql": "cpe:2.3:a:postgresql:postgresql",
    "vsftpd": "cpe:2.3:a:vsftpd_project:vsftpd",
    "openssl": "cpe:2.3:a:openssl:openssl",
    "tomcat": "cpe:2.3:a:apache:tomcat",
    "iis": "cpe:2.3:a:microsoft:iis",
    "jenkins": "cpe:2.3:a:jenkins:jenkins",
    "drupal": "cpe:2.3:a:drupal:drupal",
    "joomla": "cpe:2.3:a:joomla:joomla",
}


class CVEIntelligenceEngine:
    def __init__(self, nvd_api_key: str = "", cache: Optional[Dict] = None, offline: bool = False):
        self.nvd_api_key = nvd_api_key
        self.cache = cache if cache is not None else {}
        self.offline = offline
        self._kev_set: Optional[set] = None

    def identify_cpe(self, product: str) -> Optional[str]:
        if not product:
            return None
        key = product.strip().lower()
        for name, cpe in CURATED_CPE_TABLE.items():
            if name in key:
                return cpe
        return None

    async def fetch_cves_for_cpe(self, cpe: str, version: str, client: httpx.AsyncClient) -> List[Dict]:
        cache_key = f"{cpe}:{version}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        if self.offline:
            return []
        cpe_match_string = f"{cpe}:{version}:*:*:*:*:*:*:*"
        params = {"cpeName": cpe_match_string, "resultsPerPage": 50}
        headers = {"apiKey": self.nvd_api_key} if self.nvd_api_key else {}
        try:
            resp = await client.get(NVD_CVE_API, params=params, headers=headers, timeout=20)
            if resp.status_code != 200:
                return []
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            self.cache[cache_key] = vulns
            return vulns
        except Exception:
            return []

    async def fetch_epss(self, cve_id: str, client: httpx.AsyncClient) -> Optional[float]:
        if self.offline:
            return None
        try:
            resp = await client.get(EPSS_API, params={"cve": cve_id}, timeout=10)
            if resp.status_code != 200:
                return None
            data = resp.json()
            rows = data.get("data", [])
            if rows:
                return float(rows[0].get("epss", 0))
        except Exception:
            return None
        return None

    async def load_kev(self, client: httpx.AsyncClient) -> set:
        if self._kev_set is not None:
            return self._kev_set
        if self.offline:
            self._kev_set = set()
            return self._kev_set
        try:
            resp = await client.get(KEV_FEED, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                self._kev_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
            else:
                self._kev_set = set()
        except Exception:
            self._kev_set = set()
        return self._kev_set

    @staticmethod
    def _extract_ranges(cve_item: Dict) -> (List[str], List[str]):
        """Extract version-range expressions and fixed versions from an
        NVD CVE item's configurations."""
        ranges: List[str] = []
        fixed: List[str] = []
        try:
            for cfg in cve_item.get("cve", {}).get("configurations", []):
                for node in cfg.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        parts = []
                        if m.get("versionStartIncluding"):
                            parts.append(f">= {m['versionStartIncluding']}")
                        if m.get("versionStartExcluding"):
                            parts.append(f"> {m['versionStartExcluding']}")
                        if m.get("versionEndIncluding"):
                            parts.append(f"<= {m['versionEndIncluding']}")
                            fixed.append(m["versionEndIncluding"])
                        if m.get("versionEndExcluding"):
                            parts.append(f"< {m['versionEndExcluding']}")
                            fixed.append(m["versionEndExcluding"])
                        if parts:
                            ranges.append(" and ".join(parts))
        except Exception:
            pass
        return ranges, fixed

    @staticmethod
    def _extract_cvss(cve_item: Dict):
        metrics = cve_item.get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]["cvssData"]
                version = {"cvssMetricV31": "3.1", "cvssMetricV40": "4.0",
                           "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}[key]
                return m.get("baseScore"), m.get("vectorString"), version
        return None, None, None

    async def correlate(self, product: str, version: Optional[str]) -> List[CVEMatch]:
        """Full correlation pipeline for a single detected product/version."""
        cpe = self.identify_cpe(product)
        if not cpe:
            return []
        results: List[CVEMatch] = []
        async with httpx.AsyncClient() as client:
            items = await self.fetch_cves_for_cpe(cpe, version or "", client)
            kev_set = await self.load_kev(client)
            for item in items:
                cve_id = item.get("cve", {}).get("id")
                if not cve_id:
                    continue
                ranges, fixed = self._extract_ranges(item)
                status = evaluate_affected(version, ranges, fixed)
                if status == MatchStatus.NOT_AFFECTED:
                    continue
                score, vector, cvss_ver = self._extract_cvss(item)
                epss = await self.fetch_epss(cve_id, client)
                refs = [r.get("url") for r in item.get("cve", {}).get("references", [])][:5]
                results.append(CVEMatch(
                    cve_id=cve_id,
                    cvss_score=score,
                    cvss_vector=vector,
                    cvss_version=cvss_ver,
                    epss_score=epss,
                    kev=cve_id in kev_set,
                    match_status=status.value,
                    cpe=cpe,
                    references=refs,
                    public_exploit_known=False,  # intelligence only; never executed
                ))
        return results
