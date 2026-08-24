# Changelog

## [1.0.0] - 2026-08-10
### Added
- Initial DRACXX framework release.
- CLI (Typer) with recon/scan/workflow/cve/assets/findings/report/modules/tools/doctor/config/history/console commands.
- Interactive DRACXX console with randomized startup banners.
- Scope control engine (domains, CIDRs, exclusions).
- Tool adapters: nmap, nuclei, subfinder, amass, assetfinder, httpx, katana, ffuf, nikto, testssl.sh, naabu, zap-baseline.
- CVE/CPE intelligence engine with real version-range evaluation (NVD, EPSS, CISA KEV).
- Weighted risk scoring engine and confidence scoring engine.
- Finding deduplication/correlation across scanners.
- Dual-mode AI provider abstraction (Anthropic/OpenAI-compatible/local).
- Multi-format reporting: terminal, JSON, CSV, Markdown, HTML.
- SQLite database (PostgreSQL-compatible schema via SQLAlchemy).
- Kali install/uninstall/update scripts, Dockerfile, docker-compose.
- Test suite covering version matching, scope, risk, confidence, dedup, CLI, database.
- Exploitation permanently disabled by design.
