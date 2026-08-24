# Changelog

## [1.1.0] — 2026-08-24

### Improved
- Concurrent workflow engine (subdomain tools, web probes, nuclei scans run with asyncio)
- Multi-phase pipeline with clear progress reporting (Passive → Network → Web → Vuln → Risk)
- Proper package `__init__.py` files for all modules
- Professional README with architecture, honest limitations, and clear security stance
- Version bump and cleaner project structure

### Security
- Exploitation remains permanently disabled
- Nuclei restricted to safe tags only
- Scope control and authorized-use policy unchanged

## [1.0.0] — Initial release

- CLI + interactive console
- Scope control, CVE/CPE engine, risk & confidence engines
- Tool adapters (nmap, nuclei, subfinder, httpx, amass, …)
- Dual-mode AI provider
- Multi-format reporting
- SQLite storage
- Guard tests ensuring no exploitation constructs
