# Changelog

## [1.2.0] — 2026-08-26

### Speed & usability
- **New FAST profile** — nuclei + httpx only, typically 1–3 minutes
- Amass only runs on DEEP (no more hangs on STANDARD/LIGHT)
- Hard timeouts on Subfinder (90s) and Amass (120s)
- Nuclei fast mode: critical/high/medium only + rate limits
- Nmap fast mode: top-100 ports for LIGHT/FAST
- `dracxx-vuln scan` is now a proper **quick vulnerability scanner** (fast by default)
- Scope correctly handles full URLs (`https://host/path`)

### Security
- Exploitation remains permanently disabled
- Nuclei still restricted to safe tags only

## [1.1.0] — 2026-08-24

- Concurrent workflow, package structure, professional README

## [1.0.0] — Initial release
