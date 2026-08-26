# Changelog

## [1.2.1] — 2026-08-26

### Detailed scan + AI
- `dracxx-vuln scan` prints full finding detail: affected URL, description, CVE, remediation, template ID
- Optional `--ai` flag for advisory AI analysis after scan
- `--full` / `--fast` modes retained
- JSON export with `--output`

### Carry-forward from 1.2.0
- FAST profile, Amass only on DEEP, hard timeouts, URL scope fix


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
