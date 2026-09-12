# DRACXX Toolkit

**AI-Driven Reconnaissance & Vulnerability Intelligence Framework**  
**v1.2.0 — MADE BY DRACXX**

```
╔════════════════════════════════════════════╗
║                 D R A C X X                 ║
║   AI RECONNAISSANCE & VULNERABILITY ENGINE  ║
║               MADE BY DRACXX                ║
╚════════════════════════════════════════════╝
```

> **EXPLOITATION: PERMANENTLY DISABLED.**  
> DRACXX performs reconnaissance, detection, correlation, and reporting only.  
> It never executes exploits, payloads, brute force, or any offensive action.  
> See [SECURITY.md](SECURITY.md) for the authorized-use policy.

---

## Why DRACXX?

Most “security frameworks” blur the line between detection and exploitation.  
DRACXX deliberately does **not**.

| Capability                    | Status          |
|-------------------------------|-----------------|
| Passive & active recon        | Yes             |
| Safe vulnerability detection  | Yes (Nuclei safe tags only) |
| Real CVE/CPE version matching | Yes             |
| EPSS + CISA KEV enrichment    | Yes             |
| Weighted risk scoring         | Yes             |
| Dual-mode AI analysis         | Yes (advisory only) |
| Multi-format reporting        | Yes             |
| Exploits / RCE / brute force  | Permanently disabled |

---

## Features

- **CLI-first** (Typer + Rich) + polished **interactive console** (`dracxx >`)
- **Randomized cosmetic startup** — multiple original ASCII banners (never affects logic)
- **Strict scope control** — domain/CIDR allowlists, exclusions, confirmation gating
- **Concurrent recon pipeline** — subdomain enumeration, port/service discovery, tech detection
- **Vulnerability detection** — Nuclei restricted to safe tags (`cve`, `exposure`, `misconfig`, `tech`…); intrusive/RCE tags excluded
- **CVE Intelligence Engine** — real version-range evaluation (`>=2.0.0 and <2.4.15`), NVD + FIRST EPSS + CISA KEV
- **Confidence & Risk engines** — documented weighted scoring (not a naive CVSS+EPSS sum)
- **Finding deduplication** across scanners into one canonical finding
- **Dual-mode AI** — remote APIs (Anthropic / OpenAI / Google-compatible) or local (Ollama / LM Studio / vLLM). AI receives structured JSON only and never executes commands
- **Multi-format reporting** — terminal, JSON, CSV, Markdown, HTML
- **SQLite storage** with PostgreSQL-compatible SQLAlchemy schema
- **Graceful degradation** — missing tools are skipped, never crash the run

---

## Architecture

```
dracxx/
├── cli/                 Typer CLI entrypoint
├── console/             Interactive DRACXX shell
├── core/
│   ├── scope.py         Strict allowlist / exclusion logic
│   └── workflow.py      Concurrent orchestrator (recon → vuln → CVE → risk)
├── config/              ~/.dracxx/config.yaml loader
├── models/              Pydantic schemas (Finding, Asset, CVEMatch, …)
├── database/            SQLAlchemy + SQLite
├── engines/
│   ├── vulnerability/   Confidence scoring
│   ├── cve/             CVE/CPE correlation + version ranges
│   └── risk/            Weighted risk model (0–100)
├── integrations/        Safe tool adapters (nmap, nuclei, subfinder, httpx, …)
├── providers/           Dual-mode AI abstraction
├── correlation/         Finding deduplication
├── reporting/           Terminal / JSON / CSV / Markdown / HTML
├── startup/             Randomized banners
└── utils/               Version parsing & range evaluation
```

---

## Quick Start

### Update existing install

```bash
cd Dracxx_Toolkit   # or your clone path
chmod +x update.sh
./update.sh
source .venv/bin/activate
dracxx-vuln --version
```

### Kali / Linux Installation

```bash
git clone https://github.com/Veer-habib/Dracxx_Toolkit.git
cd Dracxx_Toolkit
chmod +x install.sh
./install.sh
source .venv/bin/activate
dracxx-vuln --version
```

The installer:
- Checks Python ≥ 3.11
- Creates a virtualenv
- Installs the package
- Initializes `~/.dracxx/` (config + database)
- Detects external tools
- Runs `doctor`

### Usage

```bash
# Quick vulnerability scan (fastest)
dracxx-vuln scan example.com

# Full pipeline — FAST (nuclei + httpx only)
dracxx-vuln workflow example.com --profile FAST --output report.json

# Full pipeline — STANDARD (balanced)
dracxx-vuln workflow example.com --profile STANDARD --output report.json

# Recon only
dracxx-vuln recon example.com --profile DEEP

# Vulnerability detection (safe templates)
dracxx-vuln scan example.com

# CVE correlation
dracxx-vuln cve nginx --version 1.18.0

# Interactive console
dracxx-vuln console

# Health check
dracxx-vuln doctor
dracxx-vuln tools
```

### Interactive Console

```
dracxx-vuln console

dracxx > set target example.com
dracxx > set profile STANDARD
dracxx > workflow
dracxx > findings
dracxx > ai "prioritize the top 3 findings and suggest remediation order"
dracxx > exit
```

---

## Scope & Authorization

DRACXX requires targets to fall within an authorized scope (`dracxx/core/scope.py`).  
CLI/console commands self-derive scope from explicitly provided targets.  
**You must have explicit written authorization** before scanning any system.

Unauthorized scanning may violate the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), or equivalent laws in your jurisdiction.

---

## AI Configuration

Edit `~/.dracxx/config.yaml`:

```yaml
ai:
  mode: api          # api | local
  provider: anthropic
  model: claude-sonnet-4-6
  endpoint: https://api.anthropic.com/v1/messages
  local_endpoint: http://localhost:11434/v1/chat/completions
  local_model: qwen2.5:14b
  temperature: 0.2
```

Set API keys via environment variables (never store secrets in the YAML):

```bash
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
export NVD_API_KEY=...          # strongly recommended
```

---

## Reports

```bash
dracxx-vuln report --fmt markdown --output assessment.md
dracxx-vuln report --fmt html     --output assessment.html
dracxx-vuln report --fmt json     --output assessment.json
dracxx-vuln report --fmt csv      --output assessment.csv
```

---

## Docker (optional)

```bash
docker build -t dracxx-vuln .
docker run --rm -it dracxx-vuln
```

Native installation is preferred for full tool access.

---

## Testing

```bash
pip install -e . pytest pytest-asyncio
pytest -v
```

Tests cover version-range matching, scope enforcement, risk scoring, confidence scoring, deduplication, CLI smoke tests, database writes, and a **guard test ensuring no exploitation constructs exist** in the codebase.

---

## Honest Limitations

- External tool adapters require the corresponding binaries on `PATH`. Missing tools are skipped gracefully.
- CPE normalization uses a curated offline-friendly table; full NVD CPE dictionary coverage requires network + API key.
- Live NVD / EPSS / KEV enrichment needs network access. An NVD API key is recommended to avoid rate limits.
- AI output is **advisory only** — scanner and database evidence remain authoritative.

---

## Security Policy

See [SECURITY.md](SECURITY.md).  
DRACXX permanently does **not** implement exploits, payloads, reverse shells, RCE, credential attacks, brute force, privilege escalation, persistence, malware, data exfiltration, or denial of service.

---

## License

MIT — see [LICENSE](LICENSE).

---

**DRACXX v1.2.0** — Detection. Intelligence. Nothing more.
