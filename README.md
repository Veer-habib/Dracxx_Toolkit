# DRACXX

**AI-Driven Reconnaissance & Vulnerability Intelligence Framework**
**MADE BY DRACXX**

```
╔════════════════════════════════════════════╗
║                 D R A C X X                 ║
║   AI RECONNAISSANCE & VULNERABILITY ENGINE  ║
║               MADE BY DRACXX                ║
╚════════════════════════════════════════════╝
```

> **EXPLOITATION: PERMANENTLY DISABLED.** DRACXX performs
> reconnaissance, detection, correlation, and reporting only. It never
> executes exploits, payloads, brute force, or any offensive action.
> See [SECURITY.md](SECURITY.md) for the authorized-use policy.

## Features

- **CLI-first** (Typer/Rich) plus a polished **interactive console**
  (`dracxx-vuln console`) with a `dracxx >` prompt.
- **Randomized cosmetic startup** — 5+ original ASCII banners, taglines,
  session IDs. Randomization never touches scan logic or scope.
- **Strict scope control** — domain/CIDR allowlists, exclusions,
  confirmation gating before active scanning.
- **Recon**: passive OSINT (Subfinder/Amass/Assetfinder), DNS, network
  enumeration (Nmap/Naabu), web/API/JS recon (httpx/Katana/ffuf).
- **Vulnerability detection**: Nuclei (safe/detection tags only), Nikto,
  testssl.sh, OWASP ZAP baseline — never exploit-tagged templates.
- **CVE/CPE Intelligence Engine**: real version-range evaluation
  (`>=2.0.0 and <2.4.15` style), NVD + FIRST EPSS + CISA KEV enrichment.
  A product-name match alone is never treated as proof of a
  vulnerability.
- **Confidence & Risk engines**: documented weighted scoring (not a
  naive CVSS+EPSS sum) — see `dracxx/engines/risk/engine.py`.
- **Finding deduplication** across multiple scanners into one canonical
  finding.
- **Dual-mode AI engine**: remote APIs (Anthropic/OpenAI/Google-compatible)
  or local OpenAI-compatible endpoints (Ollama/LM Studio/vLLM). AI only
  receives structured JSON findings and never executes commands.
- **Multi-format reporting**: terminal, JSON, CSV, Markdown, HTML.
- **SQLite** storage with a PostgreSQL-compatible SQLAlchemy schema.
- **Graceful degradation** — missing tools are skipped, never crash the
  run (`dracxx-vuln tools` / `dracxx-vuln doctor`).

## Architecture

```
dracxx/
├── cli/            Typer CLI entrypoint
├── console/        Interactive DRACXX shell
├── core/           scope control, workflow orchestrator
├── config/         ~/.dracxx/config.yaml loader
├── models/         Pydantic schema (Finding, Asset, CVEMatch, ...)
├── database/       SQLAlchemy models + session (SQLite)
├── engines/
│   ├── vulnerability/   confidence scoring
│   ├── cve/              CVE/CPE correlation engine
│   └── risk/             weighted risk model
├── integrations/   tool adapters (nmap, nuclei, subfinder, httpx, ...)
├── providers/      AI provider abstraction (API + local)
├── correlation/    finding deduplication
├── reporting/      terminal/json/csv/markdown/html reports
├── startup/        randomized banners
└── utils/          version parsing/range evaluation
```

## Kali Linux Installation

```bash
git clone <YOUR_REPOSITORY>
cd dracxx
chmod +x install.sh
./install.sh
```

The installer detects Kali, checks Python 3.11+, creates a venv,
installs dependencies, initializes the database/config, detects
external tools, and runs `doctor`.

```bash
source .venv/bin/activate
dracxx-vuln
# or
python3 -m dracxx
```

## CLI Usage

```bash
dracxx-vuln recon example.com --profile STANDARD
dracxx-vuln scan example.com
dracxx-vuln workflow example.com --output report.json
dracxx-vuln cve nginx --version 1.18.0
dracxx-vuln findings
dracxx-vuln report --fmt html --output report.html
dracxx-vuln modules
dracxx-vuln tools
dracxx-vuln doctor
dracxx-vuln config --show
dracxx-vuln history
dracxx-vuln console
dracxx-vuln --version
```

## Interactive Console

```
dracxx-vuln console

dracxx > set target example.com
dracxx > set profile DEEP
dracxx > recon
dracxx > scan
dracxx > workflow
dracxx > cve openssl 1.1.1
dracxx > ai "prioritize the top 3 findings"
dracxx > findings
dracxx > exit
```

## Scope & Authorization

DRACXX requires targets to fall within an authorized scope
(`dracxx/core/scope.py`). CLI/console commands self-derive scope from
explicitly provided targets; production deployments should load a
signed scope file before enabling active scanning.

## AI Configuration

Edit `~/.dracxx/config.yaml`:

```yaml
ai:
  mode: api        # api | local
  provider: anthropic
  model: claude-sonnet-4-6
  endpoint: https://api.anthropic.com/v1/messages
  local_endpoint: http://localhost:11434/v1/chat/completions
  local_model: qwen2.5:14b
  temperature: 0.2
```

Set API keys via environment variables (never in the YAML):

```bash
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
export NVD_API_KEY=...
```

## Reports

```bash
dracxx-vuln report --fmt markdown --output assessment.md
dracxx-vuln report --fmt html --output assessment.html
dracxx-vuln report --fmt json --output assessment.json
dracxx-vuln report --fmt csv --output assessment.csv
```

## Docker

```bash
docker build -t dracxx-vuln .
docker run --rm -it dracxx-vuln
```

Docker is optional — native Kali installation works without it.

## Testing

```bash
pip install -e . pytest pytest-asyncio
pytest -v
```

Covers version-range matching, scope enforcement, risk scoring,
confidence scoring, deduplication, CLI smoke tests, database writes,
and a guard test ensuring no exploitation constructs exist in the
codebase.

## Limitations (honest disclosure)

- Tool adapters (nmap/nuclei/subfinder/etc.) require the corresponding
  binaries on `PATH`; DRACXX detects and gracefully skips missing ones.
- CPE normalization uses a small curated table as an offline-friendly
  fallback, not the full NVD CPE dictionary API.
- NVD/EPSS/KEV enrichment requires network access; an NVD API key is
  recommended to avoid rate limiting.
- `dnsx` adapter is scaffolded but stdin-piping in constrained
  environments may need adjustment for full DNS record enumeration.

## License

MIT — see [LICENSE](LICENSE).
