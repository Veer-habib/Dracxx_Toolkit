#!/usr/bin/env bash
set -e
echo "=== DRACXX Installer ==="

if grep -qi kali /etc/os-release 2>/dev/null; then
  echo "[+] Kali Linux detected"
else
  echo "[!] Non-Kali system detected — continuing anyway"
fi

PYVER=$(python3 -c 'import sys; print(sys.version_info>=(3,11))')
if [ "$PYVER" != "True" ]; then
  echo "[!] Python 3.11+ required"; exit 1
fi
echo "[+] Python version OK"

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
echo "[+] Dependencies installed"

mkdir -p ~/.dracxx
python3 -c "from dracxx.database.db import init_db; init_db()"
python3 -c "from dracxx.config.config import ensure_config; ensure_config()"
echo "[+] Database and config initialized"

echo "[+] Detecting external security tools..."
for t in nmap nuclei subfinder amass assetfinder httpx katana ffuf nikto testssl.sh naabu zap-baseline.py; do
  if command -v "$t" >/dev/null 2>&1; then
    echo "  [✓] $t"
  else
    echo "  [✗] $t (optional, install via apt/go for full coverage)"
  fi
done

dracxx-vuln doctor || true

echo ""
echo "=== DRACXX installed ==="
echo "Run: source .venv/bin/activate && dracxx-vuln"
