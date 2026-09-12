#!/usr/bin/env bash
# DRACXX quick updater — run from the repo root after git clone or anytime
set -e
echo "=== DRACXX Updater ==="

# Must be in repo root
if [ ! -f "pyproject.toml" ] || [ ! -d "dracxx" ]; then
  echo "[!] Run this from the DRACXX repo root (where pyproject.toml lives)"
  exit 1
fi

# Prefer git pull if this is a git clone
if [ -d ".git" ]; then
  echo "[+] Pulling latest from origin..."
  git pull --ff-only origin main 2>/dev/null || git pull --ff-only origin master 2>/dev/null || {
    echo "[!] git pull failed — continuing with local tree"
  }
else
  echo "[!] Not a git repo — updating installed package from local files only"
fi

# Ensure venv
if [ ! -d ".venv" ]; then
  echo "[+] Creating virtualenv..."
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "[+] Upgrading pip and reinstalling DRACXX (editable)..."
pip install --upgrade pip -q
pip install -e . -q

# Refresh config/db if needed (non-destructive)
python3 -c "from dracxx.config.config import ensure_config; ensure_config()" 2>/dev/null || true
python3 -c "from dracxx.database.db import init_db; init_db()" 2>/dev/null || true

VER=$(python3 -c "from dracxx import __version__; print(__version__)" 2>/dev/null || echo "unknown")
echo ""
echo "=== DRACXX updated to v${VER} ==="
echo "Activate with:  source .venv/bin/activate"
echo "Then run:       dracxx-vuln --version"
echo "                dracxx-vuln findings"
