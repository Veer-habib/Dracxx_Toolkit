"""Configuration loading from ~/.dracxx/config.yaml and environment variables."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml
from pydantic import BaseModel

CONFIG_DIR = Path(os.path.expanduser("~/.dracxx"))
CONFIG_PATH = CONFIG_DIR / "config.yaml"

DEFAULT_CONFIG = {
    "ai": {
        "mode": "api",  # api | local
        "provider": "anthropic",  # anthropic | openai | google | other
        "model": "claude-sonnet-4-6",
        "endpoint": "https://api.anthropic.com/v1/messages",
        "local_endpoint": "http://localhost:11434/v1/chat/completions",
        "local_model": "qwen2.5:14b",
        "temperature": 0.2,
    },
    "apis": {
        "shodan_key": "",
        "censys_id": "",
        "censys_secret": "",
        "securitytrails_key": "",
        "nvd_api_key": "",
    },
    "scan": {
        "default_profile": "STANDARD",
        "concurrency": 10,
        "timeout_seconds": 30,
        "rate_limit_per_sec": 5,
    },
    "scope": {
        "require_confirmation": True,
    },
}


class AIConfig(BaseModel):
    mode: str = "api"
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-6"
    endpoint: str = "https://api.anthropic.com/v1/messages"
    local_endpoint: str = "http://localhost:11434/v1/chat/completions"
    local_model: str = "qwen2.5:14b"
    temperature: float = 0.2


class DracxxConfig(BaseModel):
    ai: AIConfig = AIConfig()
    apis: Dict[str, str] = {}
    scan: Dict[str, Any] = {}
    scope: Dict[str, Any] = {}


def ensure_config() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        with open(CONFIG_PATH, "w") as f:
            yaml.safe_dump(DEFAULT_CONFIG, f, sort_keys=False)
    return CONFIG_PATH


def load_config() -> DracxxConfig:
    ensure_config()
    with open(CONFIG_PATH) as f:
        raw = yaml.safe_load(f) or {}
    # Environment variable overrides (never hardcode secrets)
    raw.setdefault("apis", {})
    raw["apis"]["anthropic_api_key"] = os.environ.get("ANTHROPIC_API_KEY", raw["apis"].get("anthropic_api_key", ""))
    raw["apis"]["openai_api_key"] = os.environ.get("OPENAI_API_KEY", raw["apis"].get("openai_api_key", ""))
    raw["apis"]["shodan_key"] = os.environ.get("SHODAN_API_KEY", raw["apis"].get("shodan_key", ""))
    raw["apis"]["nvd_api_key"] = os.environ.get("NVD_API_KEY", raw["apis"].get("nvd_api_key", ""))
    return DracxxConfig(**raw)


def save_config(cfg: DracxxConfig):
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(cfg.model_dump(), f, sort_keys=False)
