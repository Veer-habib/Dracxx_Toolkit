"""Dual-mode AI provider abstraction.

Supports OpenAI, Anthropic, Google Gemini (native API), and local
OpenAI-compatible endpoints (Ollama, LM Studio, vLLM).

The AI NEVER executes security commands or exploits. It only receives
structured findings (JSON) and returns analysis text. Deterministic
scanner/database evidence remains authoritative — AI output is
advisory only.
"""
from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List

import httpx


SYSTEM_PROMPT = """You are a defensive security analyst assisting DRACXX,
a non-exploitative reconnaissance and vulnerability intelligence
framework. You will be given structured findings (JSON) only.

Rules:
- Never suggest, generate, or describe exploit code, payloads, or attack
  commands.
- Explain vulnerabilities, validate CVE/CPE correlation plausibility,
  flag likely false positives, and recommend remediation.
- Treat deterministic scanner/database evidence as authoritative; do not
  override confirmed data, only add analysis.
- Be concise and cite finding IDs when referencing specific items.
"""


class AIProvider(ABC):
    def __init__(self, model: str, temperature: float = 0.2, **kwargs):
        self.model = model
        self.temperature = temperature
        self.extra = kwargs

    @abstractmethod
    async def analyze(self, findings: List[Dict[str, Any]], instruction: str) -> str:
        ...

    @staticmethod
    def _build_payload(findings: List[Dict[str, Any]], instruction: str) -> str:
        return json.dumps({"instruction": instruction, "findings": findings}, default=str)[:16000]


class AnthropicProvider(AIProvider):
    def __init__(self, model: str, api_key: str, temperature: float = 0.2,
                 endpoint: str = "https://api.anthropic.com/v1/messages", **kwargs):
        super().__init__(model, temperature, **kwargs)
        self.api_key = api_key
        self.endpoint = endpoint

    async def analyze(self, findings, instruction: str) -> str:
        if not self.api_key:
            return "[AI unavailable: no Anthropic API key configured]"
        payload = self._build_payload(findings, instruction)
        body = {
            "model": self.model,
            "max_tokens": 1500,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": payload}],
        }
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(self.endpoint, json=body, headers=headers, timeout=60)
                resp.raise_for_status()
                data = resp.json()
                return "".join(
                    b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"
                )
        except Exception as e:
            return f"[AI analysis failed: {e}]"


class OpenAICompatibleProvider(AIProvider):
    """OpenAI and local OpenAI-compatible servers (Ollama/LM Studio/vLLM)."""

    def __init__(self, model: str, api_key: str, temperature: float = 0.2,
                 endpoint: str = "https://api.openai.com/v1/chat/completions", **kwargs):
        super().__init__(model, temperature, **kwargs)
        self.api_key = api_key
        self.endpoint = endpoint

    async def analyze(self, findings, instruction: str) -> str:
        if not self.api_key and "localhost" not in self.endpoint and "127.0.0.1" not in self.endpoint:
            return "[AI unavailable: no API key configured]"
        payload = self._build_payload(findings, instruction)
        body = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": payload},
            ],
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(self.endpoint, json=body, headers=headers, timeout=90)
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            return f"[AI analysis failed: {e}]"


class GeminiProvider(AIProvider):
    """Google Gemini native generateContent API (no browser involved)."""

    def __init__(self, model: str, api_key: str, temperature: float = 0.2, **kwargs):
        super().__init__(model, temperature, **kwargs)
        self.api_key = api_key
        # Strip accidental "models/" prefix
        if self.model.startswith("models/"):
            self.model = self.model[len("models/"):]

    async def analyze(self, findings, instruction: str) -> str:
        if not self.api_key:
            return "[AI unavailable: no GOOGLE_API_KEY / Gemini key configured]"
        payload = self._build_payload(findings, instruction)
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent"
        )
        body = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": payload}],
                }
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": 2048,
            },
        }
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json=body, headers=headers, timeout=90)
                if resp.status_code >= 400:
                    # include short body for debugging
                    detail = resp.text[:300] if resp.text else resp.reason_phrase
                    return f"[AI analysis failed: HTTP {resp.status_code} — {detail}]"
                data = resp.json()
                parts = (
                    data.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [])
                )
                text = "".join(p.get("text", "") for p in parts)
                return text or "[AI returned empty response]"
        except Exception as e:
            return f"[AI analysis failed: {e}]"


def build_provider(cfg) -> AIProvider:
    """cfg is AIConfig (mode, provider, model, endpoint, ...)."""
    if cfg.mode == "local":
        return OpenAICompatibleProvider(
            model=getattr(cfg, "local_model", "llama3"),
            api_key="",
            temperature=cfg.temperature,
            endpoint=cfg.local_endpoint,
        )

    provider = (cfg.provider or "").lower().strip()

    if provider == "anthropic":
        return AnthropicProvider(
            model=cfg.model,
            api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            temperature=cfg.temperature,
            endpoint=cfg.endpoint or "https://api.anthropic.com/v1/messages",
        )

    if provider in ("google", "gemini"):
        key = (
            os.environ.get("GOOGLE_API_KEY")
            or os.environ.get("GEMINI_API_KEY")
            or ""
        )
        model = cfg.model or "gemini-2.0-flash"
        return GeminiProvider(model=model, api_key=key, temperature=cfg.temperature)

    # default: OpenAI
    return OpenAICompatibleProvider(
        model=cfg.model,
        api_key=os.environ.get("OPENAI_API_KEY", ""),
        temperature=cfg.temperature,
        endpoint=cfg.endpoint or "https://api.openai.com/v1/chat/completions",
    )
