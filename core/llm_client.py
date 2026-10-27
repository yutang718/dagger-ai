"""Attacker/judge LLM abstraction.

Dagger-AI uses an LLM in two red-team roles (the PyRIT pattern):
  * attacker — generates and mutates adversarial prompts toward an objective
  * judge    — decides whether a target response satisfies the objective

Supported providers: `openai` (any OpenAI-compatible base_url incl. vLLM/
Ollama/LM Studio), `anthropic`, and `offline`. Offline mode needs no network
or key and powers deterministic payload selection + heuristic judging so the
platform is fully functional out of the box.
"""
from __future__ import annotations

import json
from typing import Optional

import httpx

from . import config


class LLMClient:
    def __init__(self, provider: str, base_url: str, api_key: str, model: str):
        self.provider = provider
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model

    @classmethod
    def attacker(cls) -> "LLMClient":
        return cls(config.ATTACKER_PROVIDER, config.ATTACKER_BASE_URL,
                   config.ATTACKER_API_KEY, config.ATTACKER_MODEL)

    @property
    def online(self) -> bool:
        return self.provider in ("openai", "anthropic") and bool(self.api_key or self.base_url)

    def complete(self, system: str, user: str, temperature: float = 0.9) -> str:
        """Single-shot completion. Returns '' on offline/failure so callers can
        fall back to their deterministic path."""
        if not self.online:
            return ""
        try:
            if self.provider == "anthropic":
                return self._anthropic(system, user, temperature)
            return self._openai(system, user, temperature)
        except Exception:
            return ""

    def _openai(self, system: str, user: str, temperature: float) -> str:
        base = self.base_url or "https://api.openai.com/v1"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model or "gpt-4o-mini",
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        with httpx.Client(timeout=config.REQUEST_TIMEOUT) as c:
            r = c.post(f"{base}/chat/completions", headers=headers, json=payload)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]

    def _anthropic(self, system: str, user: str, temperature: float) -> str:
        base = self.base_url or "https://api.anthropic.com/v1"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model or "claude-3-5-sonnet-latest",
            "max_tokens": 1024,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        with httpx.Client(timeout=config.REQUEST_TIMEOUT) as c:
            r = c.post(f"{base}/messages", headers=headers, json=payload)
            r.raise_for_status()
            return "".join(b.get("text", "") for b in r.json().get("content", []))

    def complete_json(self, system: str, user: str) -> Optional[dict]:
        raw = self.complete(system, user, temperature=0.2)
        if not raw:
            return None
        raw = raw.strip()
        # tolerate ```json fences
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1].lstrip("json").strip()
        try:
            return json.loads(raw)
        except Exception:
            return None
