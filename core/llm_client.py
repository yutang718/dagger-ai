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
        self.last_error = ""   # populated on a failed complete() for diagnostics

    @classmethod
    def attacker(cls) -> "LLMClient":
        # Runtime console config (Settings page) takes precedence over the env
        # defaults so the operator can bring/switch their own LLM live.
        from . import settings
        cfg = settings.llm_config()
        return cls(cfg["provider"], cfg["base_url"], cfg["api_key"], cfg["model"])

    @property
    def online(self) -> bool:
        return self.provider in ("openai", "anthropic", "azure") and bool(self.api_key or self.base_url)

    def complete(self, system: str, user: str, temperature: float = 0.9) -> str:
        """Single-shot completion. Returns '' on offline/failure so callers can
        fall back to their deterministic path. On failure, self.last_error holds
        a human-readable reason (including the provider's response body) so the
        Settings 'test connection' can show what actually went wrong."""
        if not self.online:
            return ""
        self.last_error = ""
        try:
            if self.provider == "anthropic":
                return self._anthropic(system, user, temperature)
            if self.provider == "azure":
                return self._azure(system, user, temperature)
            return self._openai(system, user, temperature)
        except Exception as e:
            detail = f"{type(e).__name__}: {e}"
            resp = getattr(e, "response", None)
            if resp is not None:
                try:
                    detail += " — " + (resp.text or "")[:400]
                except Exception:
                    pass
            self.last_error = detail
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

    # Azure OpenAI uses api-key auth, the deployment in the URL path, and a
    # required api-version. `base_url` is the resource endpoint
    # (https://<resource>.openai.azure.com) OR a full chat-completions URL;
    # `model` is the deployment name. api-version can be given in base_url's
    # query string, else a current stable default is used.
    _AZURE_API_VERSION = "2024-10-21"

    def _azure(self, system: str, user: str, temperature: float) -> str:
        from urllib.parse import urlsplit, parse_qs
        base = self.base_url
        ver = (parse_qs(urlsplit(base).query).get("api-version") or [None])[0] \
            or self._AZURE_API_VERSION
        if "/chat/completions" in base:          # user pasted the full deployment URL
            url = base
            if "api-version=" not in url:
                url += ("&" if "?" in url else "?") + "api-version=" + ver
        else:                                     # build from resource host + deployment
            host = base.split("/openai/")[0].rstrip("/")
            deployment = self.model or "gpt-4o"
            url = f"{host}/openai/deployments/{deployment}/chat/completions?api-version={ver}"
        headers = {"Content-Type": "application/json", "api-key": self.api_key}
        payload = {
            "temperature": temperature,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        with httpx.Client(timeout=config.REQUEST_TIMEOUT) as c:
            r = c.post(url, headers=headers, json=payload)
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
