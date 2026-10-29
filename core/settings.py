"""Runtime settings (operator-configurable from the console).

The attacker/judge LLM can be configured two ways:
  * environment variables (config.ATTACKER_*) — the deployment default, and
  * the console Settings page — stored in the `settings` table under key
    "llm" and taking precedence over the environment at runtime.

This lets an operator "bring their own LLM" (OpenAI-compatible or Anthropic)
and switch it live without restarting the container, while still booting with
a sane default (offline engine) when nothing is configured. The stored API
key never leaves the server: API responses expose only `has_api_key`.
"""
from __future__ import annotations

from typing import Any

from . import config
from .db import SessionLocal
from .models import Setting

LLM_KEY = "llm"
_ALLOWED_PROVIDERS = ("offline", "openai", "anthropic", "azure")


def _get(key: str) -> dict[str, Any]:
    db = SessionLocal()
    try:
        row = db.get(Setting, key)
        return dict(row.value) if row and isinstance(row.value, dict) else {}
    finally:
        db.close()


def _put(key: str, value: dict[str, Any]) -> None:
    db = SessionLocal()
    try:
        row = db.get(Setting, key)
        if row is None:
            db.add(Setting(key=key, value=value))
        else:
            row.value = value
        db.commit()
    finally:
        db.close()


def llm_config() -> dict[str, Any]:
    """Effective attacker/judge LLM config (DB over env). Includes the api_key
    for internal use by LLMClient; never return this straight to the client."""
    stored = _get(LLM_KEY)
    cfg = {
        "provider": config.ATTACKER_PROVIDER,
        "base_url": config.ATTACKER_BASE_URL,
        "api_key": config.ATTACKER_API_KEY,
        "model": config.ATTACKER_MODEL,
        "api_version": config.ATTACKER_API_VERSION,
    }
    cfg.update({k: v for k, v in stored.items() if k in cfg and v is not None})
    cfg["source"] = "console" if stored else "environment"
    return cfg


def llm_config_public() -> dict[str, Any]:
    """Same, but with the key redacted — safe to send to the browser."""
    cfg = llm_config()
    key = cfg.pop("api_key", "")
    cfg["has_api_key"] = bool(key)
    cfg["online"] = cfg["provider"] in ("openai", "anthropic", "azure") and bool(key or cfg["base_url"])
    return cfg


def set_llm_config(provider: str, base_url: str, model: str,
                   api_key: str | None, api_version: str = "") -> dict[str, Any]:
    """Persist an LLM config change. `api_key=None` keeps the existing key;
    an empty string clears it. Returns the public (redacted) config."""
    if provider not in _ALLOWED_PROVIDERS:
        raise ValueError(f"unknown provider '{provider}'")
    stored = _get(LLM_KEY)
    stored["provider"] = provider
    stored["base_url"] = (base_url or "").strip()
    stored["model"] = (model or "").strip()
    stored["api_version"] = (api_version or "").strip()
    if api_key is not None:
        stored["api_key"] = api_key.strip()
    _put(LLM_KEY, stored)
    return llm_config_public()
