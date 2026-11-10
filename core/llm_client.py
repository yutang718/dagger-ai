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

import contextvars
import json
import re
import time
from typing import Optional

import httpx

from . import config, pricing

# A transient provider error (rate limit / 5xx) should not silently drop the
# whole engagement to the offline engine — retry once before giving up.
_RETRYABLE = {429, 500, 502, 503, 504}

# Analytical reasoning (planning, interpreting, validating, judging) wants a low,
# focused temperature; only adversarial PROMPT generation benefits from a high one.
ANALYTIC_TEMP = 0.3
CREATIVE_TEMP = 0.9


class UsageMeter:
    """Accumulates token usage across the LLM calls of one engagement so the
    console can show tokens used and an estimated USD cost."""

    def __init__(self):
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.by_model: dict[str, dict] = {}

    def add(self, model: str, prompt_tokens: int, completion_tokens: int):
        self.calls += 1
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        m = self.by_model.setdefault(model or "(default)",
                                     {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0})
        m["calls"] += 1
        m["prompt_tokens"] += prompt_tokens
        m["completion_tokens"] += completion_tokens

    def as_dict(self) -> dict:
        total_cost = 0.0
        models = {}
        for model, u in self.by_model.items():
            c = pricing.cost_usd(model, u["prompt_tokens"], u["completion_tokens"])
            total_cost += c
            models[model] = {**u, "cost_usd": round(c, 6)}
        return {
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.prompt_tokens + self.completion_tokens,
            "cost_usd": round(total_cost, 6),
            "by_model": models,
        }


# Per-engagement meter, scoped to the running thread's context.
_METER: contextvars.ContextVar[Optional[UsageMeter]] = contextvars.ContextVar("llm_meter", default=None)


def new_meter() -> UsageMeter:
    m = UsageMeter()
    _METER.set(m)
    return m


def _record(model: str, prompt_tokens: int, completion_tokens: int):
    m = _METER.get()
    if m is not None:
        m.add(model, int(prompt_tokens or 0), int(completion_tokens or 0))


class LLMClient:
    def __init__(self, provider: str, base_url: str, api_key: str, model: str,
                 api_version: str = ""):
        self.provider = provider
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.api_version = (api_version or "").strip()  # Azure only
        self.last_error = ""   # populated on a failed complete() for diagnostics
        # Newer OpenAI/Azure models (gpt-5, o-series) reject `max_tokens` and/or a
        # non-default `temperature`. We learn the right shape from the provider's
        # 400 and remember it on the instance, so classic backends (vLLM/Ollama)
        # and reasoning models both work without the operator configuring anything.
        self._token_param = "max_tokens"
        self._no_temp = False
        if re.match(r"(?i)^(gpt-5|o[1-4]\b)", (model or "").strip()):
            self._token_param = "max_completion_tokens"   # known to require it

    @classmethod
    def attacker(cls) -> "LLMClient":
        # Runtime console config (Settings page) takes precedence over the env
        # defaults so the operator can bring/switch their own LLM live.
        from . import settings
        cfg = settings.llm_config()
        return cls(cfg["provider"], cfg["base_url"], cfg["api_key"], cfg["model"],
                   cfg.get("api_version", ""))

    @classmethod
    def judge(cls) -> "LLMClient":
        """The success judge. Uses a separate judge LLM when any DAGGER_JUDGE_*
        override is set (so the attacker never scores its own output), else the
        attacker's config — judging always runs at a low, conservative temperature."""
        from . import settings
        base = settings.llm_config()
        prov = config.JUDGE_PROVIDER or base["provider"]
        return cls(prov, config.JUDGE_BASE_URL or base["base_url"],
                   config.JUDGE_API_KEY or base["api_key"],
                   config.JUDGE_MODEL or base["model"],
                   config.JUDGE_API_VERSION or base.get("api_version", ""))

    @property
    def online(self) -> bool:
        return self.provider in ("openai", "anthropic", "azure") and bool(self.api_key or self.base_url)

    def complete(self, system: str, user: str, temperature: float = CREATIVE_TEMP,
                 max_tokens: int = 1024) -> str:
        """Single-shot completion. Returns '' on offline/failure so callers can
        fall back to their deterministic path. Retries once on a transient
        provider error (rate limit / 5xx) so one blip doesn't silently demote the
        whole engagement to the offline engine. On final failure, self.last_error
        holds a human-readable reason (incl. the provider's response body) so the
        Settings 'test connection' can show what actually went wrong."""
        if not self.online:
            return ""
        self.last_error = ""
        for attempt in range(2):   # initial try + one retry on a transient error
            try:
                if self.provider == "anthropic":
                    return self._anthropic(system, user, temperature, max_tokens)
                if self.provider == "azure":
                    return self._azure(system, user, temperature, max_tokens)
                return self._openai(system, user, temperature, max_tokens)
            except Exception as e:
                status = getattr(getattr(e, "response", None), "status_code", None)
                detail = f"{type(e).__name__}: {e}"
                resp = getattr(e, "response", None)
                if resp is not None:
                    try:
                        detail += " — " + (resp.text or "")[:400]
                    except Exception:
                        pass
                self.last_error = detail
                if status in _RETRYABLE and attempt == 0:
                    time.sleep(0.8)          # brief backoff, then retry once
                    continue
                return ""
        return ""

    def _chat_completion(self, url: str, headers: dict, system: str, user: str,
                         temperature: float, max_tokens: int, model: str | None = None) -> str:
        """Post an OpenAI-style chat completion, adapting the payload to the model:
        newer models (gpt-5 / o-series) reject `max_tokens` and/or a non-default
        `temperature`, so on the provider's 400 we switch to `max_completion_tokens`
        / drop `temperature`, remember it, and retry — classic backends keep working."""
        messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
        for _ in range(3):                       # at most two shape adaptations
            payload = {"messages": messages, self._token_param: max_tokens}
            if model:
                payload["model"] = model
            if not self._no_temp:
                payload["temperature"] = temperature
            with httpx.Client(timeout=config.REQUEST_TIMEOUT) as c:
                r = c.post(url, headers=headers, json=payload)
            if r.status_code == 400:
                low = (r.text or "").lower()
                if "unsupported" in low or "not supported" in low:
                    if "max_completion_tokens" in low and self._token_param != "max_completion_tokens":
                        self._token_param = "max_completion_tokens"; continue
                    if "temperature" in low and not self._no_temp:
                        self._no_temp = True; continue
            r.raise_for_status()
            data = r.json()
            u = data.get("usage") or {}
            _record(self.model, u.get("prompt_tokens", 0), u.get("completion_tokens", 0))
            return data["choices"][0]["message"]["content"]
        return ""

    def _openai(self, system: str, user: str, temperature: float, max_tokens: int = 1024) -> str:
        base = self.base_url or "https://api.openai.com/v1"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return self._chat_completion(f"{base}/chat/completions", headers, system, user,
                                     temperature, max_tokens, model=self.model or "gpt-4o-mini")

    # Azure OpenAI uses api-key auth, the deployment in the URL path, and a
    # required api-version. `base_url` is the resource endpoint
    # (https://<resource>.openai.azure.com) OR a full chat-completions URL;
    # `model` is the deployment name. api-version can be given in base_url's
    # query string, else a current stable default is used.
    _AZURE_API_VERSION = "2024-10-21"

    def _azure(self, system: str, user: str, temperature: float, max_tokens: int = 1024) -> str:
        from urllib.parse import urlsplit, parse_qs
        base = self.base_url
        # Precedence: the explicit api-version field, then one in the URL, then default.
        ver = self.api_version \
            or (parse_qs(urlsplit(base).query).get("api-version") or [None])[0] \
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
        return self._chat_completion(url, headers, system, user, temperature, max_tokens)

    def _anthropic(self, system: str, user: str, temperature: float, max_tokens: int = 1024) -> str:
        base = self.base_url or "https://api.anthropic.com/v1"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model or "claude-3-5-sonnet-latest",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        with httpx.Client(timeout=config.REQUEST_TIMEOUT) as c:
            r = c.post(f"{base}/messages", headers=headers, json=payload)
            r.raise_for_status()
            data = r.json()
            u = data.get("usage") or {}
            _record(self.model, u.get("input_tokens", 0), u.get("output_tokens", 0))
            return "".join(b.get("text", "") for b in data.get("content", []))

    def complete_json(self, system: str, user: str, max_tokens: int = 700) -> Optional[dict]:
        raw = self.complete(system, user, temperature=ANALYTIC_TEMP, max_tokens=max_tokens)
        return _loads_lax(raw)


def _loads_lax(raw: str) -> Optional[dict]:
    """Parse a JSON object out of a model reply, tolerating code fences and
    surrounding prose (some models narrate before/after the JSON)."""
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith("```"):                      # strip a ```json … ``` fence
        raw = raw.strip("`")
        raw = re.sub(r"^\s*json\b", "", raw, flags=re.I).strip()
    try:
        return json.loads(raw)
    except Exception:
        pass
    m = re.search(r"\{.*\}", raw, re.S)            # first balanced-ish {...} block
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            return None
    return None
