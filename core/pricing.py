"""Approximate LLM pricing for the token/cost estimate shown in the console.

Prices are USD per 1,000,000 tokens as (input, output), list prices for common
models. They are estimates for operator awareness, not billing — providers
change prices and may bill differently (cached tokens, batch, etc.). Match is
by case-insensitive substring of the configured model name; unknown models fall
back to DEFAULT. Override/extend via DAGGER_LLM_PRICES (JSON) if needed.
"""
from __future__ import annotations

import json
import os

# (input_per_1M, output_per_1M) USD
PRICES: dict[str, tuple[float, float]] = {
    # OpenAI
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4.1": (2.00, 8.00),
    "o4-mini": (1.10, 4.40),
    "o3-mini": (1.10, 4.40),
    "gpt-3.5-turbo": (0.50, 1.50),
    # Anthropic
    "claude-3-5-haiku": (0.80, 4.00),
    "claude-3-haiku": (0.25, 1.25),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-7-sonnet": (3.00, 15.00),
    "claude-sonnet-4": (3.00, 15.00),
    "claude-opus-4": (15.00, 75.00),
    "claude-3-opus": (15.00, 75.00),
}

DEFAULT: tuple[float, float] = (1.00, 3.00)   # unknown model fallback


def _load_overrides() -> None:
    raw = os.getenv("DAGGER_LLM_PRICES", "")
    if not raw:
        return
    try:
        for k, v in json.loads(raw).items():
            PRICES[k.lower()] = (float(v[0]), float(v[1]))
    except Exception:
        pass


_load_overrides()


def price_for(model: str) -> tuple[float, float]:
    m = (model or "").lower()
    for key, price in PRICES.items():
        if key in m:
            return price
    return DEFAULT


def cost_usd(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    pin, pout = price_for(model)
    return round(prompt_tokens / 1e6 * pin + completion_tokens / 1e6 * pout, 6)
