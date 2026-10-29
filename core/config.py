"""Central configuration for Dagger-AI.

All settings come from environment variables so the whole platform runs
unchanged inside Docker. Nothing here requires an external API key: if no
attacker/judge LLM is configured, Dagger-AI falls back to a deterministic
offline engine so it works out-of-the-box.
"""
from __future__ import annotations

import os
from pathlib import Path


def _env(*names: str, default: str = "") -> str:
    for n in names:
        v = os.getenv(n)
        if v is not None and v != "":
            return v
    return default


def _bool(name: str, default: bool = False) -> bool:
    return _env(name, default=str(default)).lower() in ("1", "true", "yes", "on")


# --- storage -------------------------------------------------------------
DATA_DIR = Path(_env("DAGGER_DATA_DIR", default="/data"))
DB_PATH = DATA_DIR / "dagger.db"
SNAPSHOT_DIR = DATA_DIR / "snapshots"

# --- auth ----------------------------------------------------------------
SECRET_KEY = _env("DAGGER_SECRET_KEY", default="change-me-to-a-long-random-string")
TOKEN_HOURS = int(_env("DAGGER_TOKEN_HOURS", default="12"))
ADMIN_USER = _env("DAGGER_ADMIN_USER", default="admin")
ADMIN_PASSWORD = _env("DAGGER_ADMIN_PASSWORD", default="Admin@12345")

# --- attacker / judge LLM ------------------------------------------------
# Dagger-AI uses an LLM to *generate and mutate* adversarial prompts and to
# *judge* whether a target's response constitutes a successful attack.
# Any OpenAI-compatible endpoint works (OpenAI, vLLM, Ollama, LM Studio...),
# or Anthropic. Leave unset to use the deterministic offline engine.
ATTACKER_PROVIDER = _env("DAGGER_ATTACKER_PROVIDER", default="offline")  # offline|openai|anthropic
ATTACKER_BASE_URL = _env("DAGGER_ATTACKER_BASE_URL", default="")
ATTACKER_API_KEY = _env("DAGGER_ATTACKER_API_KEY", default="")
ATTACKER_MODEL = _env("DAGGER_ATTACKER_MODEL", default="")
# Azure OpenAI only: api-version (e.g. 2024-10-21). Blank uses the client default.
ATTACKER_API_VERSION = _env("DAGGER_ATTACKER_API_VERSION", default="")

# --- safety / authorization gate ----------------------------------------
# Dagger-AI only attacks systems the operator is authorized to test.
# When REQUIRE_AUTHORIZATION is on (default), every target must carry an
# explicit authorization note before any campaign can run against it.
REQUIRE_AUTHORIZATION = _bool("DAGGER_REQUIRE_AUTHORIZATION", default=True)

# Hard cap so an operator cannot accidentally launch an unbounded campaign.
MAX_TURNS = int(_env("DAGGER_MAX_TURNS", default="8"))
MAX_ATTEMPTS = int(_env("DAGGER_MAX_ATTEMPTS", default="60"))
REQUEST_TIMEOUT = int(_env("DAGGER_REQUEST_TIMEOUT", default="60"))

# The bundled intentionally-vulnerable demo targets (isolated containers).
DEMO_TARGET_URL = _env("DAGGER_DEMO_TARGET_URL", default="http://vulnerable-target:9009/chat")
DEMO_WEB_URL = _env("DAGGER_DEMO_WEB_URL", default="http://vulnerable-webapp:9010")
DEMO_HOST = _env("DAGGER_DEMO_HOST", default="vulnerable-webapp")

# Tool-runner sidecar (AI pentest engine drives real tools through it).
TOOL_RUNNER_URL = _env("DAGGER_TOOL_RUNNER_URL", default="http://tool-runner:9020")
TOOL_RUNNER_TOKEN = _env("DAGGER_TOOL_RUNNER_TOKEN", default="")
# Max tool invocations per engagement (budget guard).
MAX_TOOL_STEPS = int(_env("DAGGER_MAX_TOOL_STEPS", default="12"))

VERSION = "1.7.5"
