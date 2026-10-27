"""Probe package. Importing registers all built-in probes (LLM + web)."""
from . import builtin  # noqa: F401  (LLM probes)
from . import web      # noqa: F401  (web-app probes)
from .base import REGISTRY, JudgeResult, Probe, Seed, WebProbe


def all_probes():
    return list(REGISTRY.values())


def get(probe_id: str) -> Probe | None:
    return REGISTRY.get(probe_id)
