"""Probe package. Importing registers all built-in probes."""
from . import builtin  # noqa: F401
from .base import REGISTRY, JudgeResult, Probe, Seed


def all_probes():
    return list(REGISTRY.values())


def get(probe_id: str) -> Probe | None:
    return REGISTRY.get(probe_id)
