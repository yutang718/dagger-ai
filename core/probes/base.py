"""Probe base class + registry.

A probe is an attack module (Garak's term). It declares taxonomy metadata,
an objective (what success means), a set of seed payloads, and an offline
heuristic judge. Orchestrators drive probes against a target; the judge
module decides success (LLM judge when configured, else probe heuristic).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

REGISTRY: dict[str, "Probe"] = {}


def register(cls):
    inst = cls()
    REGISTRY[inst.id] = inst
    return cls


@dataclass
class Seed:
    technique: str
    prompt: str
    note: str


@dataclass
class JudgeResult:
    success: bool
    score: float
    evidence: str = ""
    rationale: str = ""


class Probe:
    id: str = "base"
    name: str = "Base probe"
    owasp: str = ""
    atlas: str = ""
    severity: str = "info"
    # Whether this probe is only meaningful against tool/agent targets.
    requires_tools: bool = False
    objective: str = ""
    description: str = ""
    remediation: str = ""

    def seeds(self) -> list[Seed]:
        raise NotImplementedError

    # Offline heuristic judge. Subclasses override for probe-specific signals.
    def judge_offline(self, response: str) -> JudgeResult:
        return JudgeResult(False, 0.0)

    # Helper: keyword / canary detection
    @staticmethod
    def _contains(text: str, *needles: str) -> bool:
        low = (text or "").lower()
        return any(n.lower() in low for n in needles)

    @staticmethod
    def _refused(text: str) -> bool:
        return bool(re.search(
            r"\b(i can('|no)?t|i am not able|i'm sorry|cannot assist|i won'?t|against my|"
            r"not able to help|unable to comply)\b", (text or "").lower()))
