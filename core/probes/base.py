"""Probe base classes + registry.

Two probe families share one registry and one result shape (so the UI, graph
and findings work identically for both):

  * LLM probes  (category="llm")  — declare seeds() + judge_offline(); driven
    by the orchestrators against a chat/agent target.
  * Web probes  (category="web")  — implement execute(base_url); run their own
    DAST-style HTTP request/response flow against a web-app target.

Every probe maps to an OWASP code and a single MITRE id (ATLAS for LLM,
ATT&CK for web).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

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
    category: str = "llm"          # "llm" | "web"
    owasp: str = ""               # OWASP code (LLM01.. or A01..)
    mitre: str = ""              # MITRE id (AML.T.... or T....)
    severity: str = "info"
    requires_tools: bool = False  # LLM: only meaningful vs tool/agent targets
    objective: str = ""
    description: str = ""
    remediation: str = ""

    # --- LLM probe interface ---
    def seeds(self) -> list[Seed]:
        raise NotImplementedError

    def judge_offline(self, response: str) -> JudgeResult:
        return JudgeResult(False, 0.0)

    # --- helpers ---
    @staticmethod
    def _contains(text: str, *needles: str) -> bool:
        low = (text or "").lower()
        return any(n.lower() in low for n in needles)

    @staticmethod
    def _refused(text: str) -> bool:
        return bool(re.search(
            r"\b(i can('|no)?t|i am not able|i'm sorry|cannot assist|i won'?t|against my|"
            r"not able to help|unable to comply)\b", (text or "").lower()))


from ..records import AttemptRec, StepRec  # noqa: E402


class WebProbe(Probe):
    """Base for DAST-style web probes. Subclasses implement execute()."""
    category = "web"

    def execute(self, base_url: str, http) -> list[AttemptRec]:
        """Run the probe against base_url using an httpx.Client `http`.
        Return a list of AttemptRec (each with its request/response steps)."""
        raise NotImplementedError

    # convenience: build a single-step attempt
    @staticmethod
    def attempt(technique, objective, request, response, note, success, score, evidence, rationale,
                latency_ms=0):
        return AttemptRec(
            technique=technique, objective=objective,
            steps=[StepRec("request", request, response, note, latency_ms)],
            success=success, score=score, evidence=evidence, rationale=rationale,
        )
