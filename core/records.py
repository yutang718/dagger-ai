"""Neutral result records shared by probes and orchestrators (no deps)."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class StepRec:
    role: str              # "attack" (llm) | "request" (web)
    prompt: str            # attack prompt OR http request text
    response: str          # target response OR http response excerpt
    note: str = ""         # human-readable "what this step does"
    latency_ms: int = 0


@dataclass
class AttemptRec:
    technique: str
    objective: str
    steps: list[StepRec] = field(default_factory=list)
    success: bool = False
    score: float = 0.0
    evidence: str = ""
    rationale: str = ""
