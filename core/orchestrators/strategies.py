"""The three orchestration strategies, fused from the reference tools:

  single_turn     — Garak-style: fire each seed payload once.
  crescendo       — PyRIT-style: escalate benign -> objective across turns.
  tree_of_attacks — PAIR/TAP-style: iteratively refine one prompt using the
                    attacker agent against the target's refusals.

Each returns a list[AttemptRec]. The engine persists them and runs the judge.
"""
from __future__ import annotations

from .. import judge as judging
from ..probes import payloads as P
from ..probes.base import Probe
from ..targets import TargetClient
from .base import AttackerAgent, AttemptRec, StepRec

STRATEGIES = {
    "single_turn": "Single-Turn Sweep",
    "crescendo": "Crescendo (multi-turn escalation)",
    "tree_of_attacks": "Tree-of-Attacks (adaptive refinement)",
}


def run(strategy: str, probe: Probe, target: TargetClient, attacker: AttackerAgent,
        max_turns: int) -> list[AttemptRec]:
    fn = {
        "single_turn": _single_turn,
        "crescendo": _crescendo,
        "tree_of_attacks": _tree_of_attacks,
    }.get(strategy, _single_turn)
    return fn(probe, target, attacker, max_turns)


def _single_turn(probe, target, attacker, max_turns):
    attempts = []
    for seed in probe.seeds():
        resp, ms = target.send(seed.prompt)
        jr = judging.judge(probe, probe.objective, resp)
        attempts.append(AttemptRec(
            technique=seed.technique, objective=probe.objective,
            steps=[StepRec("attack", seed.prompt, resp, seed.note, ms)],
            success=jr.success, score=jr.score, evidence=jr.evidence, rationale=jr.rationale,
        ))
    return attempts


def _crescendo(probe, target, attacker, max_turns):
    """Walk a benign->malicious ladder; stop early on success."""
    steps, history = [], []
    ladder = P.CRESCENDO_LADDER[:max_turns] if probe.id in ("prompt_injection", "jailbreak") \
        else [s.prompt for s in probe.seeds()][:max_turns]
    best = None
    for i, prompt in enumerate(ladder):
        resp, ms = target.send(prompt, history)
        note = f"Turn {i+1}/{len(ladder)}: escalation step"
        steps.append(StepRec("attack", prompt, resp, note, ms))
        history += [{"role": "user", "content": prompt},
                    {"role": "assistant", "content": resp}]
        jr = judging.judge(probe, probe.objective, resp)
        if best is None or jr.score > best.score:
            best = jr
        if jr.success:
            break
    return [AttemptRec(
        technique="crescendo", objective=probe.objective, steps=steps,
        success=best.success, score=best.score, evidence=best.evidence, rationale=best.rationale,
    )]


def _tree_of_attacks(probe, target, attacker, max_turns):
    """Adaptive refinement: keep mutating one prompt until success or budget."""
    attempts = []
    for seed in probe.seeds()[:3]:  # a few independent branches
        steps = []
        prompt = seed.prompt
        last_resp = ""
        best = None
        for depth in range(max_turns):
            resp, ms = target.send(prompt)
            note = f"Branch '{seed.technique}' depth {depth+1}: " + (
                seed.note if depth == 0 else "adaptive refinement after refusal")
            steps.append(StepRec("attack", prompt, resp, note, ms))
            jr = judging.judge(probe, probe.objective, resp)
            if best is None or jr.score > best.score:
                best = jr
            if jr.success:
                break
            prompt = attacker.refine(probe.objective, prompt, resp, seed.prompt)
            last_resp = resp
        attempts.append(AttemptRec(
            technique=f"tree:{seed.technique}", objective=probe.objective, steps=steps,
            success=best.success, score=best.score, evidence=best.evidence, rationale=best.rationale,
        ))
    return attempts
