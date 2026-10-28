"""Campaign execution engine.

Runs in a background thread per Run. For each selected probe it invokes the
chosen orchestrator against the target, persists every attempt and its steps
(the structured "attach" trail), then distills successful attempts into
Findings with severity, OWASP/ATLAS mapping, evidence and remediation.
"""
from __future__ import annotations

import threading
from datetime import datetime

import httpx

from . import config, taxonomy
from .db import SessionLocal
from .models import Attempt, Campaign, Finding, Run, Step, Target
from .orchestrators import AttackerAgent
from .orchestrators import run as orchestrate
from .probes import get as get_probe
from .targets import TargetClient

_RUNNING: set[int] = set()


def start_run(run_id: int) -> None:
    t = threading.Thread(target=_execute, args=(run_id,), daemon=True)
    t.start()


def stop_run(run_id: int) -> None:
    _RUNNING.discard(run_id)


def _execute(run_id: int) -> None:
    _RUNNING.add(run_id)
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if not run:
            return
        campaign = db.get(Campaign, run.campaign_id)
        target = db.get(Target, campaign.target_id)
        run.status = "running"
        db.commit()

        attacker = AttackerAgent()
        tclient = TargetClient(target)
        http = httpx.Client(timeout=config.REQUEST_TIMEOUT, follow_redirects=True,
                            headers={"User-Agent": "Dagger-AI/1.0"})
        ctx = {"attempts": 0, "success": 0,
               "sev": {s: 0 for s in taxonomy.SEVERITY_ORDER}}

        if target.kind == "host":
            # AI pentest engagement: the operator drives real tools + web probes.
            from . import operator
            attempts = operator.run_engagement(
                target.endpoint or "", campaign.probes or list(operator.MODULES),
                bool(target.allow_internal),
                min(campaign.max_turns or config.MAX_TOOL_STEPS, config.MAX_TOOL_STEPS),
                attacker.client)
            for a in attempts:
                if run_id not in _RUNNING:
                    run.status = "stopped"; break
                _persist(db, run_id, a, None, ctx)
                db.commit()
        else:
            for probe_id in (campaign.probes or []):
                if run_id not in _RUNNING:
                    run.status = "stopped"
                    break
                probe = get_probe(probe_id)
                if not probe:
                    continue
                if probe.category == "web":
                    try:
                        attempts = probe.execute(target.endpoint or "", http)
                    except Exception as e:
                        from .records import AttemptRec, StepRec
                        attempts = [AttemptRec(probe.id, probe.objective,
                                    [StepRec("request", "(web probe)", f"[probe error] {e}", "")],
                                    False, 0.0, "", f"probe error: {e}")]
                else:
                    attempts = orchestrate(campaign.orchestrator, probe, tclient, attacker,
                                           campaign.max_turns or 6)
                for a in attempts:
                    _persist(db, run_id, a, probe, ctx)
                    db.commit()

        run.summary = {
            "attempts": ctx["attempts"],
            "successes": ctx["success"],
            "severity": ctx["sev"],
            "worst": taxonomy.worst([s for s, n in ctx["sev"].items() if n]),
        }
        if run.status != "stopped":
            run.status = "done"
        run.finished_at = datetime.utcnow()
        db.commit()
    except Exception as e:  # record failure instead of dying silently
        db.rollback()
        run = db.get(Run, run_id)
        if run:
            run.status = "error"
            run.error = str(e)[:2000]
            run.finished_at = datetime.utcnow()
            db.commit()
    finally:
        _RUNNING.discard(run_id)
        try:
            http.close()
        except Exception:
            pass
        db.close()


def _persist(db, run_id, a, probe, ctx):
    """Persist one AttemptRec: its steps, and either its explicit findings list
    (pentest tools) or a probe-derived finding (LLM/web probes)."""
    ctx["attempts"] += 1
    # Determine attempt severity + taxonomy.
    if a.findings:
        sev = taxonomy.worst([f.get("severity", "info") for f in a.findings])
        owasp = a.findings[0].get("owasp", "")
        mitre = a.findings[0].get("mitre", "")
    elif a.success and probe is not None:
        sev, owasp, mitre = probe.severity, probe.owasp, probe.mitre
    else:
        sev = "info"
        owasp = probe.owasp if probe else ""
        mitre = probe.mitre if probe else ""
    row = Attempt(
        run_id=run_id, probe=(probe.id if probe else a.technique), technique=a.technique,
        phase=getattr(a, "phase", ""), owasp=owasp, atlas=mitre, severity=sev,
        success=a.success, score=a.score, objective=a.objective,
        rationale=a.rationale, evidence=a.evidence,
    )
    db.add(row); db.flush()
    for i, s in enumerate(a.steps):
        db.add(Step(attempt_id=row.id, idx=i, role=s.role, prompt=s.prompt,
                    response=s.response, note=s.note, latency_ms=s.latency_ms))
    # Findings
    if a.findings:
        for f in a.findings:
            fs = f.get("severity", "info")
            db.add(Finding(
                run_id=run_id, attempt_id=row.id,
                title=f.get("title", "finding"), severity=fs,
                owasp=f.get("owasp", ""), atlas=f.get("mitre", ""),
                description=f.get("description", ""), evidence=f.get("evidence", ""),
                remediation=f.get("remediation", "")))
            ctx["success"] += 1
            ctx["sev"][fs] = ctx["sev"].get(fs, 0) + 1
    elif a.success and probe is not None:
        db.add(_finding(run_id, row.id, probe, a))
        ctx["success"] += 1
        ctx["sev"][probe.severity] = ctx["sev"].get(probe.severity, 0) + 1


def _finding(run_id, attempt_id, probe, a) -> Finding:
    owlabel = taxonomy.owasp_label(probe.owasp)
    return Finding(
        run_id=run_id, attempt_id=attempt_id,
        title=f"{probe.name} — {owlabel}",
        severity=probe.severity, owasp=probe.owasp, atlas=probe.mitre,
        description=f"{probe.description}\n\nTechnique: {a.technique}\nJudge: {a.rationale}",
        evidence=a.evidence or "(see attempt steps)",
        remediation=probe.remediation,
    )
