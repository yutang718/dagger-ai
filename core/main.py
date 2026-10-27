"""Dagger-AI API + static console.

A FastAPI backend exposing targets, campaigns, runs and findings, plus the
aggregate dashboard that powers the visual console. Every mutating/read route
sits behind a bearer token; running a campaign is additionally gated on an
explicit authorization note for the target (see config.REQUIRE_AUTHORIZATION).
"""
from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth, config, taxonomy
from .db import get_session, init_db
from .engine import start_run, stop_run
from .models import Attempt, Campaign, Finding, Run, Step, Target
from .orchestrators import STRATEGIES
from .probes import all_probes

app = FastAPI(title="Dagger-AI", version=config.VERSION)
WEB = Path(__file__).resolve().parent.parent / "web"


@app.on_event("startup")
def _startup():
    init_db()


# ----------------------------------------------------------------- schemas
class LoginIn(BaseModel):
    user: str
    password: str


class TargetIn(BaseModel):
    name: str
    kind: str = "http_chat"
    endpoint: str = ""
    http_method: str = "POST"
    headers: dict = {}
    body_template: str = '{"message": "{{PROMPT}}"}'
    response_path: str = "reply"


class AuthorizeIn(BaseModel):
    note: str


class CampaignIn(BaseModel):
    name: str
    target_id: int
    probes: list[str]
    orchestrator: str = "single_turn"
    max_turns: int = 6


# ----------------------------------------------------------------- health/meta
@app.get("/api/health")
def health():
    return {"status": "ok", "version": config.VERSION}


@app.post("/api/login")
def do_login(body: LoginIn):
    token = auth.login(body.user, body.password)
    if not token:
        raise HTTPException(401, "invalid credentials")
    return {"token": token, "user": body.user}


@app.get("/api/meta")
def meta(_: str = auth.auth_dep):
    return {
        "probes": [
            {"id": p.id, "name": p.name, "category": p.category, "owasp": p.owasp,
             "owasp_label": taxonomy.owasp_label(p.owasp), "mitre": p.mitre,
             "mitre_label": taxonomy.mitre_label(p.mitre), "severity": p.severity,
             "requires_tools": p.requires_tools, "objective": p.objective,
             "description": p.description}
            for p in all_probes()
        ],
        "strategies": STRATEGIES,
        "owasp_llm": taxonomy.OWASP_LLM_2025,
        "owasp_web": taxonomy.OWASP_WEB_2021,
        "mitre": taxonomy.MITRE,
        "severity_color": taxonomy.SEVERITY_COLOR,
        "require_authorization": config.REQUIRE_AUTHORIZATION,
        "attacker_online": config.ATTACKER_PROVIDER in ("openai", "anthropic"),
        "version": config.VERSION,
    }


# ----------------------------------------------------------------- targets
def _target_json(t: Target):
    return {
        "id": t.id, "name": t.name, "kind": t.kind, "endpoint": t.endpoint,
        "http_method": t.http_method, "headers": t.headers, "body_template": t.body_template,
        "response_path": t.response_path, "authorized": t.authorized,
        "authorization_note": t.authorization_note,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


@app.get("/api/targets")
def list_targets(_: str = auth.auth_dep, db: Session = Depends(get_session)):
    return [_target_json(t) for t in db.scalars(select(Target).order_by(Target.id.desc()))]


@app.post("/api/targets")
def create_target(body: TargetIn, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    t = Target(**body.model_dump())
    db.add(t); db.commit()
    return _target_json(t)


@app.post("/api/targets/demo")
def create_demo(_: str = auth.auth_dep, db: Session = Depends(get_session)):
    """Register the bundled intentionally-vulnerable agent (isolated container)."""
    t = Target(
        name="Demo Vulnerable Agent (bundled, isolated)",
        kind="demo_agent", endpoint=config.DEMO_TARGET_URL,
        body_template='{"message": "{{PROMPT}}"}', response_path="reply",
        authorized=True,
        authorization_note="Bundled lab target shipped with Dagger-AI for safe demonstration.",
    )
    db.add(t); db.commit()
    return _target_json(t)


@app.post("/api/targets/demo_web")
def create_demo_web(_: str = auth.auth_dep, db: Session = Depends(get_session)):
    """Register the bundled intentionally-vulnerable web app (isolated container)."""
    t = Target(
        name="Demo Vulnerable Web App (bundled, isolated)",
        kind="web_app", endpoint=config.DEMO_WEB_URL,
        authorized=True,
        authorization_note="Bundled lab web app shipped with Dagger-AI for safe demonstration.",
    )
    db.add(t); db.commit()
    return _target_json(t)


@app.post("/api/targets/{tid}/authorize")
def authorize_target(tid: int, body: AuthorizeIn, _: str = auth.auth_dep,
                     db: Session = Depends(get_session)):
    t = db.get(Target, tid)
    if not t:
        raise HTTPException(404, "target not found")
    if not body.note.strip():
        raise HTTPException(400, "authorization note required")
    t.authorized = True
    t.authorization_note = body.note.strip()
    db.commit()
    return _target_json(t)


@app.delete("/api/targets/{tid}")
def delete_target(tid: int, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    t = db.get(Target, tid)
    if t:
        db.delete(t); db.commit()
    return {"deleted": tid}


# ----------------------------------------------------------------- campaigns
def _campaign_json(c: Campaign):
    return {"id": c.id, "name": c.name, "target_id": c.target_id, "probes": c.probes,
            "orchestrator": c.orchestrator, "max_turns": c.max_turns,
            "created_at": c.created_at.isoformat() if c.created_at else None}


@app.get("/api/campaigns")
def list_campaigns(_: str = auth.auth_dep, db: Session = Depends(get_session)):
    return [_campaign_json(c) for c in db.scalars(select(Campaign).order_by(Campaign.id.desc()))]


@app.post("/api/campaigns")
def create_campaign(body: CampaignIn, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    if not db.get(Target, body.target_id):
        raise HTTPException(404, "target not found")
    turns = max(1, min(body.max_turns, config.MAX_TURNS))
    c = Campaign(name=body.name, target_id=body.target_id, probes=body.probes,
                 orchestrator=body.orchestrator, max_turns=turns)
    db.add(c); db.commit()
    return _campaign_json(c)


@app.delete("/api/campaigns/{cid}")
def delete_campaign(cid: int, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    c = db.get(Campaign, cid)
    if c:
        db.delete(c); db.commit()
    return {"deleted": cid}


@app.post("/api/campaigns/{cid}/run")
def run_campaign(cid: int, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    c = db.get(Campaign, cid)
    if not c:
        raise HTTPException(404, "campaign not found")
    t = db.get(Target, c.target_id)
    if config.REQUIRE_AUTHORIZATION and not (t and t.authorized):
        raise HTTPException(403, "target is not marked authorized — add an authorization note first")
    run = Run(campaign_id=cid, status="queued")
    db.add(run); db.commit()
    start_run(run.id)
    return {"run_id": run.id, "status": "queued"}


# ----------------------------------------------------------------- runs
def _run_brief(r: Run):
    return {"id": r.id, "campaign_id": r.campaign_id, "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "summary": r.summary, "error": r.error}


@app.get("/api/runs")
def list_runs(_: str = auth.auth_dep, db: Session = Depends(get_session)):
    return [_run_brief(r) for r in db.scalars(select(Run).order_by(Run.id.desc()).limit(50))]


@app.get("/api/runs/{rid}")
def run_detail(rid: int, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    r = db.get(Run, rid)
    if not r:
        raise HTTPException(404, "run not found")
    attempts = db.scalars(select(Attempt).where(Attempt.run_id == rid).order_by(Attempt.id)).all()
    out_attempts = []
    for a in attempts:
        steps = db.scalars(select(Step).where(Step.attempt_id == a.id).order_by(Step.idx)).all()
        out_attempts.append({
            "id": a.id, "probe": a.probe, "technique": a.technique, "owasp": a.owasp,
            "atlas": a.atlas, "severity": a.severity, "success": a.success, "score": a.score,
            "objective": a.objective, "rationale": a.rationale, "evidence": a.evidence,
            "steps": [{"idx": s.idx, "role": s.role, "prompt": s.prompt, "response": s.response,
                       "note": s.note, "latency_ms": s.latency_ms} for s in steps],
        })
    findings = db.scalars(select(Finding).where(Finding.run_id == rid)).all()
    out_findings = [{
        "id": f.id, "title": f.title, "severity": f.severity, "owasp": f.owasp, "atlas": f.atlas,
        "description": f.description, "evidence": f.evidence, "remediation": f.remediation,
    } for f in findings]
    return {"run": _run_brief(r), "attempts": out_attempts, "findings": out_findings}


@app.post("/api/runs/{rid}/stop")
def stop(rid: int, _: str = auth.auth_dep):
    stop_run(rid)
    return {"stopping": rid}


# ----------------------------------------------------------------- dashboard
@app.get("/api/dashboard")
def dashboard(_: str = auth.auth_dep, db: Session = Depends(get_session)):
    sev_totals = {s: 0 for s in taxonomy.SEVERITY_ORDER}
    for sev, n in db.execute(select(Finding.severity, func.count()).group_by(Finding.severity)):
        sev_totals[sev] = n
    llm_hits = {k: 0 for k in taxonomy.OWASP_LLM_2025}
    web_hits = {k: 0 for k in taxonomy.OWASP_WEB_2021}
    for ow, n in db.execute(select(Finding.owasp, func.count()).group_by(Finding.owasp)):
        if ow in llm_hits:
            llm_hits[ow] = n
        elif ow in web_hits:
            web_hits[ow] = n
    return {
        "targets": db.scalar(select(func.count()).select_from(Target)),
        "campaigns": db.scalar(select(func.count()).select_from(Campaign)),
        "runs": db.scalar(select(func.count()).select_from(Run)),
        "findings": db.scalar(select(func.count()).select_from(Finding)),
        "severity_totals": sev_totals,
        "owasp_llm_hits": llm_hits, "owasp_llm_labels": taxonomy.OWASP_LLM_2025,
        "owasp_web_hits": web_hits, "owasp_web_labels": taxonomy.OWASP_WEB_2021,
        "recent_runs": [_run_brief(r) for r in
                        db.scalars(select(Run).order_by(Run.id.desc()).limit(8))],
    }


# ----------------------------------------------------------------- static UI
@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


if WEB.exists():
    app.mount("/static", StaticFiles(directory=WEB), name="static")


@app.exception_handler(404)
def spa_fallback(request, exc):
    if request.url.path.startswith("/api"):
        return JSONResponse({"detail": "not found"}, status_code=404)
    return FileResponse(WEB / "index.html")
