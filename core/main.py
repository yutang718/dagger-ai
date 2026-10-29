"""Dagger-AI API + static console.

A FastAPI backend exposing targets, campaigns, runs and findings, plus the
aggregate dashboard that powers the visual console. Every mutating/read route
sits behind a bearer token; running a campaign is additionally gated on an
explicit authorization note for the target (see config.REQUIRE_AUTHORIZATION).
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth, config, profile, settings, taxonomy, tools_client, translations
from .db import get_session, init_db
from .engine import start_run, stop_run
from .llm_client import LLMClient
from .models import Attempt, Campaign, Finding, Run, Step, Target
from .operator import MODULE_META, MODULES
from .orchestrators import STRATEGIES
from .probes import all_probes

app = FastAPI(title="Dagger-AI", version=config.VERSION)
WEB = Path(__file__).resolve().parent.parent / "web"


@app.on_event("startup")
def _startup():
    init_db()
    # Runs that were in-flight when the process last stopped cannot resume (their
    # worker threads are gone), so mark them stopped instead of leaving orphans.
    from sqlalchemy import update
    from .db import SessionLocal
    db = SessionLocal()
    try:
        db.execute(update(Run).where(Run.status.in_(("running", "queued"))).values(status="stopped"))
        db.commit()
    finally:
        db.close()


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


class TargetPatch(BaseModel):
    name: str | None = None
    kind: str | None = None
    endpoint: str | None = None
    http_method: str | None = None
    headers: dict | None = None
    body_template: str | None = None
    response_path: str | None = None


class AuthorizeIn(BaseModel):
    note: str


class CampaignIn(BaseModel):
    name: str
    target_id: int
    probes: list[str]
    orchestrator: str = "single_turn"
    max_turns: int = 6
    session_cookies: str = ""


class CampaignPatch(BaseModel):
    name: str | None = None
    probes: list[str] | None = None
    orchestrator: str | None = None
    max_turns: int | None = None
    session_cookies: str | None = None


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
    def _probe(p):
        zh = translations.PROBE_ZH.get(p.id, (p.name, p.description))
        return {"id": p.id, "name": p.name, "name_zh": zh[0], "category": p.category,
                "owasp": p.owasp, "owasp_label": taxonomy.owasp_label(p.owasp), "mitre": p.mitre,
                "mitre_label": taxonomy.mitre_label(p.mitre), "severity": p.severity,
                "requires_tools": p.requires_tools, "objective": p.objective,
                "description": p.description, "description_zh": zh[1]}
    llm = settings.llm_config_public()
    return {
        "probes": [_probe(p) for p in all_probes()],
        "strategies": STRATEGIES,
        "strategies_zh": translations.STRATEGY_ZH,
        "pentest_modules": [
            {"id": mid, "name": MODULE_META[mid][0], "name_zh": translations.MODULE_ZH.get(mid, MODULE_META[mid][0]),
             "tool": MODULE_META[mid][1], "phase": MODULES[mid][0]}
            for mid in MODULES
        ],
        "phases_zh": translations.PHASE_ZH,
        "owasp_llm": taxonomy.OWASP_LLM_2025,
        "owasp_llm_zh": translations.OWASP_LLM_ZH,
        "owasp_web": taxonomy.OWASP_WEB_2021,
        "owasp_web_zh": translations.OWASP_WEB_ZH,
        "mitre": taxonomy.MITRE,
        "severity_color": taxonomy.SEVERITY_COLOR,
        "severity_zh": translations.SEVERITY_ZH,
        "require_authorization": config.REQUIRE_AUTHORIZATION,
        "attacker_online": llm["online"],
        "llm": llm,
        "version": config.VERSION,
    }


# ----------------------------------------------------------------- settings
class LLMSettingsIn(BaseModel):
    provider: str = "offline"       # offline | openai | azure | anthropic
    base_url: str = ""
    model: str = ""
    api_key: str | None = None      # None keeps the stored key; "" clears it
    api_version: str = ""           # Azure only


@app.get("/api/settings/llm")
def get_llm_settings(_: str = auth.auth_dep):
    return settings.llm_config_public()


@app.put("/api/settings/llm")
def put_llm_settings(body: LLMSettingsIn, _: str = auth.auth_dep):
    try:
        return settings.set_llm_config(body.provider, body.base_url, body.model,
                                        body.api_key, body.api_version)
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/settings/llm/test")
def test_llm_settings(_: str = auth.auth_dep):
    """Probe the configured attacker/judge LLM with a tiny completion so the
    operator gets immediate feedback that their endpoint/key works."""
    import time
    client = LLMClient.attacker()
    if not client.online:
        return {"ok": False, "online": False,
                "detail": "No online provider configured — using the offline engine."}
    t0 = time.time()
    out = client.complete("You are a connectivity check.",
                          "Reply with the single word: PONG", temperature=0.0)
    ms = int((time.time() - t0) * 1000)
    ok = bool(out.strip())
    return {"ok": ok, "online": True, "latency_ms": ms,
            "model": client.model or "(provider default)", "sample": (out or "")[:120],
            "detail": "Response received." if ok else
                      (client.last_error or "No response — check base URL / key / model.")}


# ----------------------------------------------------------------- targets
def _target_json(t: Target):
    return {
        "id": t.id, "name": t.name, "kind": t.kind, "endpoint": t.endpoint,
        "http_method": t.http_method, "headers": t.headers, "body_template": t.body_template,
        "response_path": t.response_path, "authorized": t.authorized,
        "allow_internal": bool(t.allow_internal),
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


@app.patch("/api/targets/{tid}")
def update_target(tid: int, body: TargetPatch, _: str = auth.auth_dep,
                  db: Session = Depends(get_session)):
    t = db.get(Target, tid)
    if not t:
        raise HTTPException(404, "target not found")
    data = body.model_dump(exclude_unset=True)
    # Authorization is granted for a specific endpoint; if the endpoint changes,
    # revoke it so a re-authorization is required before the new host can be run.
    if "endpoint" in data and data["endpoint"] != t.endpoint:
        t.authorized = False
        t.authorization_note = ""
    for k, v in data.items():
        setattr(t, k, v)
    db.commit()
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


@app.post("/api/targets/demo_host")
def create_demo_host(_: str = auth.auth_dep, db: Session = Depends(get_session)):
    """Register the bundled web app as a HOST target for a full AI pentest."""
    t = Target(
        name="Demo Host — AI pentest (bundled, isolated)",
        kind="host", endpoint=config.DEMO_WEB_URL,
        authorized=True, allow_internal=True,
        authorization_note="Bundled isolated lab host shipped with Dagger-AI for safe demonstration.",
    )
    db.add(t); db.commit()
    return _target_json(t)


@app.get("/api/tools/status")
def tools_status(_: str = auth.auth_dep):
    """Which pentest binaries are installed in the tool-runner right now."""
    return {"runner_url": config.TOOL_RUNNER_URL, "tools": tools_client.available()}


@app.get("/api/targets/{tid}/profile")
def target_profile(tid: int, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    """Target intel / BOM, derived from everything its engagements observed —
    open ports, OS, web-server versions, components, discovered paths."""
    t = db.get(Target, tid)
    if not t:
        raise HTTPException(404, "target not found")
    camp_ids = [c for c in db.scalars(select(Campaign.id).where(Campaign.target_id == tid))]
    run_ids = [r for r in db.scalars(select(Run.id).where(Run.campaign_id.in_(camp_ids)))] if camp_ids else []
    blobs, findings, sev = [], [], {}
    vulns = {}
    last = None
    _rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    _cls = lambda s: re.split(r"[:：—]", s or "")[0].strip()
    if run_ids:
        for (resp,) in db.execute(select(Step.response).join(Attempt, Step.attempt_id == Attempt.id)
                                  .where(Attempt.run_id.in_(run_ids)).limit(5000)):
            if resp:
                blobs.append(resp)
        # De-duplicate across runs first: the same issue (title+owasp+evidence)
        # found in several engagements of this target is ONE distinct vulnerability.
        distinct = {}
        for f in db.scalars(select(Finding).where(Finding.run_id.in_(run_ids))):
            dk = (f.title.strip().lower(), f.owasp or "", (f.evidence or "")[:200].strip().lower())
            distinct.setdefault(dk, f)
        for f in distinct.values():
            findings.append({"title": f.title, "severity": f.severity, "owasp": f.owasp,
                             "evidence": f.evidence})
            sev[f.severity] = sev.get(f.severity, 0) + 1
            # vulnerabilities grouped by issue class; count = distinct issues in it
            key = (_cls(f.title).lower(), f.owasp or "", f.severity)
            v = vulns.get(key)
            if v:
                v["count"] += 1
            else:
                vulns[key] = {"title": _cls(f.title), "severity": f.severity, "owasp": f.owasp,
                              "atlas": f.atlas, "description": f.description,
                              "remediation": f.remediation, "evidence": f.evidence, "count": 1}
        last = db.scalar(select(func.max(Run.finished_at)).where(Run.id.in_(run_ids)))
    prof = profile.build_profile(t.endpoint, blobs, findings)
    prof.update({
        "target": _target_json(t),
        "runs": len(run_ids),
        "findings_by_sev": sev,
        "findings_total": sum(sev.values()),
        "vulnerabilities": sorted(vulns.values(), key=lambda v: (_rank.get(v["severity"], 0), v["count"]),
                                  reverse=True),
        "last_seen": last.isoformat() if last else None,
    })
    return prof


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


# -------------------------------------------------- targeted single-vuln verify
class VerifyIn(BaseModel):
    target_id: int
    probe: str            # probe id, CVE id, or a name/id substring
    url: str = ""         # optional same-host endpoint override
    cookies: str = ""


def _resolve_probe(q: str):
    """Resolve a user-typed vulnerability name/id/CVE to a web probe."""
    from .probes import base as pbase
    q = (q or "").strip()
    if not q:
        return None
    p = pbase.REGISTRY.get(q)
    if p is None:
        p = pbase.verifier_for(q)          # a CVE id -> its verifier probe
    if p is None:
        ql = q.lower()
        for c in all_probes():
            if getattr(c, "category", "") != "web":
                continue
            cves = " ".join(getattr(c, "cves", ()))
            if ql in c.id.lower() or ql in c.name.lower() or ql in cves.lower():
                p = c
                break
    return p if (p is not None and getattr(p, "category", "") == "web") else None


@app.post("/api/verify")
def verify_vuln(body: VerifyIn, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    """Run ONE probe against a registered authorized target for a quick,
    preliminary verification — returns the exact payload, result and evidence.
    Benign proof-of-concept only (no shell / weaponization)."""
    import httpx
    t = db.get(Target, body.target_id)
    if not t:
        raise HTTPException(404, "target not found")
    if config.REQUIRE_AUTHORIZATION and not t.authorized:
        raise HTTPException(403, "target is not marked authorized — authorize it first")
    p = _resolve_probe(body.probe)
    if p is None:
        raise HTTPException(404, f"no web vulnerability matches '{body.probe}'")
    target_url = (body.url or "").strip() or (t.endpoint or "")
    if not target_url:
        raise HTTPException(400, "no target URL")
    if body.url:   # override must stay on the authorized target's host
        from urllib.parse import urlparse
        oh, th = urlparse(body.url).hostname, urlparse(t.endpoint or "").hostname
        if oh and th and oh != th:
            raise HTTPException(400, "override URL must be the same host as the target")
    ck = tools_client.cookie_header(body.cookies)
    hdrs = {"User-Agent": "Dagger-AI/verify"}
    if ck:
        hdrs["Cookie"] = ck
    http = httpx.Client(timeout=config.REQUEST_TIMEOUT, follow_redirects=True, headers=hdrs)
    try:
        recs = p.execute(target_url, http)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"probe error: {e}")
    finally:
        http.close()
    a = recs[0] if recs else None
    if a is None:
        raise HTTPException(500, "probe produced no result")
    return {
        "probe": p.id, "name": p.name, "severity": p.severity, "owasp": p.owasp,
        "atlas": getattr(p, "mitre", ""), "target": target_url,
        "success": a.success, "score": a.score, "objective": a.objective,
        "evidence": a.evidence, "rationale": a.rationale, "phase": a.phase or "exploit",
        "steps": [{"idx": i, "role": s.role, "prompt": s.prompt, "response": s.response,
                   "note": s.note, "latency_ms": s.latency_ms} for i, s in enumerate(a.steps)],
    }


# ----------------------------------------------------------------- campaigns
def _campaign_json(c: Campaign):
    return {"id": c.id, "name": c.name, "target_id": c.target_id, "probes": c.probes,
            "orchestrator": c.orchestrator, "max_turns": c.max_turns,
            "session_cookies": getattr(c, "session_cookies", "") or "",
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
                 orchestrator=body.orchestrator, max_turns=turns,
                 session_cookies=(body.session_cookies or "")[:8000])
    db.add(c); db.commit()
    return _campaign_json(c)


@app.patch("/api/campaigns/{cid}")
def update_campaign(cid: int, body: CampaignPatch, _: str = auth.auth_dep,
                    db: Session = Depends(get_session)):
    c = db.get(Campaign, cid)
    if not c:
        raise HTTPException(404, "campaign not found")
    if body.name is not None:
        c.name = body.name
    if body.probes is not None:
        c.probes = body.probes
    if body.orchestrator is not None:
        c.orchestrator = body.orchestrator
    if body.max_turns is not None:
        c.max_turns = max(1, min(body.max_turns, config.MAX_TURNS))
    if body.session_cookies is not None:
        c.session_cookies = body.session_cookies[:8000]
    db.commit()
    return _campaign_json(c)


@app.delete("/api/campaigns/{cid}")
def delete_campaign(cid: int, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    c = db.get(Campaign, cid)
    if c:
        db.delete(c); db.commit()
    return {"deleted": cid}


@app.post("/api/campaigns/{cid}/run")
def run_campaign(cid: int, lang: str = "en", _: str = auth.auth_dep,
                 db: Session = Depends(get_session)):
    c = db.get(Campaign, cid)
    if not c:
        raise HTTPException(404, "campaign not found")
    t = db.get(Target, c.target_id)
    if config.REQUIRE_AUTHORIZATION and not (t and t.authorized):
        raise HTTPException(403, "target is not marked authorized — add an authorization note first")
    run = Run(campaign_id=cid, status="queued")
    db.add(run); db.commit()
    start_run(run.id, "zh" if lang == "zh" else "en")
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
            "id": a.id, "probe": a.probe, "technique": a.technique, "phase": a.phase or "",
            "owasp": a.owasp, "atlas": a.atlas, "severity": a.severity, "success": a.success,
            "score": a.score,
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
    # Count DISTINCT vulnerabilities per target (the same issue re-found across a
    # target's runs is one), so totals are meaningful rather than inflated by
    # repeated scans.
    run_target = {rid: tid for rid, tid in db.execute(
        select(Run.id, Campaign.target_id).join(Campaign, Run.campaign_id == Campaign.id)).all()}
    sev_totals = {s: 0 for s in taxonomy.SEVERITY_ORDER}
    llm_hits = {k: 0 for k in taxonomy.OWASP_LLM_2025}
    web_hits = {k: 0 for k in taxonomy.OWASP_WEB_2021}
    seen = set()
    findings_count = 0
    for f in db.scalars(select(Finding)):
        tid = run_target.get(f.run_id)
        dk = (tid, f.title.strip().lower(), f.owasp or "", (f.evidence or "")[:200].strip().lower())
        if dk in seen:
            continue
        seen.add(dk)
        findings_count += 1
        sev_totals[f.severity] = sev_totals.get(f.severity, 0) + 1
        if f.owasp in llm_hits:
            llm_hits[f.owasp] += 1
        elif f.owasp in web_hits:
            web_hits[f.owasp] += 1
    # Aggregate LLM token usage + estimated cost across all runs.
    usage = {"calls": 0, "total_tokens": 0, "cost_usd": 0.0}
    for (summ,) in db.execute(select(Run.summary)):
        u = (summ or {}).get("usage") or {}
        usage["calls"] += u.get("calls", 0)
        usage["total_tokens"] += u.get("total_tokens", 0)
        usage["cost_usd"] += u.get("cost_usd", 0.0)
    usage["cost_usd"] = round(usage["cost_usd"], 4)
    return {
        "llm_usage": usage,
        "targets": db.scalar(select(func.count()).select_from(Target)),
        "campaigns": db.scalar(select(func.count()).select_from(Campaign)),
        "runs": db.scalar(select(func.count()).select_from(Run)),
        "findings": findings_count,
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
