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
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth, config, profile, report, scoring, settings, taxonomy, tools_client, translations
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


class LoginFields(BaseModel):
    login_mode: str = ""          # "" | form | json | bearer
    login_url: str = ""
    login_user: str = ""
    login_password: str = ""
    login_user_field: str = "username"
    login_pass_field: str = "password"
    login_token_path: str = "token"


class CampaignIn(LoginFields):
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
    login_mode: str | None = None
    login_url: str | None = None
    login_user: str | None = None
    login_password: str | None = None
    login_user_field: str | None = None
    login_pass_field: str | None = None
    login_token_path: str | None = None


class LoginTestIn(LoginFields):
    target_id: int | None = None
    allow_internal: bool = False


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
    last = first = None
    exec_summary = ""
    phases = []
    _rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    _phase_rank = {"recon": 1, "fingerprint": 2, "discovery": 3, "vuln": 4,
                   "vuln-scan": 4, "exploit": 5, "report": 6}
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
            # score pre-scoring rows at read time (CVSS band + CWE mapping)
            _sc = scoring.enrich_finding({"severity": f.severity, "owasp": f.owasp or "",
                                          "title": f.title, "evidence": f.evidence or "",
                                          "cvss": f.cvss or 0.0, "cvss_vector": f.cvss_vector or "",
                                          "cwe": f.cwe or ""})
            # vulnerabilities grouped by issue class; count = distinct issues in it
            key = (_cls(f.title).lower(), f.owasp or "", f.severity)
            v = vulns.get(key)
            if v:
                v["count"] += 1
                if _sc["cvss"] > v["cvss"]:
                    v["cvss"], v["cvss_vector"] = _sc["cvss"], _sc["cvss_vector"]
                v["cwe"] = v["cwe"] or _sc["cwe"]
            else:
                vulns[key] = {"title": _cls(f.title), "severity": f.severity, "owasp": f.owasp,
                              "atlas": f.atlas, "description": f.description,
                              "remediation": f.remediation, "evidence": f.evidence, "count": 1,
                              "cvss": _sc["cvss"], "cvss_vector": _sc["cvss_vector"],
                              "cwe": _sc["cwe"]}
        last = db.scalar(select(func.max(Run.finished_at)).where(Run.id.in_(run_ids)))
        first = db.scalar(select(func.min(Run.started_at)).where(Run.id.in_(run_ids)))
        # Executive summary prose: the operator writes one per run (stored as the
        # "report" step). Surface the most recent so the report reads as analysis,
        # not just a finding count.
        exec_summary = db.scalar(
            select(Step.response).join(Attempt, Step.attempt_id == Attempt.id)
            .where(Attempt.run_id.in_(run_ids), Step.role == "report",
                   Step.response != "").order_by(Step.id.desc()).limit(1)) or ""
        # Kill-chain phases actually exercised, for the methodology section.
        seen = {p for (p,) in db.execute(
            select(Attempt.phase).where(Attempt.run_id.in_(run_ids),
                                        Attempt.phase != "").distinct()) if p}
        seen.discard("report")  # the summary meta-phase, not a kill-chain phase
        phases = sorted(seen, key=lambda p: _phase_rank.get(p, 99))
    prof = profile.build_profile(t.endpoint, blobs, findings)
    prof.update({
        "target": _target_json(t),
        "runs": len(run_ids),
        "findings_by_sev": sev,
        "findings_total": sum(sev.values()),
        "vulnerabilities": sorted(vulns.values(),
                                  key=lambda v: (v.get("cvss", 0), _rank.get(v["severity"], 0), v["count"]),
                                  reverse=True),
        "exec_summary": exec_summary,
        "phases": phases,
        "first_seen": first.isoformat() if first else None,
        "last_seen": last.isoformat() if last else None,
    })
    return prof


def _report_for(tid: int, db: Session) -> dict:
    t = db.get(Target, tid)
    if not t:
        raise HTTPException(404, "target not found")
    return report.build_report(db, t)


def _report_filename(rep: dict, ext: str) -> str:
    base = re.sub(r"[^\w.\-]+", "_", rep["target"]["name"] or "target")
    return f"dagger-report-{base}.{ext}"


@app.get("/api/targets/{tid}/report.json")
def report_json(tid: int, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    rep = _report_for(tid, db)
    return JSONResponse(rep, headers={
        "Content-Disposition": f'attachment; filename="{_report_filename(rep, "json")}"'})


@app.get("/api/targets/{tid}/report.md")
def report_md(tid: int, lang: str = "en", _: str = auth.auth_dep,
              db: Session = Depends(get_session)):
    rep = _report_for(tid, db)
    return PlainTextResponse(report.to_markdown(rep, lang), media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{_report_filename(rep, "md")}"'})


@app.get("/api/targets/{tid}/report.sarif")
def report_sarif(tid: int, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    rep = _report_for(tid, db)
    return JSONResponse(report.to_sarif(rep), headers={
        "Content-Disposition": f'attachment; filename="{_report_filename(rep, "sarif")}"'})


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
    # Never echo the stored password back to the client; expose only whether one
    # is set so the form can show a "saved" placeholder.
    return {"id": c.id, "name": c.name, "target_id": c.target_id, "probes": c.probes,
            "orchestrator": c.orchestrator, "max_turns": c.max_turns,
            "session_cookies": getattr(c, "session_cookies", "") or "",
            "login_mode": getattr(c, "login_mode", "") or "",
            "login_url": getattr(c, "login_url", "") or "",
            "login_user": getattr(c, "login_user", "") or "",
            "login_user_field": getattr(c, "login_user_field", "") or "username",
            "login_pass_field": getattr(c, "login_pass_field", "") or "password",
            "login_token_path": getattr(c, "login_token_path", "") or "token",
            "has_login_password": bool(getattr(c, "login_password", "") or ""),
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
                 session_cookies=(body.session_cookies or "")[:8000],
                 login_mode=(body.login_mode or "").strip()[:10],
                 login_url=(body.login_url or "")[:600],
                 login_user=(body.login_user or "")[:300],
                 login_password=(body.login_password or "")[:300],
                 login_user_field=(body.login_user_field or "username")[:80],
                 login_pass_field=(body.login_pass_field or "password")[:80],
                 login_token_path=(body.login_token_path or "token")[:120])
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
    if body.login_mode is not None:
        c.login_mode = (body.login_mode or "").strip()[:10]
    if body.login_url is not None:
        c.login_url = (body.login_url or "")[:600]
    if body.login_user is not None:
        c.login_user = (body.login_user or "")[:300]
    # Empty password means "keep the saved one" (the form never receives it back);
    # it is cleared when auto-login is turned off (login_mode == "").
    if body.login_password:
        c.login_password = body.login_password[:300]
    if not (c.login_mode or ""):
        c.login_password = ""
    if body.login_user_field is not None:
        c.login_user_field = (body.login_user_field or "username")[:80]
    if body.login_pass_field is not None:
        c.login_pass_field = (body.login_pass_field or "password")[:80]
    if body.login_token_path is not None:
        c.login_token_path = (body.login_token_path or "token")[:120]
    db.commit()
    return _campaign_json(c)


class _LoginCfg:
    """Lightweight campaign-like holder so login.derive_session can read the
    login_* attributes without a persisted Campaign."""
    def __init__(self, body: "LoginTestIn"):
        self.login_mode = body.login_mode
        self.login_url = body.login_url
        self.login_user = body.login_user
        self.login_password = body.login_password
        self.login_user_field = body.login_user_field
        self.login_pass_field = body.login_pass_field
        self.login_token_path = body.login_token_path


@app.post("/api/campaigns/test-login")
def test_login(body: LoginTestIn, _: str = auth.auth_dep, db: Session = Depends(get_session)):
    """Try the configured credentials now and report whether a session was
    captured — without persisting anything or echoing secrets back."""
    from . import login
    allow_internal = body.allow_internal
    if body.target_id:
        t = db.get(Target, body.target_id)
        if t:
            allow_internal = allow_internal or bool(t.allow_internal)
    sess = login.derive_session(_LoginCfg(body), allow_internal)
    cookies = sess.get("cookies", "") or ""
    n = len([x for x in cookies.split(";") if "=" in x]) if cookies else 0
    return {"ok": bool(sess.get("ok")), "diag": sess.get("diag", ""),
            "cookies": n, "bearer": bool(sess.get("authz"))}


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
    out_findings = []
    for f in findings:
        d = {"id": f.id, "title": f.title, "severity": f.severity,
             "cvss": f.cvss or 0.0, "cvss_vector": f.cvss_vector or "", "cwe": f.cwe or "",
             "owasp": f.owasp, "atlas": f.atlas,
             "description": f.description, "evidence": f.evidence, "remediation": f.remediation}
        scoring.enrich_finding(d)   # score pre-scoring rows at read time
        out_findings.append(d)
    # Highest risk first — CVSS, then severity rank as a tiebreak.
    out_findings.sort(key=lambda x: (x["cvss"], taxonomy.SEVERITY_SCORE.get(x["severity"], 0)),
                      reverse=True)
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
