"""Structured engagement report for a target: one source of truth that renders
to JSON, Markdown and SARIF 2.1.0.

Findings are de-duplicated across every run of the target (the same issue found
in several engagements is one vulnerability), ranked by CVSS then severity, and
each carries a technical appendix — the affected location and a reproduction
trail (the command/request that found it plus a response snippet) pulled from
the attempt's steps, so the report stands on its own as evidence.
"""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import func, select

from . import scoring, taxonomy
from .models import Attempt, Campaign, Finding, Run, Step, Target


def _pad(i: int) -> str:
    return f"F-{i:02d}"


def build_report(db, target: Target) -> dict:
    """Assemble the full report structure for a target across all its runs."""
    camp_ids = list(db.scalars(select(Campaign.id).where(Campaign.target_id == target.id)))
    run_ids = (list(db.scalars(select(Run.id).where(Run.campaign_id.in_(camp_ids))))
               if camp_ids else [])
    sev: dict[str, int] = {}
    distinct: dict[tuple, Finding] = {}
    if run_ids:
        for f in db.scalars(select(Finding).where(Finding.run_id.in_(run_ids))):
            dk = (f.title.strip().lower(), f.owasp or "", (f.evidence or "")[:200].strip().lower())
            # keep the highest-scored instance of a repeated finding
            prev = distinct.get(dk)
            if prev is None or (f.cvss or 0) > (prev.cvss or 0):
                distinct[dk] = f

    findings = []
    for f in distinct.values():
        sev[f.severity] = sev.get(f.severity, 0) + 1
        appendix = _appendix(db, f)
        fd = {
            "title": f.title, "severity": f.severity,
            "cvss": f.cvss or 0.0, "cvss_vector": f.cvss_vector or "",
            "cwe": f.cwe or "", "owasp": f.owasp or "", "atlas": f.atlas or "",
            "description": f.description or "", "evidence": f.evidence or "",
            "remediation": f.remediation or "",
            "affected": appendix["affected"], "reproduction": appendix["reproduction"],
            "run_id": f.run_id,
        }
        scoring.enrich_finding(fd)   # score pre-scoring rows at read time
        findings.append(fd)
    findings.sort(key=lambda x: (x["cvss"], taxonomy.SEVERITY_SCORE.get(x["severity"], 0)),
                  reverse=True)
    for i, fd in enumerate(findings, 1):
        fd["id"] = _pad(i)

    exec_summary = ""
    first = last = None
    if run_ids:
        exec_summary = db.scalar(
            select(Step.response).join(Attempt, Step.attempt_id == Attempt.id)
            .where(Attempt.run_id.in_(run_ids), Step.role == "report", Step.response != "")
            .order_by(Step.id.desc()).limit(1)) or ""
        first = db.scalar(select(func.min(Run.started_at)).where(Run.id.in_(run_ids)))
        last = db.scalar(select(func.max(Run.finished_at)).where(Run.id.in_(run_ids)))

    total = sum(sev.values())
    worst = taxonomy.worst([s for s, n in sev.items() if n]) if total else "info"
    return {
        "target": {"id": target.id, "name": target.name, "endpoint": target.endpoint,
                   "kind": target.kind},
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "runs": len(run_ids),
        "first_seen": first.isoformat() + "Z" if first else None,
        "last_seen": last.isoformat() + "Z" if last else None,
        "summary": {"total": total, "by_severity": sev, "worst": worst,
                    "exec_summary": exec_summary},
        "findings": findings,
    }


def _appendix(db, f: Finding) -> dict:
    """Affected location + reproduction trail for one finding, from its attempt."""
    affected, repro = [], []
    if f.evidence:
        affected.append(f.evidence.strip()[:300])
    if f.attempt_id:
        steps = db.scalars(select(Step).where(Step.attempt_id == f.attempt_id)
                           .order_by(Step.idx)).all()
        for s in steps[:4]:
            cmd = (s.prompt or "").strip()
            snip = (s.response or "").strip()
            if not cmd and not snip:
                continue
            repro.append({"step": s.role or "step", "command": cmd[:400],
                          "response": snip[:600]})
    return {"affected": affected, "reproduction": repro}


# --------------------------------------------------------------- Markdown
def to_markdown(rep: dict, lang: str = "en") -> str:
    zh = lang == "zh"
    t = rep["target"]
    s = rep["summary"]
    L = (lambda en, cn: cn if zh else en)
    out = []
    out.append(f"# {L('Penetration Test Report', '渗透测试报告')} — {t['name']}")
    out.append("")
    out.append(f"- {L('Target', '目标')}: `{t.get('endpoint') or t['name']}`")
    out.append(f"- {L('Generated', '生成时间')}: {rep['generated_at']}")
    out.append(f"- {L('Engagements', '扫描轮次')}: {rep['runs']}  ·  "
               f"{L('Findings', '发现项')}: {s['total']}  ·  "
               f"{L('Worst severity', '最高风险')}: **{s['worst']}**")
    out.append("")
    # Severity breakdown
    out.append(f"## {L('Risk summary', '风险概览')}")
    bysev = s["by_severity"]
    for lvl in taxonomy.SEVERITY_ORDER:
        if bysev.get(lvl):
            out.append(f"- **{lvl}**: {bysev[lvl]}")
    out.append("")
    if s["exec_summary"]:
        out.append(f"## {L('Executive summary', '执行摘要')}")
        out.append(s["exec_summary"])
        out.append("")
    # Findings
    out.append(f"## {L('Findings', '发现项')}")
    out.append("")
    if not rep["findings"]:
        out.append(L("No vulnerabilities were confirmed.", "未确认到漏洞。"))
    for fd in rep["findings"]:
        cvss = f"CVSS {fd['cvss']}" if fd["cvss"] else ""
        cwe = fd["cwe"]
        tags = "  ".join(x for x in [f"`{fd['severity']}`", cvss, cwe,
                                     taxonomy.owasp_label(fd["owasp"]) if fd["owasp"] else ""] if x)
        out.append(f"### {fd['id']} · {fd['title']}")
        out.append(tags)
        if fd["cvss_vector"]:
            out.append(f"`{fd['cvss_vector']}`")
        out.append("")
        if fd["description"]:
            out.append(fd["description"])
            out.append("")
        if fd["affected"]:
            out.append(f"**{L('Affected', '受影响位置')}:**")
            for a in fd["affected"]:
                out.append(f"- `{a}`")
            out.append("")
        if fd["reproduction"]:
            out.append(f"**{L('Reproduction', '复现步骤')}:**")
            for r in fd["reproduction"]:
                out.append(f"- _{r['step']}_: `{r['command'] or '(see response)'}`")
                if r["response"]:
                    snippet = r["response"].replace("```", "`` `")
                    out.append("  ```\n  " + snippet.replace("\n", "\n  ")[:600] + "\n  ```")
            out.append("")
        if fd["remediation"]:
            out.append(f"**{L('Remediation', '修复建议')}:** {fd['remediation']}")
            out.append("")
    return "\n".join(out)


# --------------------------------------------------------------- SARIF 2.1.0
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def to_sarif(rep: dict) -> dict:
    """SARIF 2.1.0 — ingestible by GitHub code scanning, DefectDojo, etc."""
    rules, results = [], []
    seen_rules = set()
    for fd in rep["findings"]:
        rule_id = fd["cwe"] or fd["owasp"] or fd["id"]
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": fd["title"][:120],
                "shortDescription": {"text": fd["title"][:200]},
                "properties": {k: v for k, v in (("cwe", fd["cwe"]),
                               ("owasp", fd["owasp"]), ("security-severity",
                               str(fd["cvss"]) if fd["cvss"] else "")) if v},
            })
        loc = (fd["affected"][0] if fd["affected"] else rep["target"].get("endpoint") or "")
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(fd["severity"], "note"),
            "message": {"text": f"[{fd['id']}] {fd['title']}"
                        + (f" — {fd['description'][:300]}" if fd["description"] else "")},
            "properties": {"severity": fd["severity"], "cvss": fd["cvss"],
                           "cvss_vector": fd["cvss_vector"], "cwe": fd["cwe"]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": str(loc)[:300] or "unknown"}}}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Dagger-AI", "informationUri":
                     "https://github.com/yutang718/dagger-ai", "rules": rules}},
            "results": results,
        }],
    }


def sarif_bytes(rep: dict) -> str:
    return json.dumps(to_sarif(rep), ensure_ascii=False, indent=2)
