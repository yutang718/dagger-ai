"""AI pentest operator.

Given an authorized host/URL target, the operator runs a staged engagement —
recon → fingerprint → discovery → vulnerability scan → exploit validation —
by driving best-of-breed tools through the tool-runner sidecar, plus the
built-in web probes. When an attacker LLM is configured it writes the plan and
the executive summary and can prioritise follow-ups; offline, it follows a
sound default playbook. Each tool run becomes one Attempt (with its command +
output as steps and parsed vulnerabilities as findings).
"""
from __future__ import annotations

from urllib.parse import urlparse

import httpx

from . import config, tools_client
from .llm_client import LLMClient
from .probes import all_probes
from .records import AttemptRec, StepRec

# module id -> (phase, runner tool). "web_probes" runs in-process.
MODULES = {
    "recon_nmap":        ("recon",       "nmap"),
    "probe_httpx":       ("fingerprint", "httpx"),
    "fingerprint_whatweb": ("fingerprint", "whatweb"),
    "discovery_ffuf":    ("discovery",   "ffuf"),
    "vuln_nuclei":       ("vuln",        "nuclei"),
    "sqli_sqlmap":       ("exploit",     "sqlmap"),
    "web_probes":        ("exploit",     "__builtin__"),
}
PHASE_ORDER = ["recon", "fingerprint", "discovery", "vuln", "exploit"]

MODULE_META = {
    "recon_nmap": ("Nmap port & service recon", "nmap"),
    "probe_httpx": ("httpx web probe / tech detect", "httpx"),
    "fingerprint_whatweb": ("WhatWeb fingerprinting", "whatweb"),
    "discovery_ffuf": ("ffuf content discovery", "ffuf"),
    "vuln_nuclei": ("Nuclei vulnerability scan", "nuclei"),
    "sqli_sqlmap": ("sqlmap SQLi validation", "sqlmap"),
    "web_probes": ("Built-in web probes (OWASP)", "builtin"),
}


def _url_and_host(endpoint: str) -> tuple[str, str]:
    if "://" in endpoint:
        return endpoint, (urlparse(endpoint).hostname or endpoint)
    return "http://" + endpoint, endpoint.split("/")[0].split(":")[0]


def run_engagement(endpoint, selected, allow_internal, max_steps, client: LLMClient | None = None):
    client = client or LLMClient.attacker()
    url, host = _url_and_host(endpoint)
    attempts: list[AttemptRec] = []

    # ---- AI plan (or deterministic note) ----
    chosen = [m for m in MODULES if m in selected] or list(MODULES)
    plan_txt = _plan(client, url, host, chosen)
    attempts.append(AttemptRec("engagement-plan", f"Plan an authorized assessment of {host}",
                               [StepRec("plan", f"target={url}  scope-host={host}", plan_txt,
                                        "AI operator plan" if client.online else "default playbook")],
                               False, 0.0, phase="plan"))

    # ---- ordered tool runs ----
    ordered = sorted(chosen, key=lambda m: PHASE_ORDER.index(MODULES[m][0]))
    budget = max_steps
    for mod in ordered:
        if budget <= 0:
            break
        phase, tool = MODULES[mod]
        budget -= 1
        if tool == "__builtin__":
            attempts.extend(_web_probe_attempts(url))
            continue
        tgt = host if tool == "nmap" else url
        res = tools_client.run(tool, tgt, allow_internal=allow_internal)
        attempts.append(_attempt_from_tool(mod, phase, res))

    # ---- AI executive summary ----
    summary = _summary(client, host, attempts)
    attempts.append(AttemptRec("engagement-summary", f"Summarise findings for {host}",
                               [StepRec("report", "executive summary", summary,
                                        "AI operator summary" if client.online else "auto summary")],
                               False, 0.0, phase="report"))
    return attempts


def _attempt_from_tool(mod, phase, res) -> AttemptRec:
    name, _ = MODULE_META.get(mod, (mod, mod))
    if not res.get("available", True):
        return AttemptRec(name, f"Run {mod}",
                          [StepRec("tool", res.get("command", mod),
                                   f"[tool not installed in tool-runner] {res.get('error','')}",
                                   f"{phase}: {name}")],
                          False, 0.0, rationale="Tool unavailable.", phase=phase)
    findings = res.get("findings", []) or []
    obs = res.get("observations", []) or []
    out = (res.get("stdout", "") or "")
    body = out
    if obs:
        body = "OBSERVATIONS:\n" + "\n".join(obs[:40]) + ("\n\n---\n" + out if out else "")
    if res.get("error"):
        body += f"\n[error] {res['error']}"
    success = bool(findings)
    evidence = findings[0].get("evidence", "") if findings else ""
    rationale = (f"{len(findings)} finding(s) from {mod}." if findings
                 else f"No findings from {mod}; {len(obs)} observation(s).")
    return AttemptRec(name, f"Run {mod}",
                      [StepRec("tool", res.get("command", mod), body[:6000],
                               f"{phase}: {name}", res.get("duration_ms", 0))],
                      success, 1.0 if success else 0.0, evidence, rationale,
                      findings=findings, phase=phase)


def _web_probe_attempts(url) -> list[AttemptRec]:
    """Run the in-process web probes (OWASP) against the URL as part of exploit phase."""
    out = []
    web = [p for p in all_probes() if getattr(p, "category", "") == "web"]
    try:
        http = httpx.Client(timeout=config.REQUEST_TIMEOUT, follow_redirects=True,
                            headers={"User-Agent": "Dagger-AI/operator"})
    except Exception:
        return out
    try:
        for p in web:
            try:
                recs = p.execute(url, http)
            except Exception as e:  # noqa: BLE001
                continue
            for a in recs:
                a.phase = "exploit"
                if a.success:
                    a.findings = [{
                        "title": f"{p.name}", "severity": p.severity, "owasp": p.owasp,
                        "mitre": p.mitre, "evidence": a.evidence,
                        "description": p.description, "remediation": p.remediation,
                    }]
                out.append(a)
    finally:
        http.close()
    return out


# -------------------------------------------------------------- LLM glue
_PLAN_SYS = ("You are a senior penetration tester planning an AUTHORIZED engagement. "
             "Given the target and the available modules, write a brief, ordered plan (<=120 words) "
             "describing what each phase checks and why. No preamble.")
_SUM_SYS = ("You are a senior penetration tester writing the executive summary of an AUTHORIZED "
            "engagement. Given the findings list, summarise risk, the most critical issues, and "
            "top remediation priorities in <=150 words.")


def _plan(client, url, host, chosen):
    if client.online:
        mods = ", ".join(chosen)
        out = client.complete(_PLAN_SYS, f"Target: {url} (host {host})\nModules available: {mods}")
        if out.strip():
            return out.strip()
    phases = " → ".join(dict.fromkeys(MODULES[m][0] for m in chosen))
    return ("Default playbook (offline engine). Phases: " + phases +
            ". Recon maps exposed services; fingerprint identifies the stack; discovery finds hidden "
            "paths; the vulnerability scan matches known issues; exploit validates high-impact findings "
            "(SQLi, OWASP web). All runs are bounded by the step budget and the authorization gate.")


def _summary(client, host, attempts):
    allf = [f for a in attempts for f in a.findings]
    if client.online and allf:
        brief = "\n".join(f"- [{f.get('severity')}] {f.get('title')} ({f.get('owasp','')})" for f in allf[:40])
        out = client.complete(_SUM_SYS, f"Host: {host}\nFindings:\n{brief}")
        if out.strip():
            return out.strip()
    if not allf:
        return f"No vulnerabilities were confirmed against {host} with the selected modules."
    bysev = {}
    for f in allf:
        bysev[f.get("severity", "info")] = bysev.get(f.get("severity", "info"), 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    line = ", ".join(f"{bysev[s]} {s}" for s in order if bysev.get(s))
    top = "; ".join(f.get("title", "") for f in allf if f.get("severity") in ("critical", "high"))[:400]
    return f"Engagement against {host} confirmed {len(allf)} finding(s): {line}. Priority issues: {top or '—'}."
