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

import ipaddress
from urllib.parse import urlparse

import httpx

from . import config, tools_client
from .llm_client import LLMClient
from .probes import all_probes
from .records import AttemptRec, StepRec

# module id -> (phase, runner tool). "web_probes" runs in-process.
MODULES = {
    "recon_nmap":          ("recon",       "nmap"),
    "recon_subfinder":     ("recon",       "subfinder"),
    "probe_httpx":         ("fingerprint", "httpx"),
    "fingerprint_whatweb": ("fingerprint", "whatweb"),
    "waf_wafw00f":         ("fingerprint", "wafw00f"),
    "tls_sslscan":         ("fingerprint", "sslscan"),
    "discovery_ffuf":      ("discovery",   "ffuf"),
    "crawl_katana":        ("discovery",   "katana"),
    "vuln_nuclei":         ("vuln",        "nuclei"),
    "vuln_nikto":          ("vuln",        "nikto"),
    "sqli_sqlmap":         ("exploit",     "sqlmap"),
    "xss_dalfox":          ("exploit",     "dalfox"),
    "cmdi_commix":         ("exploit",     "commix"),
    "web_probes":          ("exploit",     "__builtin__"),
}
PHASE_ORDER = ["recon", "fingerprint", "discovery", "vuln", "exploit"]

MODULE_META = {
    "recon_nmap": ("Nmap port & service recon", "nmap"),
    "recon_subfinder": ("Subfinder subdomain enumeration", "subfinder"),
    "probe_httpx": ("httpx web probe / tech detect", "httpx"),
    "fingerprint_whatweb": ("WhatWeb fingerprinting", "whatweb"),
    "waf_wafw00f": ("WAFW00F WAF detection", "wafw00f"),
    "tls_sslscan": ("sslscan TLS/SSL analysis", "sslscan"),
    "discovery_ffuf": ("ffuf content discovery", "ffuf"),
    "crawl_katana": ("Katana crawl / URL discovery", "katana"),
    "vuln_nuclei": ("Nuclei vulnerability scan", "nuclei"),
    "vuln_nikto": ("Nikto web-server scan", "nikto"),
    "sqli_sqlmap": ("sqlmap SQLi validation", "sqlmap"),
    "xss_dalfox": ("dalfox XSS validation", "dalfox"),
    "cmdi_commix": ("commix command-injection validation", "commix"),
    "web_probes": ("Built-in web probes (OWASP)", "builtin"),
}


# Tools that work against a bare IP or a whole network/CIDR (host vuln scanning),
# vs. the web-path tools that need a single HTTP URL.
NETWORK_TOOLS = {"nmap", "httpx", "nuclei"}


def _is_cidr(s: str) -> bool:
    """True for a multi-host network range like 10.0.0.0/24 or 2001:db8::/120."""
    try:
        return ipaddress.ip_network(s.strip(), strict=False).num_addresses > 1
    except ValueError:
        return False


def _url_and_host(endpoint: str) -> tuple[str, str]:
    e = (endpoint or "").strip()
    if "://" in e:
        return e, (urlparse(e).hostname or e)
    if _is_cidr(e):                       # IP range / CIDR → pass through to nmap/nuclei/httpx
        return e, e
    # bare host or single IP
    return "http://" + e, e.split("/")[0].split(":")[0]


def _select_for_target(chosen, host):
    """For a CIDR/range target, keep only network-capable modules (nmap/httpx/
    nuclei) so web-path tools aren't pointed at a whole subnet."""
    if not _is_cidr(host):
        return chosen
    net = [m for m in chosen if MODULES[m][1] in NETWORK_TOOLS]
    return net or [m for m in MODULES if MODULES[m][1] in NETWORK_TOOLS]


def run_engagement(endpoint, selected, allow_internal, max_steps, client: LLMClient | None = None,
                   on_attempt=None, cancelled=None, lang="en"):
    """Dispatch: an LLM-driven closed loop when an attacker LLM is online
    (plan → choose next action from results → execute → validate → re-plan →
    summarise), else the deterministic default playbook.

    `on_attempt(a)` is called for each attempt as it is produced, so the engine
    can persist it immediately and the Live Monitor streams progress. `cancelled()`
    is polled between steps so a Stop takes effect mid-engagement. `lang` is the
    operator's UI language, so the plan/conclusions/validation/summary come back
    in Chinese or English to match the console."""
    client = client or LLMClient.attacker()
    url, host = _url_and_host(endpoint)
    if client.online:
        return _agentic_engagement(client, url, host, selected, allow_internal, max_steps,
                                   on_attempt, cancelled, lang)
    return _playbook_engagement(client, url, host, selected, allow_internal, max_steps,
                                on_attempt, cancelled, lang)


def _emit(attempts, a, on_attempt):
    attempts.append(a)
    if on_attempt:
        try:
            on_attempt(a)
        except Exception:
            pass
    return a


def _playbook_engagement(client, url, host, selected, allow_internal, max_steps,
                         on_attempt=None, cancelled=None, lang="en"):
    attempts: list[AttemptRec] = []

    # ---- AI plan (or deterministic note) ----
    chosen = [m for m in MODULES if m in selected] or list(MODULES)
    chosen = _select_for_target(chosen, host)
    plan_txt = _plan(client, url, host, chosen, lang)
    _emit(attempts, AttemptRec("engagement-plan", f"Plan an authorized assessment of {host}",
                               [StepRec("plan", f"target={url}  scope-host={host}", plan_txt,
                                        "AI operator plan" if client.online else "default playbook")],
                               False, 0.0, phase="plan"), on_attempt)

    # ---- ordered tool runs ----
    ordered = sorted(chosen, key=lambda m: PHASE_ORDER.index(MODULES[m][0]))
    budget = max_steps
    for mod in ordered:
        if budget <= 0 or (cancelled and cancelled()):
            break
        phase, tool = MODULES[mod]
        budget -= 1
        if tool == "__builtin__":
            for a in _web_probe_attempts(url, lang):
                _emit(attempts, a, on_attempt)
            continue
        tgt = host if tool == "nmap" else url
        res = tools_client.run(tool, tgt, allow_internal=allow_internal)
        _emit(attempts, _attempt_from_tool(mod, phase, res, lang), on_attempt)

    # ---- AI executive summary ----
    summary = _summary(client, host, attempts, lang)
    _emit(attempts, AttemptRec("engagement-summary", f"Summarise findings for {host}",
                               [StepRec("report", "executive summary", summary,
                                        "AI operator summary" if client.online else "auto summary")],
                               False, 0.0, phase="report"), on_attempt)
    return attempts


def _attempt_from_tool(mod, phase, res, lang="en") -> AttemptRec:
    name, _ = MODULE_META.get(mod, (mod, mod))
    zh = lang == "zh"
    if not res.get("available", True):
        return AttemptRec(name, f"Run {mod}",
                          [StepRec("tool", res.get("command", mod),
                                   f"[tool not installed in tool-runner] {res.get('error','')}",
                                   f"{phase}: {name}")],
                          False, 0.0,
                          rationale=("该工具在工具运行器中不可用。" if zh else "Tool unavailable."), phase=phase)
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
    if zh:
        rationale = (f"{name}：发现 {len(findings)} 项问题。" if findings
                     else f"{name}：未发现问题；{len(obs)} 条观测。")
    else:
        rationale = (f"{len(findings)} finding(s) from {name}." if findings
                     else f"No findings from {name}; {len(obs)} observation(s).")
    return AttemptRec(name, f"Run {mod}",
                      [StepRec("tool", res.get("command", mod), body[:6000],
                               f"{phase}: {name}", res.get("duration_ms", 0))],
                      success, 1.0 if success else 0.0, evidence, rationale,
                      findings=findings, phase=phase)


def _web_probe_attempts(url, lang="en") -> list[AttemptRec]:
    """Run the in-process web probes (OWASP) against the URL as part of exploit phase."""
    from . import translations
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
            pname = translations.PROBE_ZH.get(p.id, (p.name, ""))[0] if lang == "zh" else p.name
            for a in recs:
                a.phase = "exploit"
                if a.success:
                    a.findings = [{
                        "title": f"{p.name}", "severity": p.severity, "owasp": p.owasp,
                        "mitre": p.mitre, "evidence": a.evidence,
                        "description": p.description, "remediation": p.remediation,
                    }]
                if lang == "zh":   # localize the conclusion shown in the UI
                    a.rationale = (f"确认漏洞：{pname}（详见证据）。" if a.success
                                   else f"未发现 {pname} 问题。")
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


def _plan(client, url, host, chosen, lang="en"):
    if client.online:
        mods = ", ".join(chosen)
        out = client.complete(_PLAN_SYS + _lang_suffix(lang),
                              f"Target: {url} (host {host})\nModules available: {mods}")
        if out.strip():
            return out.strip()
    phases = " → ".join(dict.fromkeys(MODULES[m][0] for m in chosen))
    if lang == "zh":
        return ("默认剧本（离线引擎）。阶段：" + phases +
                "。侦察阶段摸清对外暴露的服务；指纹识别确定技术栈；内容发现找出隐藏路径；"
                "漏洞扫描匹配已知问题；利用阶段验证高影响发现（SQL 注入、OWASP Web）。"
                "所有运行都受步数预算与授权门限的约束。")
    return ("Default playbook (offline engine). Phases: " + phases +
            ". Recon maps exposed services; fingerprint identifies the stack; discovery finds hidden "
            "paths; the vulnerability scan matches known issues; exploit validates high-impact findings "
            "(SQLi, OWASP web). All runs are bounded by the step budget and the authorization gate.")


def _summary(client, host, attempts, lang="en"):
    allf = [f for a in attempts for f in a.findings]
    if client.online and allf:
        brief = "\n".join(f"- [{f.get('severity')}] {f.get('title')} ({f.get('owasp','')})" for f in allf[:40])
        out = client.complete(_SUM_SYS + _lang_suffix(lang), f"Host: {host}\nFindings:\n{brief}")
        if out.strip():
            return out.strip()
    if not allf:
        return (f"在所选模块下，未对 {host} 确认到漏洞。" if lang == "zh"
                else f"No vulnerabilities were confirmed against {host} with the selected modules.")
    bysev = {}
    for f in allf:
        bysev[f.get("severity", "info")] = bysev.get(f.get("severity", "info"), 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    line = ", ".join(f"{bysev[s]} {s}" for s in order if bysev.get(s))
    top = "; ".join(f.get("title", "") for f in allf if f.get("severity") in ("critical", "high"))[:400]
    if lang == "zh":
        return f"对 {host} 的任务确认了 {len(allf)} 项发现：{line}。优先处理：{top or '—'}。"
    return f"Engagement against {host} confirmed {len(allf)} finding(s): {line}. Priority issues: {top or '—'}."


# ============================================================ agentic loop
_NEXT_SYS = (
    "You are an autonomous penetration-test operator running an AUTHORIZED engagement. "
    "Given the target, the modules still available, and the results so far, choose the single "
    "most valuable NEXT module to run — or stop when further scanning adds little value. "
    "Respect the phase order (recon → fingerprint → discovery → vuln → exploit). "
    'Reply ONLY with JSON: {"module": "<module_id>|stop", "reason": "<one short sentence>"}.')
_VAL_SYS = (
    "You are a senior penetration tester VALIDATING the findings of an AUTHORIZED engagement. "
    "For the findings given, state which are likely true positives vs. need manual verification, "
    "note any likely false positives, and give the top remediation priorities. <=120 words, no preamble.")


def _next_action(client, url, host, remaining, ran) -> dict:
    state = "\n".join(f"- {m}: {n} finding(s)" for m, n in ran) or "(nothing run yet)"
    rem = ", ".join(sorted(remaining))
    data = client.complete_json(
        _NEXT_SYS,
        f"Target: {url} (host {host})\nModules available: {rem}\n"
        f"Phase order: {' -> '.join(PHASE_ORDER)}\nResults so far:\n{state}\n"
        "Choose the next module id to run now, or \"stop\".")
    return data or {}


def _validate(client, host, attempts, lang="en") -> str:
    allf = [f for a in attempts for f in a.findings]
    if not allf:
        return ""
    brief = "\n".join(
        f"- [{f.get('severity')}] {f.get('title')} ({f.get('owasp','')}) "
        f"evidence: {str(f.get('evidence',''))[:80]}" for f in allf[:40])
    return client.complete(_VAL_SYS + _lang_suffix(lang), f"Host: {host}\nFindings:\n{brief}").strip()


_INTERP_SYS = (
    "You are a penetration tester explaining ONE tool's result to a teammate in plain language. "
    "In 1-2 short sentences, say what this step found and what it means for the target's security "
    "(or that it found nothing notable). No preamble, no raw output, no markdown, no bullet points.")


def _lang_suffix(lang: str) -> str:
    """Make the LLM answer in the operator's UI language."""
    if lang == "zh":
        return ("\n\nIMPORTANT: Write your ENTIRE response in Simplified Chinese (简体中文) — "
                "every sentence, including technical explanations. Do not answer in English.")
    return ""


def _interpret(client, mod, res, lang="en") -> str:
    """Ask the LLM for a short, human-readable conclusion of one tool's output,
    so the operator doesn't just dump raw nmap/nuclei/ffuf text at the user."""
    if not (client and client.online):
        return ""
    name = MODULE_META.get(mod, (mod, mod))[0]
    findings = res.get("findings", []) or []
    obs = res.get("observations", []) or []
    fbrief = "; ".join(f"{f.get('severity')}: {f.get('title')}" for f in findings[:12]) \
        or "no confirmed findings"
    obrief = "\n".join(obs[:20])[:1500]
    out = client.complete(
        _INTERP_SYS + _lang_suffix(lang),
        f"Tool: {name}\nConfirmed findings: {fbrief}\nObservations:\n{obrief}\n\n"
        "Explain in plain language what this step found and what it means.")
    return out.strip()


def _run_module(mod, url, host, allow_internal, reason, client=None, lang="en"):
    """Run one module, attaching the LLM's reasoning for choosing it (as a step
    note) and a plain-language conclusion of the output (as the rationale)."""
    phase, tool = MODULES[mod]
    out = []
    if tool == "__builtin__":
        out = _web_probe_attempts(url, lang)
        hits = sum(1 for a in out if a.success)
    else:
        tgt = host if tool == "nmap" else url
        res = tools_client.run(tool, tgt, allow_internal=allow_internal)
        a = _attempt_from_tool(mod, phase, res, lang)
        if a.steps and reason:
            a.steps[0].note = f"AI chose this — {reason} · " + a.steps[0].note
        concl = _interpret(client, mod, res, lang)
        if concl:
            a.rationale = concl
        elif reason:
            a.rationale = f"Rationale: {reason} | " + (a.rationale or "")
        out = [a]
        hits = len(res.get("findings", []) or [])
    return out, hits


def _agentic_engagement(client, url, host, selected, allow_internal, max_steps,
                        on_attempt=None, cancelled=None, lang="en"):
    attempts: list[AttemptRec] = []
    chosen = [m for m in MODULES if m in selected] or list(MODULES)
    chosen = _select_for_target(chosen, host)

    # 1) PLAN — the LLM writes the strategy.
    plan_txt = _plan(client, url, host, chosen, lang)
    _emit(attempts, AttemptRec("engagement-plan", f"Plan an authorized assessment of {host}",
                               [StepRec("plan", f"target={url}  scope-host={host}", plan_txt,
                                        "AI operator plan")], False, 0.0, phase="plan"), on_attempt)

    # 2) CLOSED LOOP — the LLM picks the next action from results, until done/budget.
    remaining = set(chosen)
    ran: list[tuple[str, int]] = []
    budget = max_steps
    while remaining and budget > 0:
        if cancelled and cancelled():
            break
        decision = _next_action(client, url, host, remaining, ran)
        mod = (decision.get("module") or "").strip()
        reason = (decision.get("reason") or "").strip()
        if mod == "stop":
            break
        if mod not in remaining:   # invalid/empty choice → fall back to phase order
            mod = sorted(remaining, key=lambda m: PHASE_ORDER.index(MODULES[m][0]))[0]
            reason = reason or "next phase in order"
        remaining.discard(mod)
        budget -= 1
        recs, hits = _run_module(mod, url, host, allow_internal, reason, client, lang)
        for a in recs:
            _emit(attempts, a, on_attempt)
        ran.append((mod, hits))

    # 3) VALIDATE — the LLM reviews the findings (true positives / FPs / priorities).
    val = _validate(client, host, attempts, lang)
    if val:
        _emit(attempts, AttemptRec("validation", f"Validate findings for {host}",
                                   [StepRec("report", "LLM validation of findings", val,
                                            "AI operator validation")], False, 0.0, phase="validate"), on_attempt)

    # 4) SUMMARY — executive summary.
    summary = _summary(client, host, attempts, lang)
    _emit(attempts, AttemptRec("engagement-summary", f"Summarise findings for {host}",
                               [StepRec("report", "executive summary", summary,
                                        "AI operator summary")], False, 0.0, phase="report"), on_attempt)
    return attempts
