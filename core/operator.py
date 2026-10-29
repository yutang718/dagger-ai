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
import re
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
    "urls_gau":            ("discovery",   "gau"),
    "params_arjun":        ("discovery",   "arjun"),
    "vuln_nuclei":         ("vuln",        "nuclei"),
    "vuln_nikto":          ("vuln",        "nikto"),
    "tls_testssl":         ("vuln",        "testssl"),
    "cms_wpscan":          ("vuln",        "wpscan"),
    "sqli_sqlmap":         ("exploit",     "sqlmap"),
    "xss_dalfox":          ("exploit",     "dalfox"),
    "cmdi_commix":         ("exploit",     "commix"),
    "secrets_gitsecrets":  ("exploit",     "gitsecrets"),
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
    "urls_gau": ("gau historical URL discovery", "gau"),
    "params_arjun": ("arjun hidden-parameter discovery", "arjun"),
    "vuln_nuclei": ("Nuclei vulnerability scan", "nuclei"),
    "vuln_nikto": ("Nikto web-server scan", "nikto"),
    "tls_testssl": ("testssl.sh TLS vulnerability scan", "testssl.sh"),
    "cms_wpscan": ("wpscan WordPress scan", "wpscan"),
    "sqli_sqlmap": ("sqlmap SQLi validation", "sqlmap"),
    "xss_dalfox": ("dalfox XSS validation", "dalfox"),
    "cmdi_commix": ("commix command-injection validation", "commix"),
    "secrets_gitsecrets": ("Exposed .git → secret scan", "git-dumper+trufflehog"),
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
                   on_attempt=None, cancelled=None, lang="en", cookies=""):
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
    ck = tools_client.cookie_header(cookies)
    if client.online:
        return _agentic_engagement(client, url, host, selected, allow_internal, max_steps,
                                   on_attempt, cancelled, lang, ck)
    return _playbook_engagement(client, url, host, selected, allow_internal, max_steps,
                                on_attempt, cancelled, lang, ck)


def _emit(attempts, a, on_attempt):
    attempts.append(a)
    if on_attempt:
        try:
            on_attempt(a)
        except Exception:
            pass
    return a


def _playbook_engagement(client, url, host, selected, allow_internal, max_steps,
                         on_attempt=None, cancelled=None, lang="en", cookies=""):
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
            for a in _web_probe_attempts(url, lang, cookies):
                _emit(attempts, a, on_attempt)
            continue
        tgt = host if tool == "nmap" else url
        res = tools_client.run(tool, tgt, allow_internal=allow_internal, cookies=cookies)
        _emit(attempts, _attempt_from_tool(mod, phase, res, lang), on_attempt)

    # ---- auto-verify EVERY discovered vuln (not just PHP) ----
    for a in _exploit_verification(url, attempts, lang, cookies):
        _emit(attempts, a, on_attempt)

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


def _web_probe_attempts(url, lang="en", cookies="") -> list[AttemptRec]:
    """Run the in-process web probes (OWASP) against the URL as part of exploit phase."""
    from . import translations
    out = []
    web = [p for p in all_probes() if getattr(p, "category", "") == "web"]
    hdrs = {"User-Agent": "Dagger-AI/operator"}
    if cookies:
        hdrs["Cookie"] = cookies
    try:
        http = httpx.Client(timeout=config.REQUEST_TIMEOUT, follow_redirects=True,
                            headers=hdrs)
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
                    if a.success:
                        verb = "检测到" if p.severity == "info" else "确认漏洞"
                        a.rationale = f"{verb}：{pname}（详见证据）。"
                    else:
                        a.rationale = f"未发现 {pname} 问题。"
                out.append(a)
    finally:
        http.close()
    return out


_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)


def _discovered_cves(attempts) -> dict:
    """Every CVE id surfaced so far (from nuclei, banners, any probe finding),
    mapped to the finding that mentioned it."""
    found: dict[str, dict] = {}
    for a in attempts:
        for f in (getattr(a, "findings", None) or []):
            blob = " ".join(str(f.get(k, "")) for k in ("title", "evidence", "description"))
            for cid in _CVE_RE.findall(blob):
                found.setdefault(cid.upper(), f)
    return found


def _cve_confirmed(attempts, cve) -> bool:
    """True only if an active probe (hands-on HTTP PoC) already confirmed this
    CVE — a scanner/tool signature match (role="tool") does not count, since
    that is exactly what we want to verify."""
    for a in attempts:
        if not getattr(a, "success", False):
            continue
        roles = {getattr(s, "role", "") for s in (getattr(a, "steps", None) or [])}
        if "request" not in roles or "tool" in roles:
            continue  # not a hands-on probe attempt
        for f in (getattr(a, "findings", None) or []):
            if cve in (str(f.get("title", "")) + str(f.get("evidence", ""))).upper():
                return True
    return False


def _exploit_verification(url, attempts, lang="en", cookies="") -> list[AttemptRec]:
    """Discovery-driven verification: for EVERY vulnerability discovered (not
    just PHP), try to actively confirm it. A scanner-flagged CVE with a benign
    verifier is exercised hands-on; one without is flagged for manual work so
    nothing is silently taken on a signature alone. All payloads stay benign."""
    from .probes import base as pbase
    zh = lang == "zh"
    cves = _discovered_cves(attempts)
    if not cves:
        return []
    out: list[AttemptRec] = []
    hdrs = {"User-Agent": "Dagger-AI/operator"}
    if cookies:
        hdrs["Cookie"] = cookies
    try:
        http = httpx.Client(timeout=config.REQUEST_TIMEOUT, follow_redirects=True,
                            headers=hdrs)
    except Exception:
        return out
    try:
        for cve, finding in sorted(cves.items()):
            probe = pbase.verifier_for(cve)
            obj = (f"验证 {cve} 是否可被利用" if zh else f"Verify whether {cve} is exploitable")
            if _cve_confirmed(attempts, cve):
                # Already proven hands-on earlier in this run — record the consolidation.
                note = (f"{cve} 已通过内置探针主动验证（见上方证据）。" if zh
                        else f"{cve} already confirmed exploitable by an active probe (evidence above).")
                out.append(AttemptRec(f"verify:{cve}", obj,
                                      [StepRec("note", cve, note, "auto-verify")],
                                      True, 1.0, str(finding.get("evidence", ""))[:200], note,
                                      phase="exploit"))
                continue
            if probe is not None:
                try:
                    recs = probe.execute(url, http)
                except Exception:
                    recs = []
                for a in recs:
                    a.phase = "exploit"
                    a.technique = f"verify:{cve}"
                    a.objective = obj
                    if a.success:
                        a.findings = [{
                            "title": probe.name, "severity": probe.severity, "owasp": probe.owasp,
                            "mitre": probe.mitre, "evidence": a.evidence,
                            "description": probe.description, "remediation": probe.remediation,
                        }]
                        a.rationale = (f"主动验证确认 {cve} 可被利用（良性 PoC，见证据）。" if zh
                                       else f"Active check confirmed {cve} is exploitable (benign PoC — see evidence).")
                    else:
                        a.rationale = (f"主动验证未能复现 {cve}（扫描器告警可能为误报或目标已缓解）。" if zh
                                       else f"Active check could not reproduce {cve} "
                                            "(scanner alert may be a false positive, or the target is mitigated).")
                    out.append(a)
            else:
                # Discovered by a scanner but we have no hands-on verifier for it.
                note = (f"扫描器发现 {cve}，但暂无内置主动验证；已标记需人工确认利用，不仅凭签名下结论。" if zh
                        else f"{cve} was flagged by a scanner but has no built-in active verifier; "
                             "flagged for manual exploitation rather than trusted on signature alone.")
                out.append(AttemptRec(f"verify:{cve}", obj,
                                      [StepRec("note", cve, note, "auto-verify")],
                                      False, 0.0, str(finding.get("evidence", ""))[:200], note,
                                      phase="exploit"))
    finally:
        http.close()
    return out


# -------------------------------------------------------------- LLM glue
# Shared expert persona — a CREST-certified senior pentester's mindset: thinks
# in attack chains and business impact, separates real exploitable issues from
# noise, evidence-driven, never overstates confidence.
_EXPERT = ("You are a CREST-certified (CCT APP & INF) senior penetration tester with 15+ years of "
           "hands-on experience, working to the OWASP Testing Guide and PTES. You reason in attack "
           "chains and business impact, distinguish genuinely exploitable issues from noise, cite "
           "concrete evidence, and never overstate confidence. This is an AUTHORIZED, scoped engagement. ")

_PLAN_SYS = (_EXPERT + "Plan the engagement: given the target and the available modules, write a "
             "concise, ordered plan (<=130 words) — what each phase establishes, which results would "
             "change your approach, and the highest-value checks for this target type. No preamble.")
_SUM_SYS = (_EXPERT + "Write the executive summary: the overall risk posture, the most critical "
            "issues, any realistic ATTACK CHAIN leading to high impact, and the top remediation "
            "priorities in order. Clear for management, precise for engineers. <=180 words. No preamble.")


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
    _EXPERT + "You are driving the engagement tool-by-tool. Given the modules still available and "
    "the results so far, choose the single most valuable NEXT module — prioritise by what the "
    "current evidence suggests is most likely exploitable and impactful, following the kill-chain "
    "order (recon → fingerprint → discovery → vuln → exploit). "
    'Reply ONLY with JSON: {"module": "<module_id>", "reason": "<one expert sentence>"}.')
_VAL_SYS = (
    _EXPERT + "VALIDATE the findings: for each, judge true-positive vs. needs-manual-verification "
    "vs. likely false-positive with brief reasoning; call out any ATTACK CHAINS (how findings "
    "combine to escalate impact); and give the top remediation priorities in order. <=170 words. No preamble.")


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
    _EXPERT + "Explain ONE tool's result to the team in plain language: in 1-2 sentences say what "
    "it found, why it matters (exploitability, what it could lead to, chaining potential), or that "
    "nothing notable was found. No preamble, no raw output, no markdown, no bullet points.")


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


def _run_module(mod, url, host, allow_internal, reason, client=None, lang="en", cookies=""):
    """Run one module, attaching the LLM's reasoning for choosing it (as a step
    note) and a plain-language conclusion of the output (as the rationale)."""
    phase, tool = MODULES[mod]
    out = []
    if tool == "__builtin__":
        out = _web_probe_attempts(url, lang, cookies)
        hits = sum(1 for a in out if a.success)
    else:
        tgt = host if tool == "nmap" else url
        res = tools_client.run(tool, tgt, allow_internal=allow_internal, cookies=cookies)
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
                        on_attempt=None, cancelled=None, lang="en", cookies=""):
    attempts: list[AttemptRec] = []
    chosen = [m for m in MODULES if m in selected] or list(MODULES)
    chosen = _select_for_target(chosen, host)

    # 1) PLAN — the LLM writes the strategy.
    plan_txt = _plan(client, url, host, chosen, lang)
    _emit(attempts, AttemptRec("engagement-plan", f"Plan an authorized assessment of {host}",
                               [StepRec("plan", f"target={url}  scope-host={host}", plan_txt,
                                        "AI operator plan")], False, 0.0, phase="plan"), on_attempt)

    # 2) CLOSED LOOP — the LLM picks the ORDER of the next action adaptively from
    #    results, but EVERY selected module runs (we don't let it skip modules you
    #    chose — that caused inconsistent coverage / missed findings run-to-run).
    remaining = set(chosen)
    ran: list[tuple[str, int]] = []
    budget = max(max_steps, len(chosen))
    while remaining and budget > 0:
        if cancelled and cancelled():
            break
        decision = _next_action(client, url, host, remaining, ran)
        mod = (decision.get("module") or "").strip()
        reason = (decision.get("reason") or "").strip()
        if mod not in remaining:   # "stop"/invalid/empty → next in phase order (still cover it)
            mod = sorted(remaining, key=lambda m: PHASE_ORDER.index(MODULES[m][0]))[0]
            reason = reason or "next phase in order"
        remaining.discard(mod)
        budget -= 1
        recs, hits = _run_module(mod, url, host, allow_internal, reason, client, lang, cookies)
        for a in recs:
            _emit(attempts, a, on_attempt)
        ran.append((mod, hits))

    # 2b) AUTO-VERIFY — for EVERY discovered vuln (not just PHP), actively try to
    #     confirm it with a benign PoC; scanner-only CVEs are flagged for manual work.
    for a in _exploit_verification(url, attempts, lang, cookies):
        _emit(attempts, a, on_attempt)

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
