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
from .llm_client import ANALYTIC_TEMP, LLMClient
from .probes import all_probes
from .records import AttemptRec, StepRec

# module id -> (phase, runner tool). "web_probes" runs in-process.
MODULES = {
    "recon_nmap":          ("recon",       "nmap"),
    "recon_naabu":         ("recon",       "naabu"),
    "recon_subfinder":     ("recon",       "subfinder"),
    "recon_theharvester":  ("recon",       "theharvester"),
    "recon_dnsx":          ("recon",       "dnsx"),
    "probe_httpx":         ("fingerprint", "httpx"),
    "fingerprint_whatweb": ("fingerprint", "whatweb"),
    "waf_wafw00f":         ("fingerprint", "wafw00f"),
    "tls_sslscan":         ("fingerprint", "sslscan"),
    "tls_tlsx":            ("fingerprint", "tlsx"),
    "discovery_ffuf":      ("discovery",   "ffuf"),
    "crawl_katana":        ("discovery",   "katana"),
    "endpoints_js":        ("discovery",   "jsendpoints"),
    "urls_gau":            ("discovery",   "gau"),
    "params_arjun":        ("discovery",   "arjun"),
    "vuln_nuclei":         ("vuln",        "nuclei"),
    "vuln_nikto":          ("vuln",        "nikto"),
    "dast_zap":            ("vuln",        "zap"),
    "tls_testssl":         ("vuln",        "testssl"),
    "cms_wpscan":          ("vuln",        "wpscan"),
    "exploits_searchsploit": ("vuln",      "searchsploit"),
    "sqli_sqlmap":         ("exploit",     "sqlmap"),
    "xss_dalfox":          ("exploit",     "dalfox"),
    "cmdi_commix":         ("exploit",     "commix"),
    "secrets_gitsecrets":  ("exploit",     "gitsecrets"),
    "bruteforce_hydra":    ("exploit",     "hydra"),
    "web_probes":          ("exploit",     "__builtin__"),
}
PHASE_ORDER = ["recon", "fingerprint", "discovery", "vuln", "exploit"]

MODULE_META = {
    "recon_nmap": ("Nmap port & service recon", "nmap"),
    "recon_naabu": ("naabu fast port discovery", "naabu"),
    "recon_subfinder": ("Subfinder subdomain enumeration", "subfinder"),
    "recon_theharvester": ("theHarvester passive OSINT (emails / subdomains)", "theHarvester"),
    "recon_dnsx": ("dnsx DNS resolution & records (A/MX/NS/TXT)", "dnsx"),
    "probe_httpx": ("httpx web probe / tech detect", "httpx"),
    "fingerprint_whatweb": ("WhatWeb fingerprinting", "whatweb"),
    "waf_wafw00f": ("WAFW00F WAF detection", "wafw00f"),
    "tls_sslscan": ("sslscan TLS/SSL analysis", "sslscan"),
    "tls_tlsx": ("tlsx TLS fingerprint & cert hygiene", "tlsx"),
    "discovery_ffuf": ("ffuf content discovery", "ffuf"),
    "crawl_katana": ("Katana crawl / URL discovery", "katana"),
    "endpoints_js": ("JS endpoint & page discovery", "jsendpoints"),
    "urls_gau": ("gau historical URL discovery", "gau"),
    "params_arjun": ("arjun hidden-parameter discovery", "arjun"),
    "vuln_nuclei": ("Nuclei vulnerability scan", "nuclei"),
    "vuln_nikto": ("Nikto web-server scan", "nikto"),
    "dast_zap": ("OWASP ZAP automated DAST scan", "zaproxy"),
    "tls_testssl": ("testssl.sh TLS vulnerability scan", "testssl.sh"),
    "cms_wpscan": ("wpscan WordPress scan", "wpscan"),
    "exploits_searchsploit": ("searchsploit known-exploit intel (Exploit-DB)", "searchsploit"),
    "sqli_sqlmap": ("sqlmap SQLi validation", "sqlmap"),
    "xss_dalfox": ("dalfox XSS validation", "dalfox"),
    "cmdi_commix": ("commix command-injection validation", "commix"),
    "secrets_gitsecrets": ("Exposed .git → secret scan", "git-dumper+trufflehog"),
    "bruteforce_hydra": ("Hydra weak/default-credential check on discovered auth services (SSH/MySQL/LDAP/RDP/FTP…)", "hydra"),
    "web_probes": ("Built-in web probes (OWASP)", "builtin"),
}


# Tools that work against a bare IP or a whole network/CIDR (host vuln scanning),
# vs. the web-path tools that need a single HTTP URL.
NETWORK_TOOLS = {"nmap", "naabu", "httpx", "nuclei"}

# Service/product + version banner, e.g. "Apache httpd 2.2.8", used to seed
# searchsploit from what recon/fingerprint observed.
_PRODVER = re.compile(r"([A-Za-z][A-Za-z0-9.\+\-]{1,28}?)[ /]v?(\d+\.\d+(?:\.\d+)?)")


def _service_terms(attempts) -> list[str]:
    """Collect product/version banners seen so far (nmap/naabu/httpx output and
    finding evidence) to drive searchsploit. Conservative and de-duplicated."""
    cand, seen = [], set()

    def add(s: str):
        s = re.sub(r"\s+", " ", (s or "")).strip(" .,:;—-")
        if len(s) < 3 or not re.search(r"\d", s):
            return
        key = s.lower()
        if key not in seen:
            seen.add(key)
            cand.append(s)

    for a in attempts or []:
        texts = []
        for f in (getattr(a, "findings", None) or []):
            texts.append(f.get("evidence", ""))
        for st in (getattr(a, "steps", None) or []):
            texts.extend((st.response or "").splitlines())
        for line in texts:
            m = re.search(r"open\s*[—:\-]+\s*(.+)$", line)   # nmap "80/tcp open — http Apache 2.2.8"
            if m:
                add(m.group(1))
                continue
            pm = _PRODVER.search(line)
            if pm and not line.lstrip().lower().startswith(("cve", "http/", "[", "{")):
                add(f"{pm.group(1)} {pm.group(2)}")
    return cand[:12]


def _capability_catalog(modules) -> str:
    """The toolbox the LLM may plan over: each candidate module with a one-line
    description, grouped by kill-chain phase. This is 'all our capabilities'."""
    by_phase: dict[str, list[str]] = {}
    for m in modules:
        if m not in MODULES:
            continue
        phase = MODULES[m][0]
        desc = MODULE_META.get(m, (m, MODULES[m][1]))[0]
        by_phase.setdefault(phase, []).append(f"  - {m}: {desc}")
    out = []
    for ph in PHASE_ORDER:
        rows = by_phase.get(ph)
        if rows:
            out.append(f"[{ph}]\n" + "\n".join(sorted(rows)))
    return "\n".join(out)


_CVE_DIGEST = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)


def _evidence_digest(attempts, cap=9000) -> str:
    """A rich intelligence digest of what THIS run has gathered so far, so the
    planner adapts to real evidence (not just finding counts): product/versions,
    discovered endpoints, CVEs, and confirmed findings with short evidence. The
    analytical models have very large context windows, so this is kept generous."""
    if not attempts:
        return "(nothing gathered yet)"
    lines = []
    terms = _service_terms(attempts)
    if terms:
        lines.append("Services/versions seen: " + ", ".join(terms[:24]))
    cves, endpoints, findings = set(), set(), []
    for a in attempts:
        for f in (getattr(a, "findings", None) or []):
            sev = f.get("severity", "info")
            title = f.get("title", "")
            ev = str(f.get("evidence", ""))[:140]
            findings.append(f"[{sev}] {title}" + (f" — {ev}" if ev else ""))
            cves.update(c.upper() for c in _CVE_DIGEST.findall(title + " " + ev))
        for st in (getattr(a, "steps", None) or []):
            resp = st.response or ""
            cves.update(c.upper() for c in _CVE_DIGEST.findall(resp))
            for u in re.findall(r"https?://[^\s'\"<>]+", resp)[:80]:
                endpoints.add(u.rstrip(".,);")[:160])
    if cves:
        lines.append("CVEs referenced: " + ", ".join(sorted(cves)[:40]))
    if endpoints:
        lines.append("Endpoints/URLs seen: " + ", ".join(sorted(endpoints)[:40]))
    if findings:
        lines.append("Confirmed/flagged so far:\n" + "\n".join(f"  - {x}" for x in findings[:50]))
    return ("\n".join(lines) or "(no notable evidence yet)")[:cap]


def _tool_invocation(tool: str, url: str, host: str, attempts=None):
    """(target, options) for a tool: host-oriented tools get the bare host,
    searchsploit gets service/version terms gathered from prior attempts, and
    web-path tools get the URL."""
    if tool in ("nmap", "naabu", "tlsx"):
        return host, None
    if tool == "searchsploit":
        return host, {"terms": _service_terms(attempts)}
    if tool == "hydra":
        # Brute-force the auth services actually discovered on this host.
        return host, {"ports": _discovered_ports(attempts)}
    return url, None


_PORT_OPEN = re.compile(r"(\d{1,5})/(?:tcp|udp)\s+open", re.I)


def _discovered_ports(attempts) -> list:
    """Open TCP/UDP ports seen in recon output (nmap / naabu), so a host-oriented
    exploit tool (hydra) can be pointed only at services that are actually up."""
    ports = set()
    for a in (attempts or []):
        for s in (getattr(a, "steps", None) or []):
            for m in _PORT_OPEN.finditer(s.response or ""):
                p = int(m.group(1))
                if 0 < p < 65536:
                    ports.add(p)
    return sorted(ports)


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
                   on_attempt=None, cancelled=None, lang="en", cookies="", authz="", prior_profile=""):
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
                                   on_attempt, cancelled, lang, ck, authz, prior_profile)
    return _playbook_engagement(client, url, host, selected, allow_internal, max_steps,
                                on_attempt, cancelled, lang, ck, authz, prior_profile)


def _emit(attempts, a, on_attempt):
    attempts.append(a)
    if on_attempt:
        try:
            on_attempt(a)
        except Exception:
            pass
    return a


def _playbook_engagement(client, url, host, selected, allow_internal, max_steps,
                         on_attempt=None, cancelled=None, lang="en", cookies="", authz="",
                         prior_profile=""):
    attempts: list[AttemptRec] = []

    # ---- AI plan (or deterministic note) ----
    chosen = [m for m in MODULES if m in selected] or list(MODULES)
    chosen = _select_for_target(chosen, host)
    plan_txt = _plan(client, url, host, chosen, lang, prior_profile)
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
            for a in _web_probe_attempts(url, lang, cookies, authz):
                _emit(attempts, a, on_attempt)
            continue
        tgt, opts = _tool_invocation(tool, url, host, attempts)
        res = tools_client.run(tool, tgt, options=opts, allow_internal=allow_internal,
                               cookies=cookies, auth_header=authz)
        _emit(attempts, _attempt_from_tool(mod, phase, res, lang), on_attempt)
        if tool == "jsendpoints":   # scan the discovered backend surface
            for sa in _scan_discovered(res, allow_internal, lang, cookies, authz):
                _emit(attempts, sa, on_attempt)

    # ---- auto-verify EVERY discovered vuln (not just PHP) ----
    for a in _exploit_verification(url, attempts, lang, cookies, authz):
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
        err = str(res.get("error", "") or "")
        # Distinguish a genuine missing tool from a runner transport/5xx error —
        # the latter is NOT "not installed" and was previously mislabelled as such.
        runner_err = ("runner" in err.lower()) or ("unreachable" in err.lower())
        if runner_err:
            tag = "[工具运行器错误] " if zh else "[tool-runner error] "
            rat = ("工具运行器返回错误（非工具缺失）。" if zh else "Tool-runner returned an error (not a missing tool).")
        else:
            tag = "[工具运行器未安装此工具] " if zh else "[tool not installed in tool-runner] "
            rat = ("该工具在工具运行器中不可用。" if zh else "Tool unavailable.")
        return AttemptRec(name, f"Run {mod}",
                          [StepRec("tool", res.get("command", mod), tag + err,
                                   f"{phase}: {name}")],
                          False, 0.0, rationale=rat, phase=phase)
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


def _web_probe_attempts(url, lang="en", cookies="", authz="") -> list[AttemptRec]:
    """Run the in-process web probes (OWASP) against the URL as part of exploit phase."""
    from . import translations
    out = []
    web = [p for p in all_probes() if getattr(p, "category", "") == "web"]
    hdrs = {"User-Agent": "Dagger-AI/operator"}
    if cookies:
        hdrs["Cookie"] = cookies
    if authz:
        hdrs["Authorization"] = authz
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


def _exploit_verification(url, attempts, lang="en", cookies="", authz="") -> list[AttemptRec]:
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
    if authz:
        hdrs["Authorization"] = authz
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

# Shared formatting rule: the console renders these texts in several places, some
# of which show them verbatim, so raw markdown (**, #, backticks) leaks as noise.
# Keep the model to clean plain text everywhere it writes for the UI.
_PLAIN = ("FORMAT: plain text only. Do NOT use markdown — no ** or __ for bold, no # headings, no "
          "backticks, no tables. Plain sentences, numbered points and simple '- ' bullets are fine.")

_PLAN_SYS = (_EXPERT +
    "Produce the ENGAGEMENT ATTACK PLAN a lead tester writes before touching the target — a real plan, "
    "not a generic methodology recital. Plan over the FULL arsenal: both the integrated capability "
    "catalog you are given AND the external tools a senior tester reaches for (e.g. Burp Suite, sqlmap, "
    "Metasploit, Hydra, ffuf, CrackMapExec, BloodHound, a hand-written PoC) — name an external tool where "
    "it is the right instrument and mark it (external). Ground EVERY decision in the PRIOR INTELLIGENCE: "
    "cite the specific observed port / service / version / component / CVE / WAF / path / finding that "
    "drives it, and do NOT plan to re-discover what is already known. Be concrete to THIS target; a plan "
    "that would read the same for any host is a failure.\n"
    "Cover these five sections in order, each on its own line starting with its number and a short label "
    "followed by a colon (e.g. '1. Attack surface:'), then tight prose or simple dashed bullets:\n"
    "1. Attack surface — what the intel establishes: exposed services, tech stack, auth/trust boundaries, "
    "the most exposed entry points.\n"
    "2. Prioritised attack paths — RANKED by (likelihood exploitable x business impact). For each: the "
    "hypothesis, the exact evidence it rests on, the capability/tool that proves it, and the result that "
    "would confirm or kill it.\n"
    "3. Attack chains — how individual weaknesses combine to escalate (initial access -> foothold -> "
    "privilege / data / impact) and the realistic worst case.\n"
    "4. Phased execution — recon -> fingerprint -> discovery -> vuln -> exploit: which capabilities you "
    "LEAD with given what is already known, and what you deliberately skip because the intel answers it.\n"
    "5. Pivot & stop criteria — the observations that would change the plan or pull a deeper tool forward, "
    "and what 'done' looks like.\n"
    "<=420 words. No preamble, no sign-off. " + _PLAIN)
_SUM_SYS = (_EXPERT + "Write the executive summary: the overall risk posture, the most critical "
            "issues, any realistic ATTACK CHAIN leading to high impact, and the top remediation "
            "priorities in order. Clear for management, precise for engineers. <=180 words. No preamble. "
            + _PLAIN)


def _plan(client, url, host, chosen, lang="en", prior_profile=""):
    if client.online:
        catalog = _capability_catalog(chosen)
        intel = (prior_profile or "").strip()
        user = (f"Target: {url} (host {host})\n\n"
                f"Capability catalog (phase → modules you may use):\n{catalog}\n")
        if intel:
            user += ("\nPRIOR INTELLIGENCE on this target (accumulated from earlier scans — "
                     "plan from this, don't re-discover what is already known):\n" + intel + "\n")
        else:
            user += "\nPRIOR INTELLIGENCE: none — this is a first look at the target.\n"
        out = client.complete(_PLAN_SYS + _lang_suffix(lang), user,
                              temperature=ANALYTIC_TEMP, max_tokens=4096)
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
        out = client.complete(_SUM_SYS + _lang_suffix(lang), f"Host: {host}\nFindings:\n{brief}",
                              temperature=ANALYTIC_TEMP, max_tokens=2048)
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
    _EXPERT + "You are EXECUTING the engagement attack plan tool-by-tool, adapting to real evidence. You "
    "are given the ATTACK PLAN you drew up, the capability catalog of modules still available, the PRIOR "
    "INTELLIGENCE on this target, and the EVIDENCE gathered so far this run. Advance the plan's highest "
    "priority attack path that is not yet resolved; deviate from it only when the evidence makes a "
    "different move clearly more valuable (say so in the reason). Choose the single most valuable NEXT "
    "module — prioritise by what "
    "the current evidence suggests is most likely exploitable and impactful, generally following the "
    "kill-chain order (recon → fingerprint → discovery → vuln → exploit) but pulling a deeper/targeted "
    "tool forward when evidence justifies it (e.g. a WordPress banner → cms_wpscan; a product+version → "
    "exploits_searchsploit; discovered parameters → an injection validator; exposed auth services such as "
    "SSH/MySQL/LDAP/RDP/FTP → bruteforce_hydra for a bounded weak/default-credential check). You MUST pick a module id "
    "that appears in the catalog. Only answer done=true once the available high-value modules are "
    "exhausted and nothing in the evidence warrants further action. "
    'Reply ONLY with JSON: {"module": "<module_id>", "reason": "<one expert sentence>"} '
    'or {"done": true, "reason": "<why the engagement is complete>"}.')
_VAL_SYS = (
    _EXPERT + "VALIDATE the findings: for each, judge true-positive vs. needs-manual-verification "
    "vs. likely false-positive with brief reasoning; call out any ATTACK CHAINS (how findings "
    "combine to escalate impact); and give the top remediation priorities in order. <=170 words. No preamble. "
    + _PLAIN)


def _next_action(client, url, host, remaining, ran, attempts=None, prior_profile="", plan="",
                 decisions=None) -> dict:
    catalog = _capability_catalog(remaining)
    ran_txt = "\n".join(f"  - {m}: {n} finding(s)" for m, n in ran) or "  (nothing run yet)"
    intel = (prior_profile or "").strip()
    digest = _evidence_digest(attempts or [])
    plan = (plan or "").strip()
    user = f"Target: {url} (host {host})\nPhase order: {' -> '.join(PHASE_ORDER)}\n\n"
    if plan:
        user += "YOUR ATTACK PLAN for this engagement (execute it, adapt on evidence):\n" + plan[:6000] + "\n\n"
    # Working memory: the agent's own recent moves and why, so it builds on its
    # reasoning instead of re-deriving every step and does not loop on dead ends.
    if decisions:
        mem = "\n".join(
            f"  {i+1}. {d['mod']} — {d.get('reason','')[:160]} -> "
            f"{'FOUND ' + str(d['hits']) if d.get('hits') else 'nothing'}"
            for i, d in enumerate(decisions[-12:]))
        user += "YOUR RECENT DECISIONS (newest last — do not repeat a dead end):\n" + mem + "\n\n"
    user += (f"Modules still available (pick one of these ids):\n{catalog}\n\n"
             f"Already run this engagement:\n{ran_txt}\n\n"
             f"EVIDENCE gathered this run:\n{digest}\n")
    if intel:
        user += "\nPRIOR INTELLIGENCE on this target (earlier scans):\n" + intel + "\n"
    user += ("\nChoose the next module id that best advances the plan now, or answer done=true if the "
             "plan's attack paths are exhausted and nothing in the evidence warrants further action.")
    data = client.complete_json(_NEXT_SYS, user)
    return data or {}


_REPLAN_SYS = (_EXPERT +
    "New evidence has arrived mid-engagement. Given YOUR ORIGINAL PLAN and the NEW EVIDENCE, "
    "REVISE the plan: state briefly what the evidence changes, which attack path is now the "
    "priority and why, and the concrete next moves (tools + what would confirm impact). Keep what "
    "still holds; drop what the evidence killed. <=220 words. No preamble. " + _PLAIN)


def _replan(client, url, host, plan, attempts, lang="en", prior_profile=""):
    """One focused plan revision when the engagement turns up a real finding, so
    the strategy adapts to what was actually discovered instead of staying frozen
    at the first-look plan. Returns the revised plan text (or the original on failure)."""
    if not (client and client.online):
        return plan
    digest = _evidence_digest(attempts or [])
    user = (f"Target: {url} (host {host})\n\nYOUR ORIGINAL PLAN:\n{(plan or '')[:6000]}\n\n"
            f"NEW EVIDENCE gathered so far this run:\n{digest}\n")
    if prior_profile:
        user += "\nPRIOR INTELLIGENCE:\n" + prior_profile.strip()[:4000] + "\n"
    out = client.complete(_REPLAN_SYS + _lang_suffix(lang), user,
                          temperature=ANALYTIC_TEMP, max_tokens=2048)
    return out.strip() or plan


def _validate(client, host, attempts, lang="en") -> str:
    allf = [f for a in attempts for f in a.findings]
    if not allf:
        return ""
    brief = "\n".join(
        f"- [{f.get('severity')}] {f.get('title')} ({f.get('owasp','')}) "
        f"evidence: {str(f.get('evidence',''))[:80]}" for f in allf[:40])
    return client.complete(_VAL_SYS + _lang_suffix(lang), f"Host: {host}\nFindings:\n{brief}",
                           temperature=ANALYTIC_TEMP, max_tokens=1536).strip()


_INTERP_SYS = (
    _EXPERT + "Summarise ONE tool's result for the live feed in a SINGLE short sentence (<=22 words): "
    "what it found and why it matters (exploitability / chaining), or that nothing notable turned up. "
    "Terse and scannable. No preamble, no raw output, no markdown, no bullet points, no restating the tool name.")


def _lang_suffix(lang: str) -> str:
    """Make the LLM answer in the operator's UI language."""
    if lang == "zh":
        return ("\n\nIMPORTANT: Write your ENTIRE response in Simplified Chinese (简体中文) — "
                "every sentence, including technical explanations. Do not answer in English.")
    return ""


def _interpret(client, mod, res, lang="en") -> str:
    """Ask the LLM for a short, human-readable conclusion of one tool's output,
    so the operator doesn't just dump raw nmap/nuclei/ffuf text at the user.

    Cost guard: a clean recon/fingerprint step carries no finding to explain, and
    those tools dominate the run (now fired in parallel), so we skip the LLM call
    there and let the deterministic one-liner stand. The spend goes where it is
    worth it — anything with a finding, and the deeper discovery/vuln/exploit work."""
    if not (client and client.online):
        return ""
    findings = res.get("findings", []) or []
    phase = MODULES.get(mod, ("", ""))[0]
    if not findings and phase in ("recon", "fingerprint"):
        return ""
    name = MODULE_META.get(mod, (mod, mod))[0]
    obs = res.get("observations", []) or []
    fbrief = "; ".join(f"{f.get('severity')}: {f.get('title')}" for f in findings[:12]) \
        or "no confirmed findings"
    obrief = "\n".join(obs[:16])[:800]
    out = client.complete(
        _INTERP_SYS + _lang_suffix(lang),
        f"Tool: {name}\nConfirmed findings: {fbrief}\nObservations:\n{obrief}\n\n"
        "Give the one-sentence takeaway.",
        temperature=ANALYTIC_TEMP, max_tokens=160)
    return out.strip()


def _scan_discovered(res, allow_internal, lang="en", cookies="", authz=""):
    """Actively scan the endpoints/pages that jsendpoints discovered: fingerprint
    them (httpx — may reveal PHP / X-Powered-By on the real backend) and vuln-scan
    them (nuclei, with its PHP/CVE templates). This is how we reach the backend
    attack surface that a SPA hides behind its frontend."""
    disc = list(dict.fromkeys((res.get("endpoints") or []) + (res.get("pages") or [])))[:50]
    if not disc:
        return []
    zh = lang == "zh"
    out = []
    hres = tools_client.run("httpx", disc[0], options={"targets": disc},
                            allow_internal=allow_internal, cookies=cookies, auth_header=authz)
    ha = _attempt_from_tool("probe_httpx", "fingerprint", hres, lang)
    ha.technique = (f"httpx 指纹：已发现的 {len(disc)} 个接口/页面" if zh
                    else f"httpx fingerprint of {len(disc)} discovered endpoints/pages")
    out.append(ha)
    nres = tools_client.run("nuclei", disc[0], options={"targets": disc},
                            allow_internal=allow_internal, cookies=cookies, auth_header=authz)
    na = _attempt_from_tool("vuln_nuclei", "vuln", nres, lang)
    na.technique = (f"Nuclei 扫描：已发现的 {len(disc)} 个接口/页面" if zh
                    else f"Nuclei scan of {len(disc)} discovered endpoints/pages")
    out.append(na)
    return out


def _run_module(mod, url, host, allow_internal, reason, client=None, lang="en", cookies="",
                attempts=None, authz=""):
    """Run one module, attaching the LLM's reasoning for choosing it (as a step
    note) and a plain-language conclusion of the output (as the rationale).
    `attempts` (prior results) seeds tools like searchsploit that need context."""
    phase, tool = MODULES[mod]
    out = []
    if tool == "__builtin__":
        out = _web_probe_attempts(url, lang, cookies, authz)
        hits = sum(1 for a in out if a.success)
    else:
        tgt, opts = _tool_invocation(tool, url, host, attempts)
        res = tools_client.run(tool, tgt, options=opts, allow_internal=allow_internal,
                               cookies=cookies, auth_header=authz)
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
        if tool == "jsendpoints":   # scan the discovered backend surface
            for sa in _scan_discovered(res, allow_internal, lang, cookies, authz):
                out.append(sa)
                hits += len((sa.findings or []))
    return out, hits


def _parallel_tool_runs(mods, url, host, allow_internal, cookies, authz) -> dict:
    """Run several independent modules' tool invocations CONCURRENTLY, returning
    {mod: result}. Only the subprocess/network wait overlaps; attempt building and
    emission stay with the caller (single-threaded), so the shared DB session and
    the attempts list are never touched from a worker thread."""
    import concurrent.futures as cf
    results: dict[str, dict] = {}

    def _work(mod):
        _, tool = MODULES[mod]
        tgt, opts = _tool_invocation(tool, url, host, None)
        return mod, tools_client.run(tool, tgt, options=opts, allow_internal=allow_internal,
                                     cookies=cookies, auth_header=authz)

    workers = max(1, min(len(mods), config.PARALLEL_WORKERS))
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in cf.as_completed([ex.submit(_work, m) for m in mods]):
            try:
                m, res = fut.result()
                results[m] = res
            except Exception:
                pass
    return results


def _available_modules(host):
    """All modules the runner can actually execute now (tool present), filtered to
    the target type. Falls back to the full set if the runner can't be queried —
    unavailable tools degrade gracefully to a 'not available' attempt anyway."""
    try:
        avail = set(tools_client.available().keys())
    except Exception:
        avail = set()
    pool = [m for m, (_, tool) in MODULES.items()
            if tool == "__builtin__" or not avail or tool in avail]
    return _select_for_target(pool, host)


def _agentic_engagement(client, url, host, selected, allow_internal, max_steps,
                        on_attempt=None, cancelled=None, lang="en", cookies="", authz="",
                        prior_profile=""):
    attempts: list[AttemptRec] = []
    # Coverage floor: every module you selected runs. Candidate pool: the whole
    # available toolbox, so the LLM can adaptively pull in a deeper capability the
    # evidence calls for — beyond what was preselected.
    selected_mods = _select_for_target([m for m in MODULES if m in selected] or list(MODULES), host)
    candidates = _available_modules(host)
    for m in selected_mods:            # ensure selection is always a candidate
        if m not in candidates:
            candidates.append(m)

    # 1) PLAN — the LLM writes the strategy from the full catalog + prior intel.
    plan_txt = _plan(client, url, host, candidates, lang, prior_profile)
    _emit(attempts, AttemptRec("engagement-plan", f"Plan an authorized assessment of {host}",
                               [StepRec("plan", f"target={url}  scope-host={host}", plan_txt,
                                        "AI operator plan")], False, 0.0, phase="plan"), on_attempt)

    run_set: set[str] = set()
    ran: list[tuple[str, int]] = []
    decisions: list[dict] = []   # working memory: what the agent chose, why, payoff
    replanned = False            # one adaptive re-plan per engagement (cost guard)

    # 1b) PARALLEL RECON — fire every independent recon/fingerprint gatherer at
    #     once. They are read-only collectors with no ordering dependency, so
    #     overlapping their subprocess/network waits collapses the slowest phase
    #     with no loss of adaptivity: the deeper discovery/vuln/exploit choices
    #     still go through the closed loop below, now seeded with full recon.
    pre = [m for m in candidates
           if MODULES[m][0] in ("recon", "fingerprint") and MODULES[m][1] != "__builtin__"]
    if pre and not (cancelled and cancelled()):
        res_map = _parallel_tool_runs(pre, url, host, allow_internal, cookies, authz)
        for mod in sorted(pre, key=lambda m: PHASE_ORDER.index(MODULES[m][0])):
            res = res_map.get(mod)
            if res is None:
                continue
            a = _attempt_from_tool(mod, MODULES[mod][0], res, lang)
            concl = _interpret(client, mod, res, lang)
            if concl:
                a.rationale = concl
            if a.steps:
                tag = "并行侦察 · " if lang == "zh" else "parallel recon · "
                a.steps[0].note = tag + (a.steps[0].note or "")
            _emit(attempts, a, on_attempt)
            run_set.add(mod)
            ran.append((mod, len(res.get("findings", []) or [])))

    # 2) CLOSED LOOP — each step the LLM re-reads the evidence gathered so far and
    #    picks the most valuable next module (from the whole toolbox), or declares
    #    the engagement complete. Guards: the selection is always covered before a
    #    "done" is honoured, and a step budget bounds adaptive exploration.
    budget = max(max_steps, len(selected_mods))
    while budget > 0:
        if cancelled and cancelled():
            break
        uncovered = [m for m in selected_mods if m not in run_set]
        remaining = [m for m in candidates if m not in run_set]
        if not remaining:
            break
        decision = _next_action(client, url, host, remaining, ran, attempts, prior_profile,
                                plan_txt, decisions)
        done = bool(decision.get("done"))
        mod = (decision.get("module") or "").strip()
        reason = (decision.get("reason") or "").strip()
        adaptive = False
        if done:
            if not uncovered:
                break                       # LLM complete AND selection covered → stop
            mod = sorted(uncovered, key=lambda m: PHASE_ORDER.index(MODULES[m][0]))[0]
            reason = reason or "coverage floor: selected module not yet run"
        elif mod not in run_set and mod in candidates:
            adaptive = mod not in selected_mods   # LLM pulled in a tool beyond selection
        else:                                # invalid/empty pick → next uncovered, else next remaining
            pool = uncovered or remaining
            mod = sorted(pool, key=lambda m: PHASE_ORDER.index(MODULES[m][0]))[0]
            reason = reason or "next phase in order"
        if mod in run_set:
            break
        run_set.add(mod)
        budget -= 1
        if adaptive:
            reason = ("adaptive (pulled in from evidence): " + reason) if reason else \
                     "adaptive: pulled in based on evidence"
        recs, hits = _run_module(mod, url, host, allow_internal, reason, client, lang, cookies,
                                 attempts=attempts, authz=authz)
        for a in recs:
            _emit(attempts, a, on_attempt)
        ran.append((mod, hits))
        decisions.append({"mod": mod, "reason": reason, "hits": hits})

        # 2a) ADAPTIVE RE-PLAN — the first real finding changes the picture, so
        #     revise the strategy once (bounded) and let the rest of the loop
        #     execute the updated plan instead of the frozen first-look one.
        if hits and not replanned and not (cancelled and cancelled()):
            replanned = True
            new_plan = _replan(client, url, host, plan_txt, attempts, lang, prior_profile)
            if new_plan and new_plan != plan_txt:
                plan_txt = new_plan
                _emit(attempts, AttemptRec(
                    "engagement-plan", f"Revise the plan for {host} on new evidence",
                    [StepRec("plan", f"re-plan after finding via {mod}", plan_txt,
                             "AI operator re-plan")], False, 0.0, phase="plan"), on_attempt)

    # 2b) AUTO-VERIFY — for EVERY discovered vuln (not just PHP), actively try to
    #     confirm it with a benign PoC; scanner-only CVEs are flagged for manual work.
    for a in _exploit_verification(url, attempts, lang, cookies, authz):
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
