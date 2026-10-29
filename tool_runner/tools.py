"""Tool integrations for the Dagger-AI tool-runner sidecar.

Each wrapper invokes a best-of-breed pentest binary, captures its output, and
normalises it into a common shape:

    {tool, available, command, returncode, stdout (truncated), duration_ms,
     findings:[{title,severity,owasp,mitre,evidence,description,remediation}],
     observations:[str], error}

Wrappers degrade gracefully: if a binary is absent (`shutil.which` is None) the
result is {available: False} instead of crashing, so the platform still runs
with whatever tools are installed. This module is self-contained (stdlib only)
and runs inside the isolated tools container.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET

MAX_OUT = 8000


def _which(bin_):
    return shutil.which(bin_) is not None


def _cookie_args(tool, options):
    """Extra argv that make `tool` send the campaign's session cookies, so scans
    run authenticated. Each tool has its own flag; tools without cookie support
    get nothing."""
    c = (options or {}).get("cookies", "")
    if not c:
        return []
    hdr = "Cookie: " + c
    if tool in ("httpx", "nuclei", "ffuf", "katana"):
        return ["-H", hdr]
    if tool == "sqlmap":
        return ["--cookie=" + c]
    if tool == "dalfox":
        return ["-C", c]
    if tool == "arjun":
        return ["--headers", hdr]
    if tool == "wpscan":
        return ["--cookie-string", c]
    if tool == "whatweb":
        return ["--cookie", c]
    return []


def _run(cmd, timeout):
    start = time.time()
    try:
        # stdin=DEVNULL so tools don't treat the (non-tty) server stdin as input —
        # e.g. commix otherwise reads its target list from stdin and does nothing.
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        out = (p.stdout or "") + (("\n[stderr]\n" + p.stderr) if p.stderr else "")
        return p.returncode, out, int((time.time() - start) * 1000), None
    except subprocess.TimeoutExpired as e:
        return None, (e.stdout or ""), int((time.time() - start) * 1000), "timeout"
    except Exception as e:  # noqa: BLE001
        return None, "", int((time.time() - start) * 1000), str(e)


def _result(tool, cmd, rc=None, out="", ms=0, findings=None, obs=None, available=True, error=None):
    return {"tool": tool, "available": available, "command": " ".join(cmd) if isinstance(cmd, list) else cmd,
            "returncode": rc, "stdout": (out or "")[:MAX_OUT], "duration_ms": ms,
            "findings": findings or [], "observations": obs or [], "error": error}


SENSITIVE_PATHS = (".git", ".env", "backup", "admin", "config", "wp-admin", "phpinfo",
                   ".svn", "id_rsa", "dump", "db", "actuator", "swagger")


# ---------------------------------------------------------------- nmap (recon)
def nmap(target, options=None, timeout=240):
    if not _which("nmap"):
        return _result("nmap", "nmap", available=False)
    cmd = ["nmap", "-sT", "-sV", "-Pn", "-T4", "--top-ports", "200", "-oX", "-", target]
    rc, out, ms, err = _run(cmd, timeout)
    obs, findings = [], []
    try:
        root = ET.fromstring(out)
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                pid = port.get("portid"); proto = port.get("protocol")
                svc = port.find("service")
                name = svc.get("name") if svc is not None else "?"
                ver = (svc.get("product", "") + " " + svc.get("version", "")).strip() if svc is not None else ""
                obs.append(f"{pid}/{proto} open — {name} {ver}".strip())
                if name in ("telnet", "ftp", "rlogin", "vnc", "smb", "microsoft-ds", "rpcbind"):
                    findings.append({"title": f"Exposed {name} service on port {pid}",
                                     "severity": "medium", "owasp": "A05", "mitre": "T1046",
                                     "evidence": f"{pid}/{proto} {name} {ver}".strip(),
                                     "description": f"A potentially risky service ({name}) is exposed.",
                                     "remediation": "Restrict or disable unneeded network services; firewall them."})
    except ET.ParseError:
        pass
    return _result("nmap", cmd, rc, out, ms, findings, obs, error=err)


# -------------------------------------------------------- httpx (probe/fingerprint)
def httpx(target, options=None, timeout=120):
    if not _which("httpx"):
        return _result("httpx", "httpx", available=False)
    cmd = ["httpx", "-u", target, "-json", "-silent", "-title", "-tech-detect",
           "-status-code", "-web-server", "-no-color"] + _cookie_args("httpx", options)
    rc, out, ms, err = _run(cmd, timeout)
    obs, findings = [], []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        tech = ",".join(d.get("tech", []) or d.get("technologies", []) or [])
        obs.append(f"{d.get('url','')} [{d.get('status_code','')}] "
                   f"{d.get('title','')} {('('+tech+')') if tech else ''}".strip())
        if d.get("webserver"):
            obs.append("server: " + d["webserver"])
    return _result("httpx", cmd, rc, out, ms, findings, obs, error=err)


# ------------------------------------------------------- nuclei (vuln scanning)
def nuclei(target, options=None, timeout=600):
    if not _which("nuclei"):
        return _result("nuclei", "nuclei", available=False)
    sev = (options or {}).get("severity", "low,medium,high,critical")
    cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-no-color", "-severity", sev] + _cookie_args("nuclei", options)
    rc, out, ms, err = _run(cmd, timeout)
    findings, obs = [], []
    for line in (out or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = d.get("info", {})
        cls = info.get("classification", {}) or {}
        cves = ",".join(cls.get("cve-id", []) or [])
        findings.append({
            "title": info.get("name", d.get("template-id", "nuclei finding")),
            "severity": (info.get("severity", "info") or "info").lower(),
            "owasp": "", "mitre": "T1595.002",
            "evidence": (d.get("matched-at") or d.get("host", "")) + (f"  [{cves}]" if cves else ""),
            "description": info.get("description", "") or f"nuclei template {d.get('template-id','')} matched.",
            "remediation": info.get("remediation", "") or "Review and patch per the referenced template/CVE.",
        })
    return _result("nuclei", cmd, rc, out, ms, findings, obs, error=err)


# ------------------------------------------------------ ffuf (content discovery)
def ffuf(target, options=None, timeout=240):
    if not _which("ffuf"):
        return _result("ffuf", "ffuf", available=False)
    wordlist = (options or {}).get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
    base = target.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", base, "-w", wordlist, "-mc", "200,204,301,302,307,401,403",
           "-of", "json", "-o", "/dev/stdout", "-s"] + _cookie_args("ffuf", options)
    rc, out, ms, err = _run(cmd, timeout)
    findings, obs = [], []
    try:
        data = json.loads(out[out.index("{"):out.rindex("}") + 1]) if "{" in out else {}
        for r in data.get("results", []):
            path = r.get("url", ""); status = r.get("status", "")
            obs.append(f"{status} {path}")
            if any(s in path.lower() for s in SENSITIVE_PATHS):
                findings.append({"title": f"Sensitive path exposed: {path}",
                                 "severity": "medium", "owasp": "A05", "mitre": "T1083",
                                 "evidence": f"HTTP {status} {path}",
                                 "description": "A sensitive or administrative path is reachable.",
                                 "remediation": "Remove/relocate or require authentication for sensitive paths."})
    except (ValueError, json.JSONDecodeError):
        pass
    return _result("ffuf", cmd, rc, out, ms, findings, obs, error=err)


# --------------------------------------------------------- whatweb (fingerprint)
def whatweb(target, options=None, timeout=90):
    if not _which("whatweb"):
        return _result("whatweb", "whatweb", available=False)
    cmd = ["whatweb", "--log-json=-", "--color=never", target] + _cookie_args("whatweb", options)
    rc, out, ms, err = _run(cmd, timeout)
    findings, obs = [], []
    try:
        start = out.index("["); arr = json.loads(out[start:out.rindex("]") + 1])
        for entry in arr:
            plugins = entry.get("plugins", {})
            for name, meta in plugins.items():
                ver = ",".join(meta.get("version", []) or [])
                obs.append(f"{name} {ver}".strip())
                if ver:
                    findings.append({"title": f"Version disclosed: {name} {ver}",
                                     "severity": "low", "owasp": "A06", "mitre": "T1595.002",
                                     "evidence": f"{name} {ver}",
                                     "description": "Component/version banner disclosed, easing CVE targeting.",
                                     "remediation": "Suppress version banners where possible."})
    except (ValueError, json.JSONDecodeError):
        pass
    return _result("whatweb", cmd, rc, out, ms, findings, obs, error=err)


# ------------------------------------------------------ sqlmap (SQLi validation)
def sqlmap(target, options=None, timeout=420):
    if not _which("sqlmap"):
        return _result("sqlmap", "sqlmap", available=False)
    cmd = ["sqlmap", "-u", target, "--batch", "--level", "2", "--risk", "1",
           "--smart", "--flush-session", "--disable-coloring"] + _cookie_args("sqlmap", options)
    rc, out, ms, err = _run(cmd, timeout)
    findings = []
    low = (out or "").lower()
    if "is vulnerable" in low or "sqlmap identified the following injection point" in low \
            or "parameter:" in low and "type:" in low:
        findings.append({"title": "SQL injection confirmed (sqlmap)",
                         "severity": "critical", "owasp": "A03", "mitre": "T1190",
                         "evidence": _extract(out, "Parameter:", 400) or "sqlmap flagged an injectable parameter",
                         "description": "sqlmap confirmed an exploitable SQL injection point.",
                         "remediation": "Use parameterised queries; validate input; least-privilege DB account."})
    return _result("sqlmap", cmd, rc, out, ms, findings, error=err)


def _extract(text, marker, n):
    i = (text or "").find(marker)
    return text[i:i + n].strip() if i >= 0 else ""


def _host_only(target):
    return target.split("://")[-1].split("/")[0]


# --------------------------------------------------------- subfinder (recon)
def subfinder(target, options=None, timeout=180):
    if not _which("subfinder"):
        return _result("subfinder", "subfinder", available=False)
    host = _host_only(target).split(":")[0]
    cmd = ["subfinder", "-d", host, "-silent", "-all"]
    rc, out, ms, err = _run(cmd, timeout)
    subs = [l.strip() for l in (out or "").splitlines() if l.strip() and "." in l]
    return _result("subfinder", cmd, rc, out, ms, [], subs[:200], error=err)


# ------------------------------------------------------------ katana (discovery)
def katana(target, options=None, timeout=180):
    if not _which("katana"):
        return _result("katana", "katana", available=False)
    cmd = ["katana", "-u", target, "-silent", "-d", "2", "-jc", "-nc"] + _cookie_args("katana", options)
    rc, out, ms, err = _run(cmd, timeout)
    urls = [l.strip() for l in (out or "").splitlines() if l.strip().startswith("http")]
    return _result("katana", cmd, rc, out, ms, [], urls[:300], error=err)


# ----------------------------------------------------------- wafw00f (fingerprint)
def wafw00f(target, options=None, timeout=90):
    if not _which("wafw00f"):
        return _result("wafw00f", "wafw00f", available=False)
    cmd = ["wafw00f", target, "-a"]
    rc, out, ms, err = _run(cmd, timeout)
    obs = ["WAF: " + m.group(1).strip() for m in re.finditer(r"is behind (.+?)(?: WAF| \()", out or "")]
    if not obs and re.search(r"(No WAF|seems to be behind no)", out or "", re.I):
        obs = ["No WAF detected"]
    return _result("wafw00f", cmd, rc, out, ms, [], obs, error=err)


# --------------------------------------------------------- sslscan (TLS/SSL)
def sslscan(target, options=None, timeout=120):
    if not _which("sslscan"):
        return _result("sslscan", "sslscan", available=False)
    host = _host_only(target)
    if ":" not in host:
        host += ":443"
    cmd = ["sslscan", "--no-colour", host]
    rc, out, ms, err = _run(cmd, timeout)
    findings, obs = [], []
    for proto, sev in (("SSLv2", "high"), ("SSLv3", "high"), ("TLSv1.0", "medium"), ("TLSv1.1", "medium")):
        if re.search(rf"{re.escape(proto)}\s+enabled", out or "") or \
           re.search(rf"Accepted.*{re.escape(proto)}", out or ""):
            obs.append(f"{proto} enabled")
            findings.append({"title": f"Weak TLS protocol enabled: {proto}", "severity": sev,
                             "owasp": "A02", "mitre": "T1040", "evidence": proto,
                             "description": f"{proto} is deprecated and insecure.",
                             "remediation": "Disable legacy SSL/TLS; require TLS 1.2+."})
    return _result("sslscan", cmd, rc, out, ms, findings, obs, error=err)


# --------------------------------------------------------- nikto (vuln)
def nikto(target, options=None, timeout=300):
    if not _which("nikto"):
        return _result("nikto", "nikto", available=False)
    cmd = ["nikto", "-h", target, "-nointeractive", "-maxtime", "180s", "-ask", "no"]
    rc, out, ms, err = _run(cmd, timeout)
    findings, obs = [], []
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("+ ") and len(line) > 6:
            item = line[2:].strip()
            obs.append(item[:160])
            low = item.lower()
            if any(k in low for k in ("osvdb", "vulnerable", "injection", "xss", "disclosure",
                                      "default", "backup", "admin", "outdated", "deprecated", ".git", "cve")):
                findings.append({"title": "Nikto: " + item[:90], "severity": "medium", "owasp": "A05",
                                 "mitre": "T1595", "evidence": item[:200],
                                 "description": "Nikto flagged a potential web-server issue.",
                                 "remediation": "Review and remediate the flagged item."})
    return _result("nikto", cmd, rc, out, ms, findings[:30], obs[:60], error=err)


# --------------------------------------------------------- dalfox (XSS exploit)
def dalfox(target, options=None, timeout=240):
    if not _which("dalfox"):
        return _result("dalfox", "dalfox", available=False)
    cmd = ["dalfox", "url", target, "--no-color", "--silence", "--no-spinner"] + _cookie_args("dalfox", options)
    rc, out, ms, err = _run(cmd, timeout)
    findings = []
    for line in (out or "").splitlines():
        if "[POC]" in line or "[VULN]" in line:
            findings.append({"title": "Cross-site scripting (dalfox)", "severity": "high",
                             "owasp": "A03", "mitre": "T1059.007", "evidence": line.strip()[:300],
                             "description": "dalfox produced a working XSS proof of concept.",
                             "remediation": "Context-aware output encoding; strict CSP."})
    return _result("dalfox", cmd, rc, out, ms, findings[:20], error=err)


# ------------------------------------------------- commix (command injection exploit)
def commix(target, options=None, timeout=300):
    """Validate OS command injection by exploiting it and running a single BENIGN
    proof command (`id`). Capturing `id` output proves shell-level code execution
    (the pentest-report standard) without any payload, reverse shell or change to
    the target — just evidence that an attacker could get a shell here."""
    if not _which("commix"):
        return _result("commix", "commix", available=False)
    # commix treats a non-TTY stdin as a piped targets list and ignores --url, so
    # run it under `script` to give it a pseudo-tty where -u is honoured.
    import shlex
    inner = "commix -u " + shlex.quote(target) + " --batch --skip-waf --os-cmd=id --level=2"
    cmd = (["script", "-qec", inner, "/dev/null"] if _which("script")
           else ["commix", "--url", target, "--batch", "--skip-waf", "--os-cmd=id"])
    rc, out, ms, err = _run(cmd, timeout)
    low = (out or "").lower()
    findings = []
    m = re.search(r"uid=\d+\(.*?\)\s+gid=\d+\([^)]*\)", out or "")   # output of `id`
    if m:
        findings.append({"title": "Remote code execution / shell access (commix)", "severity": "critical",
                         "owasp": "A03", "mitre": "T1059",
                         "evidence": "Ran `id` on the target → " + m.group(0),
                         "description": "commix exploited OS command injection and executed a command on the "
                                        "target, proving shell-level code execution is achievable.",
                         "remediation": "Never pass user input to a shell; use safe argument APIs; allow-list "
                                        "input; run with least privilege and no shell."})
    elif "is vulnerable" in low or ("injection point" in low and "command" in low):
        findings.append({"title": "OS command injection (commix)", "severity": "critical",
                         "owasp": "A03", "mitre": "T1059",
                         "evidence": _extract(out, "injection", 300) or "commix flagged a command-injection point",
                         "description": "commix confirmed an OS command injection point (not fully exploited).",
                         "remediation": "Avoid shell calls with user input; use safe APIs; allow-list input."})
    return _result("commix", cmd, rc, out, ms, findings, error=err)


# --------------------------------------------------------- gau (URL discovery)
def gau(target, options=None, timeout=180):
    if not _which("gau"):
        return _result("gau", "gau", available=False)
    host = _host_only(target).split(":")[0]
    cmd = ["gau", "--subs", "--threads", "5", host]
    rc, out, ms, err = _run(cmd, timeout)
    urls = [l.strip() for l in (out or "").splitlines() if l.strip().startswith("http")]
    return _result("gau", cmd, rc, out, ms, [], urls[:400], error=err)


# --------------------------------------------------------- arjun (param discovery)
def arjun(target, options=None, timeout=180):
    if not _which("arjun"):
        return _result("arjun", "arjun", available=False)
    cmd = ["arjun", "-u", target, "--stable"] + _cookie_args("arjun", options)
    rc, out, ms, err = _run(cmd, timeout)
    obs, seen = [], set()
    for line in (out or "").splitlines():
        m = re.search(r"parameters? found:\s*(.+)", line, re.I)
        if m:
            for p in re.split(r"[,\s]+", m.group(1).strip()):
                if p and p not in seen:
                    seen.add(p); obs.append("param: " + p)
    return _result("arjun", cmd, rc, out, ms, [], obs[:100], error=err)


# --------------------------------------------------------- testssl.sh (TLS vulns)
def testssl(target, options=None, timeout=300):
    bin_ = "testssl.sh" if _which("testssl.sh") else ("testssl" if _which("testssl") else None)
    if not bin_:
        return _result("testssl", "testssl.sh", available=False)
    host = _host_only(target)
    if ":" not in host:
        host += ":443"
    cmd = [bin_, "--color", "0", "--fast", "--quiet", "-U", host]
    rc, out, ms, err = _run(cmd, timeout)
    findings, obs = [], []
    VULNS = [("Heartbleed", "critical"), ("ROBOT", "high"), ("Ticketbleed", "high"), ("CCS", "high"),
             ("CRIME", "medium"), ("POODLE", "high"), ("BEAST", "low"), ("LUCKY13", "medium"),
             ("SWEET32", "medium"), ("FREAK", "high"), ("DROWN", "high"), ("LOGJAM", "medium")]
    for vuln, sev in VULNS:
        if re.search(rf"{vuln}.*(VULNERABLE|potentially vulnerable)", out or "", re.I):
            obs.append(f"{vuln}: vulnerable")
            findings.append({"title": f"TLS vulnerability: {vuln}", "severity": sev, "owasp": "A02",
                             "mitre": "T1040", "evidence": vuln,
                             "description": f"testssl.sh flagged the TLS stack vulnerable to {vuln}.",
                             "remediation": "Patch the TLS library; disable weak protocols/ciphers; use TLS 1.2+."})
    return _result("testssl", cmd, rc, out, ms, findings, obs, error=err)


# --------------------------------------------------------- wpscan (WordPress)
def wpscan(target, options=None, timeout=360):
    if not _which("wpscan"):
        return _result("wpscan", "wpscan", available=False)
    cmd = ["wpscan", "--url", target, "--no-banner", "--format", "json",
           "--random-user-agent", "--disable-tls-checks"] + _cookie_args("wpscan", options)
    rc, out, ms, err = _run(cmd, timeout)
    findings = []
    try:
        start = (out or "").find("{")
        data = json.loads(out[start:out.rindex("}") + 1]) if start >= 0 else {}

        def _addv(vulns, where):
            for vv in (vulns or []):
                findings.append({"title": f"WordPress {where}: {vv.get('title', 'vulnerability')}",
                                 "severity": "high", "owasp": "A06", "mitre": "T1595.002",
                                 "evidence": str(vv.get('title', ''))[:200],
                                 "description": "wpscan matched a known WordPress vulnerability.",
                                 "remediation": "Update WordPress core/plugins/themes to patched versions."})
        ver = data.get("version") or {}
        if isinstance(ver, dict):
            _addv(ver.get("vulnerabilities"), "core")
        for name, pl in (data.get("plugins", {}) or {}).items():
            if isinstance(pl, dict):
                _addv(pl.get("vulnerabilities"), f"plugin {name}")
        for name, th in (data.get("themes", {}) or {}).items():
            if isinstance(th, dict):
                _addv(th.get("vulnerabilities"), f"theme {name}")
    except (ValueError, KeyError):
        pass
    return _result("wpscan", cmd, rc, out, ms, findings[:30], error=err)


# ----------------------------------- gitsecrets (exposed .git → dump → secrets)
def gitsecrets(target, options=None, timeout=300):
    """If a .git directory is exposed, dump it (git-dumper) and scan the recovered
    repository for leaked secrets (trufflehog, else gitleaks)."""
    import tempfile, shutil as _sh, urllib.request
    base = target if "://" in target else "http://" + target
    giturl = base.rstrip("/") + "/.git/"
    cmd = ["git-dumper", giturl, "<tmp>", "+ trufflehog"]
    try:
        r = urllib.request.urlopen(urllib.request.Request(giturl + "config"), timeout=15)
        cfg = r.read(200)
        if b"[core]" not in cfg and b"repositoryformatversion" not in cfg:
            return _result("gitsecrets", cmd, 0, "(.git not exposed)", 0, [], ["/.git not accessible"])
    except Exception as e:
        return _result("gitsecrets", cmd, None, "", 0, [], [f"/.git not accessible: {e}"])
    if not _which("git-dumper"):
        return _result("gitsecrets", cmd, None, "", 0,
                       [{"title": "Exposed .git directory", "severity": "high", "owasp": "A05",
                         "mitre": "T1213", "evidence": giturl,
                         "description": "A .git directory is web-accessible; source and history can be recovered.",
                         "remediation": "Block access to .git; don't deploy VCS metadata."}],
                       ["git-dumper not installed — reported exposure only"])
    d = tempfile.mkdtemp(prefix="gitdump_")
    out = ""
    findings = [{"title": "Exposed .git directory", "severity": "high", "owasp": "A05",
                 "mitre": "T1213", "evidence": giturl,
                 "description": "A .git directory is web-accessible; source and history can be recovered.",
                 "remediation": "Block access to .git; don't deploy VCS metadata."}]
    try:
        _run(["git-dumper", giturl, d], min(timeout - 60, 180))
        if _which("trufflehog"):
            rc, out, ms, err = _run(["trufflehog", "filesystem", d, "--json", "--no-update"], 120)
            for line in (out or "").splitlines():
                try:
                    j = json.loads(line)
                    det = j.get("DetectorName") or j.get("DetectorType")
                    raw = str(j.get("Raw") or "")[:40]
                    if det:
                        findings.append({"title": f"Secret leaked in repo: {det}", "severity": "critical",
                                         "owasp": "A02", "mitre": "T1552",
                                         "evidence": f"{det}: {raw}…",
                                         "description": "A credential/secret was recovered from the exposed git repository.",
                                         "remediation": "Rotate the secret, purge it from git history, and block .git exposure."})
                except (ValueError, KeyError):
                    continue
        elif _which("gitleaks"):
            rc, out, ms, err = _run(["gitleaks", "detect", "--source", d, "--no-banner",
                                     "--report-format", "json", "--report-path", "/dev/stdout"], 120)
            try:
                for item in json.loads(out or "[]"):
                    findings.append({"title": f"Secret leaked in repo: {item.get('RuleID', 'secret')}",
                                     "severity": "critical", "owasp": "A02", "mitre": "T1552",
                                     "evidence": str(item.get('Secret', ''))[:40] + "…",
                                     "description": "A credential/secret was recovered from the exposed git repository.",
                                     "remediation": "Rotate the secret, purge it from git history, and block .git exposure."})
            except ValueError:
                pass
        return _result("gitsecrets", cmd, 0, out[:4000], 0, findings[:40], [f"dumped repo + scanned ({d})"])
    finally:
        _sh.rmtree(d, ignore_errors=True)


# tools whose binary name differs from the registry key
BINARIES = {"testssl": "testssl", "gitsecrets": "git-dumper"}

REGISTRY = {
    "nmap": nmap, "httpx": httpx, "nuclei": nuclei, "ffuf": ffuf,
    "whatweb": whatweb, "sqlmap": sqlmap,
    "subfinder": subfinder, "katana": katana, "wafw00f": wafw00f, "sslscan": sslscan,
    "nikto": nikto, "dalfox": dalfox, "commix": commix,
    "gau": gau, "arjun": arjun, "testssl": testssl, "wpscan": wpscan, "gitsecrets": gitsecrets,
}


def available_tools():
    return {name: _which(BINARIES.get(name, name)) for name in REGISTRY}
