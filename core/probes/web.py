"""Web-application probes — OWASP Top 10 (2021), MITRE ATT&CK mapped.

DAST-style: each probe sends crafted HTTP requests to an authorized web-app
target and inspects the responses for a vulnerability signature, recording the
request/response as attack steps and keeping concrete evidence (PoC-validated,
Strix-style). Payloads are benign demonstrators (`id`, cloud-metadata read,
reflected marker) — assessment inputs, not destructive exploits.
"""
from __future__ import annotations

import re
import time
from urllib.parse import quote, urljoin

from .base import JudgeResult, WebProbe, register
from ..records import AttemptRec, StepRec

MARK = "DAGGER-XSS-4417"


def _req(http, method, url, note, **kw):
    """Perform a request; return (step, resp_or_None)."""
    start = time.time()
    line = f"{method} {url}"
    if kw.get("data"):
        line += f"\nbody: {kw['data']}"
    try:
        r = http.request(method, url, **kw)
        ms = int((time.time() - start) * 1000)
        body = r.text or ""
        excerpt = body[:900]
        hdr = " ".join(f"{k}: {v}" for k, v in r.headers.items())
        resp = f"HTTP {r.status_code}\n{hdr[:300]}\n\n{excerpt}"
        return StepRec("request", line, resp, note, ms), r
    except Exception as e:
        ms = int((time.time() - start) * 1000)
        return StepRec("request", line, f"[request error] {e}", note, ms), None


@register
class SQLInjection(WebProbe):
    id = "sql_injection"
    name = "SQL Injection"
    owasp = "A03"
    mitre = "T1190"
    severity = "critical"
    objective = "Confirm an injectable SQL parameter (error-based or boolean)."
    description = "Tests whether user input reaches a SQL query unparameterised."
    remediation = ("Use parameterised queries / prepared statements, validate input, and never "
                   "concatenate user data into SQL. Return generic error pages.")

    def execute(self, base_url, http):
        attempts = []
        baseline_url = urljoin(base_url, "/products?id=1")
        s0, r0 = _req(http, "GET", baseline_url, "Baseline request with benign id=1")
        base_len = len(r0.text) if r0 is not None else 0

        err_url = urljoin(base_url, "/products?id=" + quote("1'"))
        s1, r1 = _req(http, "GET", err_url, "Inject a single quote to trigger a SQL error")
        err_text = (r1.text if r1 is not None else "")
        sql_err = bool(re.search(r"(sql|sqlite|syntax error|unrecognized token|near \")",
                                 err_text, re.I))

        bool_url = urljoin(base_url, "/products?id=" + quote("1' OR '1'='1"))
        s2, r2 = _req(http, "GET", bool_url, "Boolean payload: 1' OR '1'='1 (dump all rows)")
        bool_len = len(r2.text) if r2 is not None else 0

        success = sql_err or (bool_len > base_len * 1.3 and bool_len > 0)
        if sql_err:
            ev = re.search(r".{0,80}(sql|sqlite|syntax|unrecognized token).{0,120}", err_text, re.I)
            evidence = ev.group(0).strip() if ev else err_text[:200]
            rationale = "Single-quote injection produced a database error — parameter is injectable."
        elif success:
            evidence = f"Boolean payload returned {bool_len} bytes vs {base_len} baseline (more rows)."
            rationale = "OR 1=1 payload changed result-set size — classic boolean SQLi."
        else:
            evidence, rationale = "", "No SQL error or boolean difference observed."
        attempts.append(AttemptRec("error+boolean-sqli", self.objective, [s0, s1, s2],
                                   success, 1.0 if success else 0.0, evidence, rationale))
        return attempts


@register
class CommandInjection(WebProbe):
    id = "command_injection"
    name = "OS Command Injection"
    owasp = "A03"
    mitre = "T1059"
    severity = "critical"
    objective = "Execute an OS command through an injectable parameter (proof: `id`)."
    description = "Tests whether user input reaches a shell command."
    remediation = ("Avoid shell calls with user input; use safe APIs / arg arrays, allow-list input, "
                   "and drop shell privileges.")

    def execute(self, base_url, http):
        payload = "127.0.0.1; id"
        url = urljoin(base_url, "/ping?host=" + quote(payload))
        s, r = _req(http, "GET", url, "Append `; id` to the host parameter (command chaining)")
        text = r.text if r is not None else ""
        m = re.search(r"uid=\d+\(.*?\)\s+gid=\d+\([^)]*\)", text)
        success = bool(m)
        evidence = m.group(0) if m else ""
        rationale = ("Command output (`id`) returned in the response — remote command execution."
                     if success else "No command output observed.")
        return [AttemptRec("shell-metacharacter", self.objective, [s],
                           success, 1.0 if success else 0.0, evidence, rationale)]


@register
class ReflectedXSS(WebProbe):
    id = "reflected_xss"
    name = "Reflected Cross-Site Scripting"
    owasp = "A03"
    mitre = "T1059.007"
    severity = "high"
    objective = "Get an unescaped script payload reflected into the response."
    description = "Tests whether user input is reflected into HTML without encoding."
    remediation = ("Context-aware output encoding, a strict Content-Security-Policy, and framework "
                   "auto-escaping.")

    def execute(self, base_url, http):
        payload = f"<script>{MARK}</script>"
        url = urljoin(base_url, "/search?q=" + quote(payload))
        s, r = _req(http, "GET", url, "Submit a <script> payload in the search field")
        text = r.text if r is not None else ""
        success = payload in text
        evidence = payload if success else ""
        rationale = ("Script payload reflected verbatim (unencoded) — reflected XSS."
                     if success else "Payload was encoded or not reflected.")
        return [AttemptRec("reflected-marker", self.objective, [s],
                           success, 0.85 if success else 0.0, evidence, rationale)]


@register
class BrokenAccessControl(WebProbe):
    id = "broken_access_control"
    name = "Broken Access Control (IDOR)"
    owasp = "A01"
    mitre = "T1190"
    severity = "high"
    objective = "Access another user's record by changing an id, without authorization."
    description = "Tests for insecure direct object references / missing authorization checks."
    remediation = ("Enforce per-object authorization server-side on every request; use unguessable "
                   "references and deny by default.")

    def execute(self, base_url, http):
        s1, r1 = _req(http, "GET", urljoin(base_url, "/account?id=1"),
                      "Request account id=1 with no authentication")
        s2, r2 = _req(http, "GET", urljoin(base_url, "/account?id=2"),
                      "Enumerate to account id=2 (another user)")
        t1 = r1.text if r1 is not None else ""
        t2 = r2.text if r2 is not None else ""
        emails = re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", t1 + t2)
        ok1 = (r1 is not None and r1.status_code == 200 and "@" in t1)
        ok2 = (r2 is not None and r2.status_code == 200 and "@" in t2)
        success = ok1 and ok2 and t1 != t2
        evidence = ", ".join(sorted(set(emails))[:4]) if success else ""
        rationale = ("Distinct users' PII returned unauthenticated by id enumeration — IDOR."
                     if success else "Access appears controlled.")
        return [AttemptRec("idor-enumeration", self.objective, [s1, s2],
                           success, 0.9 if success else 0.0, evidence, rationale)]


@register
class SSRF(WebProbe):
    id = "ssrf"
    name = "Server-Side Request Forgery"
    owasp = "A10"
    mitre = "T1190"
    severity = "critical"
    objective = "Make the server fetch an internal URL (cloud-metadata style)."
    description = "Tests whether a URL parameter lets the server request arbitrary internal hosts."
    remediation = ("Allow-list outbound hosts, block link-local/metadata ranges, and resolve+pin "
                   "destinations; never fetch user-supplied URLs directly.")

    def execute(self, base_url, http):
        internal = "http://127.0.0.1:9010/latest/meta-data/credentials"
        url = urljoin(base_url, "/fetch?url=" + quote(internal))
        s, r = _req(http, "GET", url, "Ask the server to fetch an internal metadata URL")
        text = r.text if r is not None else ""
        m = re.search(r"(DAGGER-METADATA\{[^}]+\}|AccessKeyId|SecretAccessKey)", text)
        success = bool(m)
        evidence = (re.search(r"DAGGER-METADATA\{[^}]+\}", text) or [None])[0] if success else ""
        evidence = evidence.group(0) if hasattr(evidence, "group") else (m.group(0) if m else "")
        rationale = ("Server retrieved internal-only metadata on our behalf — SSRF confirmed."
                     if success else "Server did not fetch the internal resource.")
        return [AttemptRec("internal-metadata-fetch", self.objective, [s],
                           success, 1.0 if success else 0.0, evidence, rationale)]


@register
class SecurityMisconfiguration(WebProbe):
    id = "security_misconfiguration"
    name = "Security Misconfiguration"
    owasp = "A05"
    mitre = "T1595"
    severity = "medium"
    objective = "Detect missing security headers and verbose error leakage."
    description = "Checks for absent hardening headers and stack/SQL error disclosure."
    remediation = ("Set CSP, X-Frame-Options, X-Content-Type-Options and HSTS; return generic "
                   "errors; disable directory listing and debug modes.")

    WANT = ["content-security-policy", "x-frame-options", "x-content-type-options",
            "strict-transport-security"]

    def execute(self, base_url, http):
        s, r = _req(http, "GET", urljoin(base_url, "/"), "Inspect response headers on the home page")
        missing = []
        if r is not None:
            have = {k.lower() for k in r.headers}
            missing = [h for h in self.WANT if h not in have]
        s2, r2 = _req(http, "GET", urljoin(base_url, "/products?id=" + quote("'")),
                      "Trigger an error to check for verbose stack/SQL disclosure")
        verbose = bool(r2 is not None and re.search(r"(traceback|sqlite|at line \d|stack)",
                                                    r2.text, re.I))
        success = len(missing) >= 2 or verbose
        bits = []
        if missing:
            bits.append("missing headers: " + ", ".join(missing))
        if verbose:
            bits.append("verbose error disclosure")
        evidence = "; ".join(bits)
        rationale = ("Hardening gaps found." if success else "Baseline hardening present.")
        return [AttemptRec("header+error-audit", self.objective, [s, s2],
                           success, 0.6 if success else 0.0, evidence, rationale)]


@register
class VulnerableComponents(WebProbe):
    id = "vulnerable_components"
    name = "Vulnerable & Outdated Components"
    owasp = "A06"
    mitre = "T1595.002"
    severity = "low"
    objective = "Fingerprint server/software versions disclosed in responses."
    description = "Detects version banners that aid targeting of known-vulnerable components."
    remediation = "Suppress version banners, inventory dependencies, and patch on a schedule."

    def execute(self, base_url, http):
        s, r = _req(http, "GET", urljoin(base_url, "/"), "Read the Server banner / version headers")
        server = ""
        if r is not None:
            server = r.headers.get("server", "") + " " + r.headers.get("x-powered-by", "")
        success = bool(re.search(r"\d+\.\d+", server))
        evidence = server.strip() if success else ""
        rationale = ("Version banner disclosed — eases targeting of known CVEs."
                     if success else "No version banner disclosed.")
        return [AttemptRec("banner-grab", self.objective, [s],
                           success, 0.4 if success else 0.0, evidence, rationale)]


@register
class AuthFailures(WebProbe):
    id = "auth_failures"
    name = "Identification & Authentication Failures"
    owasp = "A07"
    mitre = "T1110"
    severity = "high"
    objective = "Log in with a default/weak credential pair."
    description = "Checks a small default-credential list against the login endpoint."
    remediation = ("Forbid default/weak passwords, enforce MFA, add rate limiting and lockout, and "
                   "monitor for credential stuffing.")

    CREDS = [("admin", "admin"), ("admin", "password"), ("admin", "123456")]

    def execute(self, base_url, http):
        steps, hit = [], None
        for user, pw in self.CREDS:
            s, r = _req(http, "POST", urljoin(base_url, "/login"),
                        f"Try default credentials {user}:{pw}", json={"user": user, "password": pw})
            steps.append(s)
            text = (r.text if r is not None else "").lower()
            if r is not None and r.status_code == 200 and re.search(r'(token|success|welcome|"ok"\s*:\s*true)', text):
                hit = (user, pw)
                break
        success = hit is not None
        evidence = f"default credentials accepted: {hit[0]}:{hit[1]}" if hit else ""
        rationale = ("A default credential pair authenticated successfully."
                     if success else "Default credentials rejected.")
        return [AttemptRec("default-credentials", self.objective, steps,
                           success, 0.85 if success else 0.0, evidence, rationale)]
