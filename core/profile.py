"""Per-target intel / BOM extractor.

Derives a target's "bill of materials" from what the scans actually observed —
open ports & services, OS hints, web-server version, technology components, and
discovered paths — by parsing the tool observations/outputs and findings stored
for that target's engagements. Derived on demand, so it always reflects every
run (it accumulates as more engagements are run), with no schema change.

Extraction is deliberately conservative: only recognised technologies and
clean server/OS banners are surfaced, so the inventory stays readable and
meaningful rather than echoing every HTTP header, user-agent or metadata string.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# Open ports (nmap obs: "80/tcp open — http Apache httpd 2.2.8")
_PORT = re.compile(r"\b(\d{1,5})/(tcp|udp)\s+open\s*[—:\-]*\s*([A-Za-z0-9_.\-]+)?\s*(.*)")
# HTTP Server / X-Powered-By headers
_SERVER = re.compile(r"(?:^|\n)\s*server:\s*([^\n]+)", re.I)
_POWERED = re.compile(r"x-powered-by:\s*([^\n]+)", re.I)
# "name/version" or "name version" banners
_VER = re.compile(r"\b([A-Za-z][A-Za-z0-9.+\-]{1,24})[/ ]v?(\d+\.\d+(?:\.\d+)?)\b")
# whatweb / httpx "Name[version]" plugin style
_WHATWEB = re.compile(r"\b([A-Za-z][A-Za-z0-9 .\-]{1,24}?)\[([^\]]+)\]")
_OS = re.compile(r"\(([^)]*(?:Ubuntu|Debian|Unix|Linux|CentOS|Red ?Hat|RHEL|Windows|"
                 r"Win32|Win64|FreeBSD|Fedora|Alpine|macOS|Darwin)[^)]*)\)", re.I)
_PATH = re.compile(r"Sensitive path exposed:\s*(\S+)")
_URL = re.compile(r"https?://[^\s'\"<>]+")
_VERNUM = re.compile(r"\d+\.\d+(?:\.\d+)?")
# Systematic intel: subdomains, emails, WAF vendor, TLS notes, CVE ids.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{3,7}\b", re.I)
_WAF = re.compile(r"\b(cloudflare|akamai|incapsula|imperva|sucuri|f5|big-?ip|mod_?security|"
                  r"aws\s?waf|awswaf|barracuda|fortiweb|wordfence|wallarm|fastly|azure\s?waf)\b", re.I)
_HOSTNAME = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){1,}[a-z]{2,})\b", re.I)
# TLS vulnerability titles the testssl/sslscan wrappers emit.
_TLS_ISSUE = re.compile(r"TLS vulnerability:\s*([A-Za-z0-9 ()]+)")

# Technologies worth surfacing (lower-case). Matched exact or as a substring.
_KNOWN_TECH = {
    "nginx", "apache", "openssh", "php", "iis", "microsoft-iis", "tomcat", "jetty", "lighttpd",
    "openssl", "litespeed", "gunicorn", "uwsgi", "passenger", "haproxy", "varnish", "caddy",
    "wordpress", "drupal", "joomla", "typo3", "magento", "shopify", "ghost", "gitlab", "github",
    "jira", "confluence", "jenkins", "grafana", "kibana", "phpmyadmin", "sharepoint",
    "elasticsearch", "mysql", "mariadb", "postgresql", "redis", "mongodb",
    "node", "nodejs", "express", "django", "flask", "rails", "ruby", "python", "java",
    "asp.net", "aspnet", "dotnet", "laravel", "symfony", "spring", "tomcat",
    "jquery", "bootstrap", "react", "vue", "angular", "angularjs", "nextjs", "nuxt",
    "modernizr", "lodash", "backbone", "ember", "d3", "highcharts", "chart.js",
    "cloudflare", "akamai", "fastly", "incapsula", "sucuri",
}
# Names that are headers / user-agents / metadata, never components.
_NOISE = {
    "country", "ip", "title", "email", "script", "html5", "meta", "frame", "iframe",
    "opensearch", "open-search", "uncommonheaders", "httponly", "cookies", "cookie",
    "passwordfield", "password-field", "strict-transport-security", "x-frame-options",
    "x-xss-protection", "x-ua-compatible", "content-security-policy", "x-content-type-options",
    "redirectlocation", "cache-control", "referrer-policy", "permissions-policy", "pragma",
    "expires", "etag", "content-type", "content-length", "connection", "date", "vary", "age",
    "x-powered-by", "access-control", "report-to", "nel", "server-timing", "via", "via-proxy",
    "probably", "possibly", "using", "through", "do", "gem", "nmap", "whatweb", "masscan",
    "mozilla", "chrome", "safari", "applewebkit", "khtml", "gecko", "edge", "edg", "msie",
    "trident", "opera", "firefox", "opr", "version", "like", "windows", "macintosh", "x11",
    "set-cookie", "upgrade", "x-request-id", "x-runtime", "x-gitlab", "cf-ray", "boringssl",
}


# Product names safe to surface even without an adjacent version (rarely appear
# incidentally in response text).
_BARE_SCAN = {
    "nginx", "apache", "openssh", "php", "iis", "tomcat", "litespeed", "openssl", "caddy",
    "wordpress", "drupal", "joomla", "typo3", "magento", "shopify", "ghost", "gitlab", "github",
    "jira", "confluence", "jenkins", "grafana", "kibana", "phpmyadmin",
    "jquery", "bootstrap", "react", "vue", "angular", "angularjs", "modernizr",
    "cloudflare", "akamai", "varnish", "mysql", "postgresql", "mariadb", "redis", "mongodb",
}
# Nicely-cased display names.
_DISPLAY = {
    "gitlab": "GitLab", "github": "GitHub", "wordpress": "WordPress", "jquery": "jQuery",
    "postgresql": "PostgreSQL", "nginx": "nginx", "php": "PHP", "openssh": "OpenSSH", "iis": "IIS",
    "microsoft-iis": "Microsoft-IIS", "mysql": "MySQL", "mariadb": "MariaDB", "mongodb": "MongoDB",
    "nodejs": "Node.js", "node": "Node.js", "aspnet": "ASP.NET", "asp.net": "ASP.NET",
    "bootstrap": "Bootstrap", "react": "React", "vue": "Vue.js", "angular": "Angular",
    "angularjs": "AngularJS", "openssl": "OpenSSL", "tomcat": "Tomcat", "apache": "Apache",
    "cloudflare": "Cloudflare", "drupal": "Drupal", "joomla": "Joomla", "varnish": "Varnish",
}
_UA_OS = re.compile(r"(x11|rv:|macintosh|applewebkit|like gecko|wow64|win64; x64|trident|khtml)", re.I)


def _disp(k: str) -> str:
    return _DISPLAY.get(k, k[:1].upper() + k[1:])


def _is_tech(name: str) -> bool:
    low = name.lower()
    if low in _NOISE or low.isdigit() or len(low) < 2:
        return False
    return any(k == low or k in low for k in _KNOWN_TECH)


def _clean_server(val: str) -> str:
    # strip everything from the next "header:" onward (responses are header-joined)
    val = re.split(r"\s+[A-Za-z][A-Za-z0-9\-]+:\s", val.strip())[0].strip()
    return _sane_banner(val)[:60]


# Signatures of ASCII-art / figlet banners (e.g. theHarvester's logo) and other
# non-data noise that must never be surfaced as an asset value.
_ARTISH = re.compile(r"[|\\/_]{2,}|[╗╚═│┌┐└┘╔╝*]{2,}|\\[Vv_]|[/\\]\s*[/\\]")


def _sane_banner(s: str) -> str:
    """Return the string only if it reads like a real banner/token — not ASCII
    art, a box-drawing logo, or a symbol-dense fragment. Else ''."""
    s = (s or "").strip()
    if not s or "\n" in s or "\r" in s:
        return ""
    if _ARTISH.search(s):
        return ""
    letters = sum(c.isalnum() for c in s)
    symbols = sum((not c.isalnum()) and (not c.isspace()) for c in s)
    if letters < 2 or (symbols >= 4 and symbols >= letters):
        return ""
    return s


def build_profile(endpoint: str, blobs: list[str], findings: list[dict]) -> dict:
    text = "\n".join(b for b in blobs if b)[:300000]

    # Ports: parse LINE BY LINE so a match can never span a newline and pull the
    # next line's "443/tcp" in as this port's service (the old whole-text regex did
    # exactly that). Only genuine single-port nmap-style lines are accepted.
    ports = {}
    for line in text.splitlines():
        m = re.match(r"\s*(\d{1,5})/(tcp|udp)\s+open\b\s*(.*)", line)
        if not m:
            continue
        pid, proto, rest = m.group(1), m.group(2), (m.group(3) or "").strip()
        if int(pid) > 65535:
            continue
        if re.search(r"\d{1,5}/(tcp|udp)", rest):     # prose listing several ports → skip
            continue
        rest = re.sub(r"^[—:\-]+\s*", "", rest)
        toks = rest.split()
        svc, product = "?", ""
        if toks and re.fullmatch(r"[A-Za-z][A-Za-z0-9\-_+.]*", toks[0]):
            svc, product = toks[0], _clean_server(" ".join(toks[1:]))
        else:
            product = _clean_server(rest)
        ports[(pid, proto)] = {"port": int(pid), "proto": proto, "service": svc, "product": product}

    servers = {s for s in (_clean_server(m.group(1)) for m in _SERVER.finditer(text)) if s}
    powered = {p for p in (_clean_server(m.group(1)) for m in _POWERED.finditer(text)) if p}
    os_hints = {h for h in (_sane_banner(m.group(1).strip()[:48])
                            for m in _OS.finditer(text)) if h and not _UA_OS.search(h)}

    comps: dict[str, dict] = {}
    for m in _WHATWEB.finditer(text):      # whatweb "Name[version]"
        name = m.group(1).strip()
        if _is_tech(name):
            vm = _VERNUM.search(m.group(2))
            comps[name.lower()] = {"name": _disp(name.lower()), "version": vm.group(0) if vm else ""}
    for m in _VER.finditer(text):          # "name/version" banners
        name, ver = m.group(1).strip(), m.group(2)
        if _is_tech(name):
            comps.setdefault(name.lower(), {"name": _disp(name.lower()), "version": ver})
    # surface known products mentioned even without an adjacent version
    low_text = text.lower()
    for k in _BARE_SCAN:
        if k in comps:
            continue
        if re.search(r"(?<![a-z0-9])" + re.escape(k) + r"(?![a-z0-9])", low_text):
            vm = re.search(re.escape(k) + r"[ /]v?(\d+\.\d+(?:\.\d+)?)", low_text)
            comps[k] = {"name": _disp(k), "version": vm.group(1) if vm else ""}

    paths = set()
    for m in _PATH.finditer(text):
        p = m.group(1)
        try:
            paths.add(urlparse(p).path or p)
        except Exception:
            paths.add(p)
    for f in findings or []:
        if "path exposed" in (f.get("title", "").lower()):
            mm = _URL.search(f.get("title", "")) or _URL.search(f.get("evidence", "") or "")
            if mm:
                try:
                    paths.add(urlparse(mm.group(0)).path)
                except Exception:
                    pass

    endpoints = set()
    for m in _URL.finditer(text):
        try:
            pu = urlparse(m.group(0).rstrip(".,);"))
            if pu.netloc:
                endpoints.add(f"{pu.scheme}://{pu.netloc}")
        except Exception:
            pass

    # Systematic intel dimensions ----------------------------------------
    apex = _apex(urlparse(endpoint).hostname or endpoint or "")
    subdomains = set()
    if apex:
        for m in _HOSTNAME.finditer(text):
            h = m.group(1).lower().strip(".")
            if h.endswith("." + apex) and h != apex and not _VERNUM.fullmatch(h):
                subdomains.add(h)
    emails = {e.lower() for e in _EMAIL.findall(text)
              if not e.lower().endswith((".png", ".jpg", ".svg", ".gif", ".js", ".css"))}
    waf = sorted({_disp_waf(m.group(1)) for m in _WAF.finditer(text)})
    cves = sorted({c.upper() for c in _CVE.findall(text)})
    tls_issues = sorted({m.group(1).strip() for m in _TLS_ISSUE.finditer(text)})
    for f in findings or []:
        blob = (f.get("title", "") + " " + str(f.get("evidence", "")))
        cves.extend(c.upper() for c in _CVE.findall(blob))
    cves = sorted(set(cves))

    return {
        "endpoint": endpoint,
        "ports": sorted(ports.values(), key=lambda p: p["port"]),
        "web_servers": sorted(servers),
        "os": sorted(os_hints),
        "powered_by": sorted(powered),
        "components": sorted(comps.values(), key=lambda c: c["name"].lower())[:50],
        "paths": sorted(p for p in paths if p)[:80],
        "endpoints": sorted(endpoints)[:20],
        "subdomains": sorted(subdomains)[:60],
        "emails": sorted(emails)[:40],
        "waf": waf,
        "tls_issues": tls_issues,
        "cves": cves[:60],
    }


def _apex(host: str) -> str:
    """Best-effort registrable domain (last two labels) for subdomain grouping.
    Good enough to group scan-observed hostnames; not a public-suffix lookup."""
    host = (host or "").strip().strip(".").lower()
    if not host or re.fullmatch(r"[\d.]+", host):   # empty or bare IP
        return ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


_WAF_DISP = {"big-ip": "F5 BIG-IP", "bigip": "F5 BIG-IP", "mod_security": "ModSecurity",
             "modsecurity": "ModSecurity", "aws waf": "AWS WAF", "awswaf": "AWS WAF",
             "azure waf": "Azure WAF", "f5": "F5"}


def _disp_waf(v: str) -> str:
    low = v.lower().strip()
    return _WAF_DISP.get(low, low[:1].upper() + low[1:])


def profile_brief(prof: dict, lang: str = "en") -> str:
    """A compact, LLM-friendly intelligence briefing of what is already known
    about this target (across all prior scans). Empty string when nothing known."""
    if not prof:
        return ""
    lines = []
    def add(label, items, fmt=lambda x: x, cap=12):
        vals = [fmt(x) for x in (items or [])][:cap]
        if vals:
            lines.append(f"{label}: " + ", ".join(str(v) for v in vals))
    add("Open ports", prof.get("ports"), lambda p: f"{p['port']}/{p.get('proto','tcp')} "
        f"{p.get('service','')} {p.get('product','')}".strip())
    add("Web servers", prof.get("web_servers"))
    add("Powered-by", prof.get("powered_by"))
    add("OS hints", prof.get("os"))
    add("Tech components", prof.get("components"),
        lambda c: f"{c['name']}{(' ' + c['version']) if c.get('version') else ''}")
    add("WAF", prof.get("waf"))
    add("TLS issues", prof.get("tls_issues"))
    add("Subdomains", prof.get("subdomains"), cap=20)
    add("Emails", prof.get("emails"), cap=10)
    add("CVEs seen", prof.get("cves"), cap=20)
    add("Discovered paths", prof.get("paths"), cap=25)
    sev = prof.get("findings_by_sev") or {}
    if sev:
        lines.append("Confirmed so far: " + ", ".join(f"{n} {s}" for s, n in sev.items() if n))
    return "\n".join(lines)
