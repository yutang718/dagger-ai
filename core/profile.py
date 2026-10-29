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
    return val[:60]


def build_profile(endpoint: str, blobs: list[str], findings: list[dict]) -> dict:
    text = "\n".join(b for b in blobs if b)[:300000]

    ports = {}
    for m in _PORT.finditer(text):
        pid, proto = m.group(1), m.group(2)
        svc = (m.group(3) or "").strip()
        rest = (m.group(4) or "").strip()
        ports[(pid, proto)] = {"port": int(pid), "proto": proto,
                               "service": svc or "?", "product": _clean_server(rest)}

    servers = {s for s in (_clean_server(m.group(1)) for m in _SERVER.finditer(text)) if s}
    powered = {p for p in (_clean_server(m.group(1)) for m in _POWERED.finditer(text)) if p}
    os_hints = {h for h in (m.group(1).strip()[:48] for m in _OS.finditer(text)) if not _UA_OS.search(h)}

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

    return {
        "endpoint": endpoint,
        "ports": sorted(ports.values(), key=lambda p: p["port"]),
        "web_servers": sorted(servers),
        "os": sorted(os_hints),
        "powered_by": sorted(powered),
        "components": sorted(comps.values(), key=lambda c: c["name"].lower())[:50],
        "paths": sorted(p for p in paths if p)[:80],
        "endpoints": sorted(endpoints)[:20],
    }
