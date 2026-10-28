"""Per-target intel / BOM extractor.

Derives a target's "bill of materials" from what the scans actually observed —
open ports & services, OS hints, web-server versions, technology components, and
discovered paths — by parsing the tool observations/outputs and findings stored
for that target's engagements. Derived on demand, so it always reflects every
run (it accumulates as more engagements are run), with no schema change.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

_PORT = re.compile(r"\b(\d{1,5})/(tcp|udp)\s+open\s*[—:\-]*\s*([A-Za-z0-9_.\-]+)?\s*(.*)")
_SERVER = re.compile(r"(?:^|\n)\s*server:\s*([^\n]+)", re.I)
_POWERED = re.compile(r"x-powered-by:\s*([^\n]+)", re.I)
_VER = re.compile(r"\b([A-Za-z][A-Za-z0-9.+\-]{1,30}?)[/ ]v?(\d+\.\d+(?:\.\d+)?)\b")
_WHATWEB = re.compile(r"\b([A-Z][A-Za-z0-9 .\-]{1,24}?)\[([^\]]+)\]")
_OS = re.compile(r"\(([^)]*(?:Ubuntu|Debian|Unix|Linux|CentOS|Red ?Hat|RHEL|Windows|"
                 r"Win32|Win64|FreeBSD|Fedora|Alpine|macOS|Darwin)[^)]*)\)", re.I)
_PATH = re.compile(r"Sensitive path exposed:\s*(\S+)")
_URL = re.compile(r"https?://[^\s'\"<>]+")

# version tokens that are not real components (incl. browser/UA noise echoed in responses)
_SKIP = {"http", "https", "tcp", "udp", "id", "v", "x", "uid", "gid", "api-version",
         "mozilla", "chrome", "safari", "firefox", "applewebkit", "khtml", "gecko",
         "edge", "edg", "opr", "opera", "version", "like gecko", "country", "using",
         "through", "do you want to use those y"}


def build_profile(endpoint: str, blobs: list[str], findings: list[dict]) -> dict:
    text = "\n".join(b for b in blobs if b)[:300000]

    ports = {}
    for m in _PORT.finditer(text):
        pid, proto = m.group(1), m.group(2)
        svc = (m.group(3) or "").strip()
        rest = (m.group(4) or "").strip()
        ports[(pid, proto)] = {"port": int(pid), "proto": proto,
                               "service": svc or "?", "product": rest[:60]}

    servers = {m.group(1).strip()[:90] for m in _SERVER.finditer(text)}
    powered = {m.group(1).strip()[:60] for m in _POWERED.finditer(text)}
    os_hints = {m.group(1).strip()[:48] for m in _OS.finditer(text)}

    comps: dict[str, dict] = {}
    for m in _WHATWEB.finditer(text):      # whatweb "Name[version]" / httpx tech
        name, val = m.group(1).strip(), m.group(2).strip()
        if len(name) > 1 and name.lower() not in _SKIP:
            comps[name.lower()] = {"name": name, "version": val[:30]}
    for m in _VER.finditer(text):          # generic "name/version" banners
        name, ver = m.group(1).strip(), m.group(2)
        low = name.lower()
        if low in _SKIP or name.isdigit():
            continue
        comps.setdefault(low, {"name": name, "version": ver})

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
        u = m.group(0).rstrip(".,);")
        try:
            pu = urlparse(u)
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
        "components": sorted(comps.values(), key=lambda c: c["name"].lower())[:60],
        "paths": sorted(p for p in paths if p)[:80],
        "endpoints": sorted(endpoints)[:20],
    }
