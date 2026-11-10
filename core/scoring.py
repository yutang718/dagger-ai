"""Risk scoring for findings: CVSS v3.1 base score (+ vector) and a CWE id.

Findings arrive from many sources. Some already carry real scores — nuclei
templates ship ``cvss-score`` / ``cvss-metrics`` / ``cwe-id``, ZAP ships a CWE —
and those are always preferred. For everything else (built-in probes, nikto,
banners) we derive a representative CVSS band from the qualitative severity and
map the issue class to a CWE from its OWASP category and title. This turns the
report from "high / medium" labels into a quantifiable, sortable risk picture.
"""
from __future__ import annotations

import re

# Representative CVSS v3.1 base scores per qualitative band (used only when the
# tool did not provide a real score). Mid-points of each severity range.
_CVSS_BAND = {"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}

# CVSS v3.1 → qualitative severity (NVD thresholds).
def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


# OWASP Top-10 category → a representative CWE for the class.
_OWASP_CWE = {
    "A01": "CWE-284", "A02": "CWE-327", "A03": "CWE-74", "A04": "CWE-657",
    "A05": "CWE-16", "A06": "CWE-1035", "A07": "CWE-287", "A08": "CWE-345",
    "A09": "CWE-778", "A10": "CWE-918",
}

# Title/keyword → CWE (more specific than the OWASP class; checked first).
_TITLE_CWE = [
    (r"\bsql\b|sqli|sql injection", "CWE-89"),
    (r"xss|cross[- ]site script", "CWE-79"),
    (r"command inj|\brce\b|remote code|os command", "CWE-78"),
    (r"code injection|template injection|ssti", "CWE-94"),
    (r"path travers|directory travers|\blfi\b|\brfi\b|file inclusion", "CWE-22"),
    (r"\bssrf\b|server[- ]side request", "CWE-918"),
    (r"open redirect", "CWE-601"),
    (r"\bcsrf\b|cross[- ]site request", "CWE-352"),
    (r"clickjack|x-frame", "CWE-1021"),
    (r"\bcors\b", "CWE-942"),
    (r"secret|api[ _-]?key|credential|token|\.git|password", "CWE-798"),
    (r"idor|insecure direct object|access control|unauthor", "CWE-284"),
    (r"deserial", "CWE-502"),
    (r"xxe|xml external", "CWE-611"),
    (r"weak cipher|tls|ssl|certificate|heartbleed|poodle|crypto", "CWE-327"),
    (r"default cred|weak password|brute", "CWE-521"),
    (r"info(rmation)? disclos|exposure|verbose error|stack trace", "CWE-200"),
    (r"misconfig|directory listing|debug", "CWE-16"),
    (r"outdated|vulnerable (component|version|library|dependency)", "CWE-1035"),
]


def _first_float(s) -> float | None:
    m = re.search(r"\d+(?:\.\d+)?", str(s or ""))
    return float(m.group(0)) if m else None


def cwe_for(owasp: str, title: str, evidence: str = "") -> str:
    blob = f"{title} {evidence}".lower()
    for pat, cwe in _TITLE_CWE:
        if re.search(pat, blob):
            return cwe
    return _OWASP_CWE.get((owasp or "")[:3].upper(), "")


def enrich_finding(f: dict) -> dict:
    """Fill cvss / cvss_vector / cwe on a finding dict in place, preferring any
    real tool-supplied values and falling back to severity band + CWE mapping.
    Returns the same dict for convenience."""
    sev = (f.get("severity") or "info").lower()
    # CVSS: real score from the tool if present, else the band for the severity.
    cvss = _first_float(f.get("cvss") or f.get("cvss_score"))
    if not cvss:   # None or 0 (unscored / pre-scoring rows) → band for the severity
        cvss = _CVSS_BAND.get(sev, 0.0)
    f["cvss"] = round(float(cvss), 1)
    vec = str(f.get("cvss_vector") or f.get("cvss_metrics") or "").strip()
    f["cvss_vector"] = vec if vec.upper().startswith("CVSS:") else ""
    # CWE: real id from the tool if present, else mapped from class/title.
    cwe = str(f.get("cwe") or "").strip()
    if cwe:
        cwe = cwe if cwe.upper().startswith("CWE-") else f"CWE-{re.sub(r'[^0-9]', '', cwe)}"
        if cwe == "CWE-":
            cwe = ""
    if not cwe:
        cwe = cwe_for(f.get("owasp", ""), f.get("title", ""), str(f.get("evidence", "")))
    f["cwe"] = cwe
    return f
