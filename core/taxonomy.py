"""Vulnerability taxonomy fused from the leading red-teaming projects.

Two OWASP families are supported side by side:
  * OWASP Top 10 for LLM Applications (2025)  -> owasp code LLM01..LLM10
  * OWASP Top 10 for Web Applications (2021)   -> owasp code A01..A10

MITRE mapping covers both domains:
  * MITRE ATLAS   (AI/ML adversary tactics)    -> AML.T####
  * MITRE ATT&CK  (enterprise techniques)      -> T####
Probes declare a single `mitre` id; lookups fall back across both maps.
"""
from __future__ import annotations

# OWASP Top 10 for LLM Applications 2025
OWASP_LLM_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

# OWASP Top 10 for Web Applications 2021
OWASP_WEB_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

OWASP_ALL = {**OWASP_LLM_2025, **OWASP_WEB_2021}

# MITRE ATLAS tactics (AI/ML).
ATLAS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0048": "External Harms",
}

# MITRE ATT&CK enterprise techniques relevant to web exploitation.
ATTACK = {
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1059.007": "JavaScript (XSS)",
    "T1110": "Brute Force",
    "T1212": "Exploitation for Credential Access",
    "T1083": "File and Directory Discovery",
    "T1595": "Active Scanning",
    "T1595.002": "Vulnerability Scanning",
    "T1552": "Unsecured Credentials",
}

# Unified MITRE lookup (ATLAS + ATT&CK).
MITRE = {**ATLAS, **ATTACK}


def mitre_label(mid: str) -> str:
    return MITRE.get(mid, mid)


def owasp_label(code: str) -> str:
    return OWASP_ALL.get(code, code)


# Ordered worst -> best for sorting and colour scales in the UI.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_SCORE = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_COLOR = {
    "critical": "#e5484d",
    "high": "#f76808",
    "medium": "#f5a623",
    "low": "#3b82f6",
    "info": "#8b8d98",
}


def worst(sevs):
    """Return the most severe level from an iterable, or 'info' if empty."""
    best = "info"
    for s in sevs:
        if SEVERITY_SCORE.get(s, 0) > SEVERITY_SCORE.get(best, 0):
            best = s
    return best
