"""Vulnerability taxonomy fused from the leading AI red-teaming projects.

- OWASP Top 10 for LLM Applications (2025)   -> owasp
- MITRE ATLAS tactic mapping                  -> atlas
- Severity model (DeepTeam / promptfoo style) -> severity

Each probe (attack module) declares which taxonomy entries it exercises so
findings can be grouped, scored and visualised consistently.
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

# MITRE ATLAS tactics most relevant to LLM red teaming.
ATLAS = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0053": "LLM Plugin Compromise",
    "AML.T0048": "External Harms",
}

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
