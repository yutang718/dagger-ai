"""Client for the tool-runner sidecar.

Thin HTTP wrapper the AI operator uses to execute pentest tools in the isolated
tools container. Returns the runner's normalised result dict, or a graceful
error result when the runner or a tool is unavailable.
"""
from __future__ import annotations

import httpx

from . import config


def _headers():
    h = {"Content-Type": "application/json"}
    if config.TOOL_RUNNER_TOKEN:
        h["X-Runner-Token"] = config.TOOL_RUNNER_TOKEN
    return h


def available() -> dict:
    try:
        with httpx.Client(timeout=15) as c:
            r = c.get(f"{config.TOOL_RUNNER_URL}/tools", headers=_headers())
            r.raise_for_status()
            return r.json().get("tools", {})
    except Exception:
        return {}


def run(tool: str, target: str, options: dict | None = None, allow_internal: bool = False) -> dict:
    payload = {"tool": tool, "target": target, "options": options or {},
               "allow_internal": allow_internal}
    try:
        with httpx.Client(timeout=config.REQUEST_TIMEOUT + 600) as c:
            r = c.post(f"{config.TOOL_RUNNER_URL}/run", headers=_headers(), json=payload)
            if r.status_code >= 400:
                return {"tool": tool, "available": False, "command": tool,
                        "stdout": "", "findings": [], "observations": [],
                        "error": f"runner {r.status_code}: {r.text[:200]}", "duration_ms": 0}
            return r.json()
    except Exception as e:  # noqa: BLE001
        return {"tool": tool, "available": False, "command": tool, "stdout": "",
                "findings": [], "observations": [], "error": f"runner unreachable: {e}",
                "duration_ms": 0}
