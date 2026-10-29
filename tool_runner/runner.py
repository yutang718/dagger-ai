"""Dagger-AI tool-runner — an isolated sidecar that executes pentest tools.

The main app never runs offensive binaries itself; it calls this service over
the internal Docker network. Keeping the toolchain in one container (a) isolates
it, (b) lets us enforce a safety gate on every invocation, and (c) mirrors the
sandbox model used by Strix/PentAGI.

Safety gate:
  * A shared token (TOOL_RUNNER_TOKEN) must match — only the app may drive it.
  * Link-local / cloud-metadata addresses are refused unless allow_internal is
    explicitly set (used only for the bundled lab target), so the platform can't
    be turned against its own host's metadata service.
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import socket
import subprocess
import threading
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

import tools

app = FastAPI(title="Dagger-AI tool-runner")
TOKEN = os.getenv("TOOL_RUNNER_TOKEN", "")


@app.on_event("startup")
def _refresh_nuclei_templates():
    """Pull the latest nuclei templates in the background on every start, so
    recent CVEs (e.g. new PHP CVEs) are detectable without rebuilding the image.
    Non-blocking: the API is available immediately while templates update."""
    if not shutil.which("nuclei"):
        return

    def _run():
        try:
            subprocess.run(["nuclei", "-update-templates", "-silent"],
                           timeout=600, capture_output=True)
        except Exception:
            pass

    threading.Thread(target=_run, daemon=True).start()


class RunIn(BaseModel):
    tool: str
    target: str
    options: dict = {}
    allow_internal: bool = False


def _host(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]


def _is_internal(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except (socket.gaierror, ValueError):
            return False
    return ip.is_link_local or ip.is_loopback or (ip.version == 4 and str(ip).startswith("169.254"))


@app.get("/health")
def health():
    return {"status": "ok", "role": "tool-runner"}


@app.get("/tools")
def list_tools(x_runner_token: str = Header(default="")):
    _auth(x_runner_token)
    return {"tools": tools.available_tools()}


@app.post("/run")
def run(body: RunIn, x_runner_token: str = Header(default="")):
    _auth(x_runner_token)
    fn = tools.REGISTRY.get(body.tool)
    if not fn:
        raise HTTPException(400, f"unknown tool: {body.tool}")
    host = _host(body.target)
    if _is_internal(host) and not body.allow_internal:
        raise HTTPException(403, "refusing link-local/metadata/loopback target (safety gate)")
    return fn(body.target, body.options)


def _auth(token: str):
    if TOKEN and token != TOKEN:
        raise HTTPException(401, "bad runner token")
