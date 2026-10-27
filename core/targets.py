"""Target adapters — the AI systems under test.

A target is anything that takes a prompt and returns text. Two kinds:
  * http_chat  — a generic OpenAI-compatible or custom JSON chat endpoint,
                 shaped by a body template + response path (promptfoo-style).
  * demo_agent — the bundled, isolated, intentionally-vulnerable agent used
                 for safe end-to-end exploit demonstrations.
"""
from __future__ import annotations

import json
import time

import httpx

from . import config


def _dig(obj, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if part == "":
            continue
        if isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


class TargetClient:
    def __init__(self, target):
        self.t = target

    def send(self, prompt: str, history: list[dict] | None = None) -> tuple[str, int]:
        """Return (response_text, latency_ms)."""
        start = time.time()
        try:
            text = self._send(prompt, history or [])
        except Exception as e:  # surface transport errors as target output
            text = f"[target error] {e}"
        return text, int((time.time() - start) * 1000)

    def _send(self, prompt: str, history: list[dict]) -> str:
        endpoint = self.t.endpoint or config.DEMO_TARGET_URL
        body_raw = (self.t.body_template or '{"message": "{{PROMPT}}"}')
        body_raw = body_raw.replace("{{PROMPT}}", json.dumps(prompt)[1:-1])
        try:
            body = json.loads(body_raw)
        except json.JSONDecodeError:
            body = {"message": prompt}
        if history and isinstance(body, dict):
            body.setdefault("history", history)
        headers = {"Content-Type": "application/json", **(self.t.headers or {})}
        with httpx.Client(timeout=config.REQUEST_TIMEOUT) as c:
            r = c.request(self.t.http_method or "POST", endpoint, headers=headers, json=body)
            r.raise_for_status()
            try:
                data = r.json()
            except ValueError:
                return r.text
        val = _dig(data, self.t.response_path or "reply")
        if val is None:
            return json.dumps(data)[:4000]
        return val if isinstance(val, str) else json.dumps(val)
