"""Auto-login — derive an authenticated session from credentials.

Given a campaign's login settings (URL + username/password), perform the login
once and return the session so the engine can inject it into web probes and the
cookie/header-capable tools. This lets scans reach pages *behind* the login,
instead of only the public landing page.

Three modes, covering the vast majority of username/password login pages:
  * form   — HTML form POST (application/x-www-form-urlencoded). Fetches the
             login page first to pick up any CSRF/anti-forgery hidden token and
             carry it into the POST. Session lives in Set-Cookie.
  * json   — JSON POST ({user_field: ..., pass_field: ...}). Session lives in
             Set-Cookie (and the response is scanned for a bearer token too).
  * bearer — JSON POST, then extract a token from the JSON response at
             `login_token_path` and send it as `Authorization: Bearer <token>`.

Pure-JS / SPA logins (login logic entirely client-side) are out of scope — they
need a headless browser; this module speaks HTTP directly.
"""
from __future__ import annotations

import json
import re

import httpx

from . import config

# Hidden-input names that typically carry a CSRF / anti-forgery token.
_CSRF_RE = re.compile(
    r'<input[^>]+name=["\']([^"\']*(?:csrf|token|authenticity|__requestverification)[^"\']*)["\']'
    r'[^>]*value=["\']([^"\']*)["\']',
    re.I,
)
# Also match value-before-name ordering.
_CSRF_RE2 = re.compile(
    r'<input[^>]+value=["\']([^"\']*)["\'][^>]*name=["\']'
    r'([^"\']*(?:csrf|token|authenticity|__requestverification)[^"\']*)["\']',
    re.I,
)


def _dig(obj, dotted: str):
    cur = obj
    for part in (dotted or "").split("."):
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


def _find_csrf(html: str):
    """Return (field, value) for a CSRF hidden input, or (None, None)."""
    if not html:
        return None, None
    m = _CSRF_RE.search(html)
    if m:
        return m.group(1), m.group(2)
    m = _CSRF_RE2.search(html)
    if m:
        return m.group(2), m.group(1)
    return None, None


def _jar_to_cookie(cookies) -> str:
    """Serialise an httpx cookie jar to a 'name=value; name=value' header."""
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def _scan_body_for_token(resp) -> str:
    """Best-effort bearer-token discovery in a login response body."""
    try:
        data = resp.json()
    except Exception:
        return ""
    for key in ("access_token", "accessToken", "token", "jwt", "id_token", "idToken"):
        v = _dig(data, key)
        if isinstance(v, str) and v:
            return v
    return ""


def derive_session(campaign, allow_internal: bool = False) -> dict:
    """Log in and return the captured session.

    Returns {"ok": bool, "cookies": str, "authz": str, "diag": str}, where
    `cookies` is a Cookie header value and `authz` is an Authorization header
    value (e.g. "Bearer x"). Either/both may be empty. Never raises — transport
    and parse errors are reported in `diag` with ok=False.
    """
    mode = (getattr(campaign, "login_mode", "") or "").strip().lower()
    url = (getattr(campaign, "login_url", "") or "").strip()
    user = getattr(campaign, "login_user", "") or ""
    pw = getattr(campaign, "login_password", "") or ""
    uf = (getattr(campaign, "login_user_field", "") or "username").strip()
    pf = (getattr(campaign, "login_pass_field", "") or "password").strip()
    if mode not in ("form", "json", "bearer"):
        return {"ok": False, "cookies": "", "authz": "", "diag": "auto-login disabled"}
    if not url or not user:
        return {"ok": False, "cookies": "", "authz": "",
                "diag": "login URL and username are required"}

    try:
        with httpx.Client(timeout=config.REQUEST_TIMEOUT, follow_redirects=True,
                          headers={"User-Agent": "Dagger-AI/1.0"}) as c:
            if mode == "form":
                data = {uf: user, pf: pw}
                try:
                    pre = c.get(url)
                    cf, cv = _find_csrf(pre.text)
                    if cf:
                        data[cf] = cv
                except httpx.HTTPError:
                    cf = None
                r = c.post(url, data=data)
                ck = _jar_to_cookie(c.cookies)
                ok = bool(ck) and r.status_code < 400
                diag = (f"form login → HTTP {r.status_code}, "
                        f"{len(c.cookies)} cookie(s){', CSRF carried' if cf else ''}")
                if not ck:
                    diag += " — no Set-Cookie returned"
                return {"ok": ok, "cookies": ck, "authz": "", "diag": diag}

            # json / bearer both POST JSON credentials
            r = c.post(url, json={uf: user, pf: pw})
            ck = _jar_to_cookie(c.cookies)
            if mode == "json":
                ok = (bool(ck) or r.status_code < 300) and r.status_code < 400
                diag = f"json login → HTTP {r.status_code}, {len(c.cookies)} cookie(s)"
                if not ck:
                    diag += " — no Set-Cookie (API may be token-based; try bearer mode)"
                return {"ok": bool(ck), "cookies": ck, "authz": "", "diag": diag}

            # bearer
            tok = _dig(_safe_json(r), getattr(campaign, "login_token_path", "") or "token")
            if not isinstance(tok, str) or not tok:
                tok = _scan_body_for_token(r)
            if r.status_code >= 400:
                return {"ok": False, "cookies": ck, "authz": "",
                        "diag": f"bearer login → HTTP {r.status_code}: {r.text[:160]}"}
            if not tok:
                return {"ok": False, "cookies": ck, "authz": "",
                        "diag": f"bearer login → HTTP {r.status_code} but no token at "
                                f"'{getattr(campaign, 'login_token_path', 'token')}'"}
            return {"ok": True, "cookies": ck, "authz": f"Bearer {tok}",
                    "diag": f"bearer login → HTTP {r.status_code}, token captured"}
    except httpx.HTTPError as e:
        return {"ok": False, "cookies": "", "authz": "", "diag": f"login transport error: {e}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "cookies": "", "authz": "", "diag": f"login error: {e}"}


def _safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return {}
