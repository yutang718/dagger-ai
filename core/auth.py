"""Minimal single-operator auth: a bearer token issued at login.

Dagger-AI is a self-hosted, single-tenant tool; this gate keeps the console
and API from being driven by anyone who can reach the port. Credentials come
from the environment (DAGGER_ADMIN_USER / DAGGER_ADMIN_PASSWORD).
"""
from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import Depends, Header, HTTPException

from . import config


def _sign(payload: str) -> str:
    sig = hmac.new(config.SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def issue_token(user: str) -> str:
    exp = int(time.time()) + config.TOKEN_HOURS * 3600
    return _sign(f"{user}:{exp}")


def verify(token: str) -> str | None:
    try:
        payload, sig = token.rsplit(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(_sign(payload).rsplit(".", 1)[1], sig):
        return None
    user, exp = payload.split(":")
    if int(exp) < time.time():
        return None
    return user


def login(user: str, password: str) -> str | None:
    if hmac.compare_digest(user, config.ADMIN_USER) and \
       hmac.compare_digest(password, config.ADMIN_PASSWORD):
        return issue_token(user)
    return None


def current_user(authorization: str = Header(default="")) -> str:
    token = authorization[7:] if authorization.lower().startswith("bearer ") else authorization
    user = verify(token)
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


auth_dep = Depends(current_user)
