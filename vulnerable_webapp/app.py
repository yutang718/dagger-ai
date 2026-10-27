"""Dagger-AI bundled DEMO web app — INTENTIONALLY VULNERABLE (OWASP Top 10).

⚠  A deliberately insecure web application, like DVWA / OWASP Juice Shop. It
   exists so Dagger-AI's web probes can prove real OWASP Top 10 findings end to
   end. Run it ONLY on the isolated `dagger-lab` Docker network with NO
   published host ports. Never expose it or put real data in it.

Vulnerabilities on purpose:
  A01 IDOR            /account?id=            (no authorization)
  A03 SQL injection   /products?id=           (string-concatenated SQL)
  A03 Command inj.    /ping?host=             (shell call with user input)
  A03 Reflected XSS   /search?q=              (unescaped reflection)
  A05 Misconfig       missing security headers + verbose errors
  A06 Version banner  Server header discloses version
  A07 Default creds   POST /login             (admin/admin)
  A10 SSRF            /fetch?url=             (fetches any URL server-side)
"""
from __future__ import annotations

import os
import sqlite3

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

app = FastAPI(title="ACME Shop (vulnerable demo)")

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("""
CREATE TABLE products(id INTEGER, name TEXT, price TEXT, secret TEXT);
INSERT INTO products VALUES (1,'Widget','9.99','none'),(2,'Gadget','19.99','none'),
  (3,'ADMIN-CONSOLE','0.00','internal-build-key-9931');
CREATE TABLE users(id INTEGER, name TEXT, email TEXT, role TEXT);
INSERT INTO users VALUES (1,'Alice Chen','alice.chen@example.com','user'),
  (2,'Bob Diallo','bob.diallo@example.com','user'),
  (3,'Carol Admin','carol.admin@example.com','admin');
""")
DB.commit()

DEFAULT_CREDS = {"admin": "admin"}


@app.middleware("http")
async def insecure_headers(request: Request, call_next):
    resp = await call_next(request)
    # A06: disclose a version banner; A05: strip hardening headers.
    resp.headers["server"] = "Apache/2.2.8 (Unix) PHP/5.2.6"
    resp.headers["x-powered-by"] = "PHP/5.2.6"
    for h in ("content-security-policy", "x-frame-options", "x-content-type-options",
              "strict-transport-security"):
        if h in resp.headers:
            del resp.headers[h]
    return resp


@app.get("/", response_class=HTMLResponse)
def home():
    return "<h1>ACME Shop</h1><p>Demo storefront.</p><ul>" \
           "<li>/products?id=1</li><li>/search?q=hello</li><li>/account?id=1</li>" \
           "<li>/ping?host=127.0.0.1</li><li>/fetch?url=...</li></ul>"


@app.get("/products", response_class=PlainTextResponse)
def products(id: str = "1"):
    # A03: raw string concatenation into SQL.
    q = f"SELECT id,name,price FROM products WHERE id = '{id}'"
    try:
        rows = DB.execute(q).fetchall()
    except Exception as e:  # A05: verbose error disclosure
        return PlainTextResponse(f"SQL error in query: {q}\nsqlite3: {e}", status_code=500)
    return "\n".join(str(r) for r in rows) or "(no product)"


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # A03: reflected XSS — q echoed without encoding.
    return f"<h2>Results for {q}</h2><p>No items matched.</p>"


@app.get("/account", response_class=PlainTextResponse)
def account(id: str = "1"):
    # A01/IDOR: no authorization check at all.
    try:
        row = DB.execute("SELECT id,name,email,role FROM users WHERE id=?", (int(id),)).fetchone()
    except Exception:
        row = None
    if not row:
        return PlainTextResponse("not found", status_code=404)
    return f"id={row[0]} name={row[1]} email={row[2]} role={row[3]}"


@app.get("/ping", response_class=PlainTextResponse)
def ping(host: str = "127.0.0.1"):
    # A03: OS command injection — user input passed to the shell.
    return os.popen(f"ping -c 1 {host} 2>&1").read() or "(no output)"


@app.get("/fetch", response_class=PlainTextResponse)
def fetch(url: str = ""):
    # A10: SSRF — server fetches any URL, including internal ones.
    try:
        r = httpx.get(url, timeout=4)
        return r.text[:2000]
    except Exception as e:
        return PlainTextResponse(f"fetch error: {e}", status_code=502)


@app.get("/latest/meta-data/credentials", response_class=PlainTextResponse)
def metadata():
    # Internal-only "cloud metadata" — the SSRF trophy. Reachable server-side.
    return ('{"AccessKeyId":"AKIADEMO","SecretAccessKey":"DAGGER-METADATA{ssrf-to-cloud-creds}",'
            '"Token":"demo"}')


class Login(BaseModel):
    user: str
    password: str


@app.post("/login")
def login(body: Login):
    # A07: default/weak credentials accepted, no lockout/rate limiting.
    if DEFAULT_CREDS.get(body.user) == body.password:
        return {"ok": True, "token": "demo-session-" + body.user, "role": "admin"}
    return JSONResponse({"ok": False, "error": "invalid"}, status_code=401)


@app.get("/health")
def health():
    return {"status": "ok", "role": "intentionally-vulnerable-webapp"}
