# 🗡️ Dagger-AI

**An AI-driven penetration-testing platform that orchestrates the world's best
security tools.** Point it at a host, a web app, an API, or an LLM system **you
own or are permitted to assess**, and an AI operator plans and runs a staged
engagement — driving real tools, interpreting their output, chaining findings,
and showing every step with PoC evidence in a visual console.

**Three attack surfaces, one platform:**

- **🎯 Host / web app — AI pentest** *(headline)*: the AI operator runs a real
  toolchain — **nmap · httpx · nuclei · ffuf · whatweb · sqlmap** plus built-in
  OWASP web probes — across recon → fingerprint → discovery → vuln-scan →
  exploit. Findings map to *OWASP Top 10 + MITRE ATT&CK* with CVE references.
- **🌐 Web apps**: built-in DAST probes — SQLi, command injection, SSRF, XSS,
  IDOR, default creds, misconfig, version disclosure · *OWASP 2021 + ATT&CK*.
- **🤖 AI / LLM**: prompt injection, jailbreaks, system-prompt leakage, data
  exfiltration, agent tool-abuse (→ shell) · *OWASP LLM Top 10 + MITRE ATLAS*.

Self-hosted, one command. Works with **no API key** (offline operator +
built-in probes); plug in an LLM to make the operator plan adaptively.

> ⚖️ **Authorized use only.** Dagger-AI is a defensive security tool. Only run
> campaigns against AI systems you own or have explicit written permission to
> test. Every target must carry an authorization note before a run can start.

---

## Why Dagger-AI — and what it borrows from the field

Dagger-AI fuses the strongest ideas from today's leading AI/offensive-security
projects into one simple, visual, self-hosted tool:

| Project | What we took |
|---|---|
| **Garak** (NVIDIA) | Probe/plugin scanner model — broad, zero-config sweeps |
| **PyRIT** (Microsoft) | LLM *attacker* + multi-turn orchestrators (Crescendo, adaptive refinement) |
| **promptfoo** | OWASP LLM Top 10 (2025) + MITRE ATLAS mapping, config-driven targets |
| **DeepTeam** | Vulnerability taxonomy spanning single- and multi-turn attacks |
| **PentAGI** | Multi-agent design (attacker + judge), self-hosted Docker, step observability |
| **Strix** | **PoC-validated findings** (evidence required), live agent/attack graph, local-first viewer, sandboxed exploit target, explicit authorization gate |

What makes it easy: a **graphical console** (not a CLI), an **offline engine**
so it runs with no keys, and a **bundled, isolated vulnerable target** so you
can watch a full exploit chain — up to **command execution / shell** — safely.

---

## Features

- **AI pentest engagements (host targets)** — an AI *operator* plans and runs a
  staged assessment, driving best-of-breed tools through an isolated sidecar and
  distilling PoC-validated findings:

  | Phase | Tool(s) | Purpose |
  |---|---|---|
  | Recon | **nmap** | ports & service/version detection |
  | Fingerprint | **httpx**, **whatweb** | tech stack, titles, banners |
  | Discovery | **ffuf** | hidden paths / content (sensitive files) |
  | Vuln scan | **nuclei** | templated CVE/misconfig detection |
  | Exploit | **sqlmap**, built-in web probes | validate SQLi + OWASP issues |

  The operator writes the plan + executive summary (LLM when configured, else a
  deterministic playbook), runs within a step budget, and degrades gracefully if
  a tool isn't installed. Tools execute in an isolated Kali sidecar, never in the
  app.

- **Structured attack campaigns** — pick modules/probes against one target.
- **Two built-in probe families** (also usable standalone):

  **AI / LLM probes** — OWASP LLM Top 10 (2025) + MITRE ATLAS:
  - `prompt_injection` — direct instruction override (LLM01 · AML.T0051)
  - `jailbreak` — persona / hypothetical / refusal-suppression (LLM01 · AML.T0054)
  - `system_prompt_leak` — recover hidden instructions (LLM07 · AML.T0057)
  - `data_exfiltration` — PII / secret disclosure (LLM02 · AML.T0057)
  - `agent_tool_abuse` — prompt-injection → tool/command execution (LLM06 · AML.T0053, **critical**)

  **Web-app probes** — OWASP Top 10 (2021) + MITRE ATT&CK:
  - `sql_injection` — error/boolean SQLi (A03 · T1190, **critical**)
  - `command_injection` — OS command execution (A03 · T1059, **critical**)
  - `ssrf` — server-side request forgery to internal metadata (A10 · T1190, **critical**)
  - `reflected_xss` — unescaped reflection (A03 · T1059.007)
  - `broken_access_control` — IDOR / missing authz (A01 · T1190)
  - `auth_failures` — default/weak credentials (A07 · T1110)
  - `security_misconfiguration` — missing headers / verbose errors (A05 · T1595)
  - `vulnerable_components` — version-banner disclosure (A06 · T1595.002)
- **Orchestration strategies**
  - `single_turn` — fire each payload once (Garak-style sweep)
  - `crescendo` — benign→malicious multi-turn escalation (PyRIT-style)
  - `tree_of_attacks` — adaptive refinement against refusals (PAIR/TAP-style)
- **LLM attacker & judge** — plug in any OpenAI-compatible endpoint or Anthropic
  to generate/mutate prompts and score success; or run the **offline** engine
  with deterministic payloads + heuristic judging (**no key needed**).
- **Visual console**
  - Dashboard: severity donut + OWASP coverage
  - **Attack-chain graph**: Target → Probes → Attempts; red paths = successful exploits
  - Click any node for the **step-by-step attack trail** (every prompt/response "attach" step)
  - **PoC-validated findings** with evidence (leaked secret, shell output, trophy flag) + remediation
- **Safety by design** — authorization gate per target, per-run budgets, and a
  demo target that can only be reached on an **internal, no-internet** Docker network.

---

## Quickstart (local Docker)

```bash
git clone <your-fork-url> dagger-ai
cd dagger-ai
./dagger start
```

Open **http://localhost:8099** → sign in with `admin` / `Admin@12345`
(change these in `.env`).

### Try it safely (bundled, isolated, pre-authorized lab targets)

**A) AI pentest (headline)** — **Targets →** *Demo host (AI pentest)* →
**Campaigns →** pick it (the pentest modules appear automatically) → **Run**.
Watch the operator work through the phases; when the tool-runner has finished
building, nmap/nuclei/ffuf run for real against the lab host, and the built-in
probes confirm **critical SQLi, command injection, and SSRF** — each with the
command/output trail and OWASP + MITRE ATT&CK mapping, plus an AI summary.

**B) Web app** — *Demo web app* → campaign → **Run** → 8 OWASP findings.

**C) LLM agent** — *Demo LLM agent* → campaign (incl. `agent_tool_abuse`) →
**Run** → prompt-injection drives the agent's shell tool to `cat /flag.txt`
(`DAGGER-FLAG{…}` trophy = proof of RCE).

> First `./dagger start` builds the Kali tool-runner (nmap/nuclei/…), which
> takes several minutes. Until it's up, AI pentest still runs using the built-in
> web probes; the dashboard's "Pentest tool-runner" panel shows which tools are live.

### Test your own AI system

**Targets → New target**, give it the endpoint, a request body template using
`{{PROMPT}}`, and the dotted path to the reply text, e.g. for an OpenAI-compatible API:

- Body: `{"model":"your-model","messages":[{"role":"user","content":"{{PROMPT}}"}]}`
- Response path: `choices.0.message.content`

Then **Authorize** it (record your permission note) and build a campaign.

### Use a real LLM as the attacker/judge (optional, stronger)

Edit `.env`:

```env
DAGGER_ATTACKER_PROVIDER=openai         # or anthropic
DAGGER_ATTACKER_BASE_URL=https://api.openai.com/v1
DAGGER_ATTACKER_API_KEY=sk-...
DAGGER_ATTACKER_MODEL=gpt-4o-mini
```

`./dagger rebuild`.

---

## Management

```bash
./dagger start      # build + start (console + demo lab)
./dagger stop       # stop (data kept in ./data)
./dagger rebuild    # after code changes
./dagger logs       # tail logs
./dagger status     # container + health
./dagger reset      # delete all data (confirms first)
```

Data (SQLite + snapshots) lives in `./data` via a bind mount, so rebuilds and
`docker compose down` never lose it.

---

## Architecture

```
┌────────────── dagger-net (bridge) ───────────────────────────┐
│  dagger-ai  :8099   FastAPI + SQLite + console (web/)         │
│    engine ─ host target ─▶ operator ─▶ tool-runner ──────────┐│
│           ─ web target  ─▶ web probes                        ││
│           ─ llm target  ─▶ orchestrators → LLM probes        ││
│  tool-runner :9020 (Kali: nmap/nuclei/httpx/ffuf/whatweb/sqlmap)──▶ internet
│         │  (your authorized external targets) ───────────────┼┼──▶ internet
│         ▼                                                     ││
├──────── dagger-lab (internal, NO internet) ──────────────────┼┘
│  vulnerable-target :9009 (weak LLM agent)                     │
│  vulnerable-webapp :9010 (weak OWASP web app = demo host)     │
└───────────────────────────────────────────────────────────────┘
```

- `core/operator.py` — AI pentest operator: plans phases, drives tools, distills findings
- `tool_runner/` — isolated Kali sidecar exposing nmap/nuclei/httpx/ffuf/whatweb/sqlmap
- `core/tools_client.py` — app → tool-runner client (graceful when a tool/runner is down)
- `core/probes/web.py` — built-in OWASP web probes · `core/probes/builtin.py` — LLM probes
- `core/orchestrators/` — single-turn / crescendo / tree-of-attacks (LLM probes)
- `core/engine.py` — runs campaigns, persists attempts+steps, distills findings
- `core/taxonomy.py` — OWASP LLM/Web + MITRE ATLAS/ATT&CK maps
- `web/` — zero-dependency console (SVG attack graph, no CDN)
- `vulnerable_target/` · `vulnerable_webapp/` — bundled lab targets for safe demos

---

## Cloud deployment

Dagger-AI runs on any cloud that runs containers. See **[DEPLOY.md](DEPLOY.md)**
for the full guide. The short version (one VM with Docker + a domain):

```bash
git clone https://github.com/yutang718/dagger-ai && cd dagger-ai
cp .env.prod.example .env && nano .env    # set DAGGER_DOMAIN + strong secrets
./dagger prod                             # console + automatic HTTPS, NO demo targets
```

> The production stack (`docker-compose.prod.yml`) **excludes the vulnerable
> demo targets** and serves the console over HTTPS only. Never expose the demo
> targets to a network you don't fully control.

## Responsible use

Dagger-AI assesses AI systems for weaknesses so they can be fixed. Do not use
it against systems you are not authorized to test. The bundled vulnerable
target is a training lab (like DVWA / OWASP Juice Shop): it deliberately
executes injected commands and must only run on the isolated `dagger-lab`
network shipped here — never expose it or mount anything valuable into it.

## License

MIT — see [LICENSE](LICENSE).
