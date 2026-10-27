# 🗡️ Dagger-AI

**An LLM-driven AI red-teaming platform for authorized testing of AI systems.**
Point it at a chatbot, an LLM API, or a tool-enabled agent **you own or are
permitted to assess**, and Dagger-AI runs structured adversarial campaigns —
prompt injection, jailbreaks, system-prompt leakage, data exfiltration, and
agent tool-abuse — then shows you every step, the evidence, and how to fix it,
in a visual console. Self-hosted, one command, no API key required.

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

- **Structured attack campaigns** — pick probes + an orchestration strategy
  against one target.
- **Probes (attack modules)**, each mapped to OWASP LLM Top 10 (2025) + MITRE ATLAS:
  - `prompt_injection` — direct instruction override (LLM01)
  - `jailbreak` — persona / hypothetical / refusal-suppression (LLM01 · jailbreak)
  - `system_prompt_leak` — recover hidden instructions (LLM07)
  - `data_exfiltration` — PII / secret disclosure (LLM02)
  - `agent_tool_abuse` — prompt-injection → tool/command execution (LLM06, **critical**)
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

### Try a full exploit chain safely (2 minutes)

1. **Targets →** *Add bundled demo agent* (it's pre-authorized; runs isolated).
2. **Campaigns →** *New campaign* → pick the demo agent, select **all probes**
   (including `agent_tool_abuse`), choose a strategy, **Create**.
3. Hit **▶ Run**. Watch the attack-chain graph light up live.
4. Click the red **`agent_tool_abuse`** node → see the prompt-injection that
   drove the agent's shell tool to run `id` / read `cat /flag.txt` —
   the `DAGGER-FLAG{…}` trophy in the evidence box is proof of RCE.

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
┌────────────── dagger-net (bridge) ──────────────┐
│  dagger-ai  :8099                                │
│   FastAPI + SQLite + static console (web/)       │
│   engine → orchestrators → probes → judge        │
│         │  (your authorized external targets) ───┼──▶ internet
│         ▼                                         │
├──────── dagger-lab (internal, NO internet) ──────┤
│  vulnerable-target :9009  (intentionally weak)   │
└──────────────────────────────────────────────────┘
```

- `core/probes/` — attack modules + payload library
- `core/orchestrators/` — single-turn / crescendo / tree-of-attacks
- `core/engine.py` — runs campaigns, persists attempts+steps, distills findings
- `core/judge.py` — LLM or heuristic success scoring (evidence required)
- `web/` — zero-dependency console (SVG attack graph, no CDN)
- `vulnerable_target/` — bundled lab agent for safe end-to-end demos

---

## Responsible use

Dagger-AI assesses AI systems for weaknesses so they can be fixed. Do not use
it against systems you are not authorized to test. The bundled vulnerable
target is a training lab (like DVWA / OWASP Juice Shop): it deliberately
executes injected commands and must only run on the isolated `dagger-lab`
network shipped here — never expose it or mount anything valuable into it.

## License

MIT — see [LICENSE](LICENSE).
