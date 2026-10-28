# Deploying Dagger-AI to the cloud

Dagger-AI is a standard Docker Compose app, so it runs on any cloud that can
run containers. This guide covers the **recommended path (a single VM)** plus
hardening and alternatives.

> ⚠️ **Read this first — two non-negotiable rules for cloud:**
> 1. **Never deploy the bundled vulnerable demo targets to the cloud.** They are
>    deliberately exploitable (command injection → shell). The production stack
>    (`docker-compose.prod.yml`) **excludes** them by design. Only use the demo
>    targets locally.
> 2. **Dagger-AI is an offensive-capable tool.** A public instance that anyone
>    can log into can be pointed at third-party systems. Lock it down: strong
>    credentials, HTTPS, and ideally restrict network access (firewall/VPN/IP
>    allow-list). Keep the per-target authorization gate **on**.

---

## Recommended: one cloud VM with Docker (works on any provider)

Works on AWS EC2, Google Compute Engine, Azure VM, Alibaba Cloud ECS, Tencent
Cloud CVM, DigitalOcean, Hetzner, etc. A small instance (1 vCPU / 1–2 GB) is
plenty.

**1. Create a Linux VM** (Ubuntu 22.04+ is fine) and open inbound **80** and
**443** only (and 22 for SSH, ideally from your IP only).

**2. Install Docker + Compose:**
```bash
curl -fsSL https://get.docker.com | sh
```

**3. Point a domain** at the VM's public IP (an `A` record, e.g.
`dagger.example.com`). Caddy needs this to issue a TLS certificate.

**4. Get the code and configure:**
```bash
git clone https://github.com/yutang718/dagger-ai
cd dagger-ai
cp .env.prod.example .env
openssl rand -hex 32          # paste into DAGGER_SECRET_KEY
nano .env                     # set DAGGER_DOMAIN, admin user/password, secret
```

**5. Launch the production stack** (console + auto-HTTPS reverse proxy, no demo targets):
```bash
docker compose -f docker-compose.prod.yml up -d --build
```

**6. Open `https://your-domain`** → sign in. Caddy fetches and renews the cert
automatically. Data persists in `./data` on the VM.

**Update later:**
```bash
git pull && docker compose -f docker-compose.prod.yml up -d --build
```

---

## No domain yet?

Edit `deploy/Caddyfile`: comment out the `{$DAGGER_DOMAIN}` block and uncomment
the `:443 { tls internal ... }` block. You'll reach it at `https://<server-ip>`
with a self-signed cert (browser warning is expected). Better: add a domain, or
keep the port closed and reach it over an **SSH tunnel**:
```bash
# with the prod stack but port published only to localhost, or via:
ssh -L 8099:localhost:8000 user@your-vm   # then open http://localhost:8099
```

---

## Hardening checklist (public deployments)

- [ ] Changed `DAGGER_ADMIN_USER` / `DAGGER_ADMIN_PASSWORD` from defaults
- [ ] Set a random 64-char `DAGGER_SECRET_KEY` (`openssl rand -hex 32`)
- [ ] HTTPS on (Caddy) — never expose the raw `:8000` to the internet
- [ ] Firewall: only 80/443 public; SSH limited to your IP
- [ ] `DAGGER_REQUIRE_AUTHORIZATION=true` (default) — every target needs a note
- [ ] Restrict who can reach the console (VPN / IP allow-list / security group)
- [ ] Demo targets NOT running (the prod compose omits them — verify with
      `docker compose -f docker-compose.prod.yml ps`)
- [ ] Regular backups of `./data`

Optional IP allow-list in `deploy/Caddyfile`:
```
@blocked not remote_ip 203.0.113.0/24 198.51.100.7
respond @blocked 403
```

---

## Other cloud options

| Option | Notes |
|---|---|
| **VM + Docker Compose** (above) | ✅ Recommended. Keeps the 2-container internal design, background run engine, and SQLite intact. |
| **Managed container host** (AWS ECS/Fargate, Azure Container Apps, Alibaba ACK, Tencent TKE) | Works. Run the `dagger` image as one always-on service; attach persistent storage for `/data`; put the platform's HTTPS load balancer in front instead of Caddy. |
| **Serverless (Cloud Run, etc.)** | ⚠️ Not ideal: runs are executed in a background thread with in-process state and SQLite, so scale-to-zero and multi-instance autoscaling will break in-flight runs. Pin to **1 always-on instance** with a mounted volume if you must. |
| **Kubernetes** | One Deployment (replicas: 1) + a PVC for `/data` + an Ingress with TLS. Keep replicas at 1 for the same reason as above. |

For heavy multi-user/parallel use, the run engine would need to move to an
external worker/queue (e.g. Celery + Redis) and Postgres — open an issue if you
want that; the current design targets single-operator self-hosting.
