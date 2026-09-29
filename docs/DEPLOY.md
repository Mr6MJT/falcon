# Deploying Falcon on a server

Requirements: a Linux server with **Docker + Docker Compose**, and (for HTTPS) a **domain**
pointed at the server's IP. Ports 80 and 443 open.

## 1. Get the code
```bash
git clone https://github.com/<your-user>/falcon.git
cd falcon
```

## 2. Configure secrets
```bash
cp infra/.env.example infra/.env
# generate strong values:
python3 -c "import secrets;print('ORVEX_JWT_SECRET=',secrets.token_urlsafe(48))"
python3 -c "import os,base64;print('ORVEX_SECRET_KEY=',base64.b64encode(os.urandom(32)).decode())"
# then edit infra/.env — set FALCON_DOMAIN, NEXT_PUBLIC_API_BASE (https://<domain>/api),
# POSTGRES_PASSWORD, ORVEX_DB_PASSWORD, the two secrets above, and the admin email/password.
nano infra/.env
```

## 3. Build & start the whole stack
```bash
docker compose --env-file infra/.env -f infra/compose.prod.yaml up -d --build
```
This starts Postgres, Redis, runs the one-shot **bootstrap** (creates the DB role, applies
migrations, seeds your admin), then brings up the API, worker, beat, web, and the Caddy
reverse proxy (which gets a Let's Encrypt certificate automatically for your domain).

## 4. Use it
Open `https://<your-domain>` and sign in with the admin email/password from `infra/.env`.

## Operating
```bash
docker compose -f infra/compose.prod.yaml ps          # status
docker compose -f infra/compose.prod.yaml logs -f api  # or worker / web / caddy
docker compose -f infra/compose.prod.yaml down         # stop
```

## Quick IP-only test (no domain / no HTTPS)
Set `FALCON_DOMAIN=:80` and `NEXT_PUBLIC_API_BASE=http://<server-ip>/api` in `infra/.env`,
then `up -d --build`. Visit `http://<server-ip>`.

## Hardening: Gate 3 egress firewall
The prod stack runs the worker with normal outbound network. To add the kernel-level egress
allow-list (so a packet can never reach an off-scope host even if an app check failed), run the
worker behind the `egress-gateway` on the no-internet `internal` network — see `infra/egress/`
and the `internal`/`egress` networks in `infra/compose.yaml`. This needs `NET_ADMIN` and a
per-run allow-list programmed by `packages/core/egress.py`.

## Responsible use
Only add programs scoped to targets you are authorized to test (a bug-bounty program you're
enrolled in, within its declared scope and its rules on automated scanning, or assets you own).
Falcon enforces scope and rate limits, but establishing authorization for a target is the
operator's responsibility.
