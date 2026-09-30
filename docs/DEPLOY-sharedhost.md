# Deploy Falcon on a shared host (alongside existing sites) — falcon.orvex.services

For a server that already runs other sites behind nginx/Caddy. Falcon runs its containers on
**loopback only** and your existing reverse proxy fronts the subdomain. It never touches ports
80/443 or your other vhosts.

## 0. DNS
Point an A record for `falcon.orvex.services` at the server's public IP (in the orvex.services
DNS zone). Confirm: `dig +short falcon.orvex.services`.

## 1. Get the code
```bash
git clone https://github.com/Mr6MJT/falcon.git
cd falcon
```

## 2. Configure
```bash
cp infra/.env.example infra/.env
python3 -c "import secrets;print('ORVEX_JWT_SECRET='+secrets.token_urlsafe(48))"
python3 -c "import os,base64;print('ORVEX_SECRET_KEY='+base64.b64encode(os.urandom(32)).decode())"
nano infra/.env
```
Set in `infra/.env`:
- `NEXT_PUBLIC_API_BASE=https://falcon.orvex.services/api`   ← baked into the web build
- `POSTGRES_PASSWORD`, `ORVEX_DB_PASSWORD`, the two secrets above
- `ORVEX_ADMIN_EMAIL`, `ORVEX_ADMIN_PASSWORD` (your first login)
- `FALCON_DOMAIN=falcon.orvex.services`

## 3. Bring up the stack (no Caddy; loopback ports 8095 web / 8096 api)
```bash
docker compose --env-file infra/.env \
  -f infra/compose.prod.yaml -f infra/compose.sharedhost.yaml up -d --build
docker compose -f infra/compose.prod.yaml -f infra/compose.sharedhost.yaml ps
```
Check nothing else is on those ports first: `sudo ss -ltnp | grep -E '8095|8096'` (should be empty
before `up`). Change the left-hand ports in `infra/compose.sharedhost.yaml` if they clash.

## 4. Wire your reverse proxy
**nginx:**
```bash
sudo cp infra/reverse-proxy/falcon.orvex.services.nginx.conf \
        /etc/nginx/sites-available/falcon.orvex.services
sudo ln -s /etc/nginx/sites-available/falcon.orvex.services /etc/nginx/sites-enabled/
sudo certbot --nginx -d falcon.orvex.services      # issues TLS + uncomments ssl_* lines
sudo nginx -t && sudo systemctl reload nginx
```
**Caddy:** append `infra/reverse-proxy/falcon.orvex.services.Caddyfile` to your Caddyfile and
`sudo systemctl reload caddy`.

## 5. Use it
Open `https://falcon.orvex.services` and sign in with the admin email/password from `infra/.env`.

## Operating
```bash
CM="docker compose -f infra/compose.prod.yaml -f infra/compose.sharedhost.yaml"
$CM logs -f api          # or worker / web
$CM ps
$CM down                 # stops ONLY Falcon; your other sites are untouched
```

## Safety on a shared box
- Falcon binds loopback only — it cannot conflict with other vhosts.
- `docker compose ... down` only stops Falcon's own containers/volumes.
- The worker does real outbound scanning; keep scope tight and honor program rules.
