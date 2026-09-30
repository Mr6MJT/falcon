# Falcon Recon Report — Deriv (private program)

**Scan ID:** `cca0eebd-f745-4cdc-8476-3210cea0abf3`
**Date:** 2026-09-29
**Type:** Passive/light recon — attack-surface mapping (non-destructive)
**Scope:** `home.deriv.com`, `api-core.deriv.com`, `core-api.deriv.com`, `cashier.deriv.com`,
`api.deriv.com`, `derivws.com`, `deriv.exchange`, `deriv.ae` (exact) + `*.deriv.ae` (wildcard)

---

## 1. Executive summary

Recon completed successfully across all in-scope roots. The scan mapped a broad attack
surface but produced **zero automated vulnerability findings** — no confirmed bugs, no secrets,
no WAF-bypass, no nuclei matches. That is an honest result: this tool is non-destructive and
only reports what it can observe or match. **The value here is the surface map and the leads it
surfaces for manual testing**, not an automated bug.

| Signal | Count |
|---|---|
| Subdomains discovered | 74 (42 unique stored; 32 in-scope, 10 out-of-scope) |
| DNS records | 92 |
| Live HTTP endpoints | 23 hosts (1,787 endpoint rows after crawl) |
| URLs crawled (katana) | 5,335 |
| Parameters observed | 607 |
| TLS certificates | 23 |
| Technologies fingerprinted | 72 |
| **Automated findings (nuclei)** | **0** |
| Secrets (trufflehog) | 0 |
| Open ports (naabu) | 0 (no in-scope IP rules — hostnames only) |

## 2. Scope engine — correctness check ✅

The scope matcher behaved exactly right, which matters for staying inside program rules:

- `*.deriv.ae` (wildcard) → **all** `deriv.ae` subdomains marked **in-scope**.
- `derivws.com` (exact) → its subdomains (`api.derivws.com`, `blue.derivws.com`,
  `green.derivws.com`, `ws.derivws.com`, `staging-api.derivws.com`, …) correctly marked
  **OUT-of-scope** and never probed.
- `deriv.exchange` (exact) → `mail.deriv.exchange` marked **OUT**.
- `cf.api.deriv.com`, `www.cashier.deriv.com` → **OUT** (not listed exact hosts).

**Do not test the OUT-of-scope hosts** — they showed up in discovery but fall outside your
program's declared scope.

## 3. Attack surface — highest-value leads (manual testing)

### Staging / pre-production (classic soft targets)
- `staging-academy.deriv.ae` → **200 OK** (live, reachable)
- `staging.deriv.ae`, `staging-app.deriv.ae`, `staging-api.deriv.ae` (**403**)
- `af-com-deriv-uae-staging.deriv.ae`, `assets-staging.deriv.ae`, `static-staging.deriv.ae`

> Staging environments are often less hardened than prod (default creds, verbose errors,
> debug flags, missing auth). Worth careful manual review — within program rules.

### APIs
- `api.deriv.ae` → **403** (auth-gated; probe for authz bypass / verb tampering / path confusion)
- `staging-api.deriv.ae` → **403**
- `api.deriv.ae/v1/signup` (crawled) — account-creation flow
- `api-core.deriv.com`, `core-api.deriv.com` (**301**), `api.deriv.com`
- `tradersview-api.deriv.ae` → 404 (exists as a hostname; enumerate routes)

### Authentication surface
- `deriv.ae/.well-known/openid-configuration` and
  `docs.deriv.ae/.well-known/openid-configuration` — **OIDC discovery documents exposed**.
  Enumerate the issuer, authorize/token endpoints, supported flows; check for weak redirect_uri
  validation, PKCE, and open-redirect on callbacks.
- Login/signup flows: `app.deriv.ae/uae/login`, `app.deriv.ae/uae/signup?accountType=real`,
  `home.deriv.com/dashboard/login`, `home.deriv.com/dashboard/signup`.

### Trading platform
- `mt5-real03-web-uae.deriv.ae` → **301** (MT5 web terminal, real-money — high value, test carefully)
- `tradersview.deriv.ae` → **200** ("AI Trading Intelligence by Deriv")

### Anomaly worth a look
- `derivws.com` → **520** (Cloudflare "web server returned an unknown error"). Origin-side
  misconfiguration or instability — sometimes leaks origin behavior; investigate gently.

## 4. Technology fingerprint

Everything sits behind **Cloudflare** (20 hosts), with **HSTS** (17) and **HTTP/3** (16) widely
enabled — a well-run edge. Other observed: Google Tag Manager, jsDelivr/Unpkg, Webflow,
**jQuery 3.5.1**. (jQuery 3.5.1 is post the 3.5.0 XSS fix, so not itself a finding, but note any
sink usage during manual DOM-XSS review.)

The heavy Cloudflare presence means: (a) IP/port scanning of these hostnames is pointless (and
the tool correctly skipped it — no in-scope IP rules), and (b) most testing is app-layer.

## 5. What was NOT found (honest)

- **0** nuclei findings (CVEs, misconfigs, exposures) across the live hosts.
- **0** exposed secrets.
- **0** WAF-bypass / takeover signals.

This is normal for a mature target on first passive recon. Real bugs on programs like this are
usually **business-logic, authz/IDOR, and auth-flow** issues — which automated scanners don't
find. That's your manual work, using the surface above.

## 6. Recommended next steps

1. Manually review the **staging** hosts and the **403 APIs** for authz bypass / IDOR.
2. Pull apart the **OIDC** config and the login/signup flows (redirect_uri, token handling).
3. Enumerate routes on the API hosts using the 607 observed parameters as a seed.
4. Keep everything within Deriv's program rules on automated traffic and rate.

---
*Generated by Falcon. Recon is non-destructive; no exploitation was performed. Authorization for
testing these targets is the operator's responsibility under the Deriv private program.*
