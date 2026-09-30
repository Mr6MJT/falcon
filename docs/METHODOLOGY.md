# Falcon methodology — derived from 6,421 public bug-bounty writeups

I analyzed the writeups dataset (6,421 entries, 671 distinct bug labels) to see what hunters
actually find, then mapped each top class to what Falcon does — so improvements target real,
high-frequency payouts instead of guesses.

## Top bug classes (by writeup frequency) vs Falcon coverage

| # writeups | Bug class | Falcon coverage |
|---|---|---|
| 884 | RCE | nuclei CVE templates → *candidate* only (never auto-confirmed). Mostly manual. |
| 652 | Information disclosure | **Partial+**: JS-secret scan (new), nuclei `exposures/disclosure/config/backup`. Gap: `.git`/`.env`/backup/source-map probes. |
| 570 | XSS | Active canary probes (`orvex-probe`, gated) → *candidate*. |
| 532 | Account takeover | Mostly manual (logic/auth). Surface it via auth-flow leads. |
| 467 | IDOR | `orvex-idor` differential (gated) → *candidate* (hard-capped). |
| 379 | Logic flaw | Manual — no scanner finds these. |
| 286 | SSRF | Active OAST canary (gated) → confirmed only on callback. |
| 259 | Broken authorization | *candidate* only (honesty matrix). |
| 230 | SQL injection | Active canary (gated) → *candidate*. |
| 223 | Authentication bypass | Manual. |
| 235 | CSRF | **Gap** — add SameSite/token + form checks. |
| 177 | Open redirect | `orvex-probe` canary → *confirmed* on canary hit (gated). |
| 152 | Path traversal | nuclei + active canary. |
| **92** | **Subdomain takeover** | ✅ **ADDED** — dangling-CNAME + provider fingerprint. |
| 66 | WAF bypass | `wafw00f` detects presence; bypass is manual. |
| 52 | Clickjacking | **Gap** — `missing_security_header` type exists, needs a stage. |
| 52 | Rate limiting | `login_probe` checks brute-force protection (gated). |
| **48** | **CORS misconfiguration** | ✅ **ADDED** — arbitrary-origin reflection + credentials. |
| 50 | GraphQL | **Gap** — add introspection-enabled check. |

## What I added this round

Both had finding types already declared in the honesty matrix but **no stage producing them** —
the clearest gap the data pointed to:

1. **Subdomain takeover** (`run_takeover`, on by default): reuses the CNAME records the `dns`
   stage already collects, matches them against a fingerprint list of ~24 takeover-prone
   providers (GitHub Pages, S3, Heroku, Fastly, Shopify, Azure, Netlify, Zendesk, …), then
   fetches the page once to check for the provider's "unclaimed" fingerprint.
   Fingerprint matched → **confirmed**; dangling CNAME only → **candidate**. Read-only.

2. **CORS misconfiguration** (`run_cors`, on by default): sends one `Origin: <probe>` GET per
   live host and inspects the `Access-Control-*` response headers. Reflecting the arbitrary
   origin **with credentials** → **confirmed** (`cors_reflect_credentials`); reflection without
   credentials → **medium** misconfiguration. Read-only.

Both route through the scoped httpx engine (default-deny scope, rate limits, egress control all
still apply) and share the generalized `_fetch_response_bodies` helper.

## Prioritized roadmap (all non-destructive, all fit the architecture)

Ranked by writeup frequency × ease × safety:

1. **Sensitive-file / exposure probe** (info-disclosure = 652). Targeted GET of known-risky
   paths on each live host: `/.git/config`, `/.env`, `/.DS_Store`, `/config.json`,
   `/swagger.json` & `/openapi.json`, `/actuator`, `/server-status`, `/.well-known/*`, common
   backup suffixes. High yield, low request count. Finding type `exposure`/`disclosure`.
2. **Security headers + clickjacking** (52). Passive analysis of the responses httpx already
   fetches: missing `X-Frame-Options`/CSP `frame-ancestors` → clickjacking; missing HSTS.
   Finding type `missing_security_header` (already in the matrix).
3. **Source-map exposure** (feeds info-disclosure + secrets). Flag reachable `*.js.map`; they
   reconstruct original source and frequently leak secrets — chains into the secrets stage.
4. **GraphQL introspection** (50). If a `/graphql` endpoint answers an introspection query,
   flag it (`misconfiguration`) and store the schema as leads.
5. **CSRF signals** (235). Flag state-changing forms lacking CSRF tokens / cookies missing
   `SameSite`. Candidate-only (impact needs manual confirmation).

What Falcon deliberately will **not** claim to auto-find: RCE, account takeover, logic flaws,
auth bypass — these are manual, and the honesty matrix keeps injection/IDOR/authz findings at
*candidate*. Falcon's job is to map the surface and surface high-confidence, verifiable signals;
the creative exploitation stays with the hunter.

---
*Data: 6,421 writeups. Detections added here are non-destructive and scope-enforced.*
