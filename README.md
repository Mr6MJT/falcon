# Orvex Recon

An **authorized-testing** platform for bug-bounty recon and vulnerability scanning.
You register a program with an **authorization record** and an explicit **scope**, and
Orvex runs a recon → fingerprint → discovery → findings → report pipeline against *only*
the in-scope assets, rate-limited and non-destructive by default.

> Orvex is built for testing systems you are authorized to test — bug-bounty programs
> whose scope and rules you follow, or engagements with a signed statement of work.
> During development it only ever points at the bundled OWASP Juice Shop lab. Pointing a
> scanner at systems you are not authorized to test is what gets people removed from
> programs (and worse), never paid. The whole design below exists to keep you inside the
> rules so findings are actually eligible for a bounty.

## Why "responsible by design" is also how you get paid

Programs reject (and ban) submissions that come from off-scope testing, DoS-style
traffic, or destructive probes. Orvex's guardrails map 1:1 to the things bounty programs
require:

| Program rule | Orvex control |
|---|---|
| Stay in scope | `is_in_scope()` — default-deny, deny-wins, label-anchored wildcards, IDN-normalised, IP≠hostname |
| No DoS / respect rate limits | per-eTLD+1 token bucket; Safe profile default; adaptive backoff on 429/503 |
| No destructive actions | GET/idempotent probes by default; nuclei `dos,intrusive,fuzz,brute-force` denied |
| Authorized only | per-program authorization record required before any run |
| Honest reporting | findings are `confirmed` / `candidate` / `informational`; IDOR/access-control hard-capped at `candidate` |

## Where fuzzing fits (added per request)

Fuzzing is a first-class module — but inside the same envelope as everything else:

- **Content/parameter fuzzing** (ffuf-style + nuclei fuzzing templates): directory/file
  discovery, parameter discovery, and reflection checks.
- **Rate-limited** through the same token bucket; honors `Retry-After` / backoff.
- **Scope-bound**: every fuzzing target passes `is_in_scope()` via `guard.run_tool`.
- **Non-destructive**: GET/idempotent by default; state-changing methods are a separate,
  authorization-gated opt-in.
- **Opt-in + gated**: only runs when the program's authorization record allows active
  testing. It is *not* stress/DoS fuzzing — that stays denied.

This keeps fuzzing useful for finding real, reportable bugs without tripping the "no DoS /
stay in scope" rules that would disqualify a submission.

## What's built so far (safety spine — slices 0→3)

The spec makes the safety spine a hard prerequisite before anything touches a network.
Implemented and tested:

- `packages/core/scope.py` — the single scope matcher (`is_in_scope`). 24 rejection tests.
- `packages/core/ratelimit.py` — token bucket keyed by eTLD+1; Safe/Normal/Aggressive
  profiles clamped to the program's contractual cap.
- `packages/core/redact.py` — secret-redaction filter for all engine output.
- `packages/core/guard.py` — **the one exec choke point**: scope → rate → spawn → redact,
  with attempt caps for sharp tools (login probing ≤ 5).
- `scripts/check_no_subprocess.py` — CI gate: process execution exists *only* in guard.py.

### Slice 1 — core schema + RLS + alembic (done)

- `packages/core/models.py` — full data model (orgs/users/programs/authorizations/scans/
  DAG stages + all result tables). The honesty invariant is enforced two ways: a Python
  guard in `Finding.__init__` **and** a DB `CheckConstraint` — IDOR / access-control /
  business-logic / injection candidates can never be stored as `confirmed`.
- `packages/core/db.py` — engine/session + the RLS org-context helper (`org_session`).
- `migrations/` — alembic initial schema + a **row-level-security** migration that
  `FORCE`s RLS on all 18 tenant tables with a fail-closed org-isolation policy.
- `scripts/seed.py` — seeds the single org + first admin (invite-based; no public signup).

Verified against a live Postgres: `alembic upgrade head` clean, `alembic check` shows no
drift, and RLS blocks cross-org reads/writes (a session bound to org A cannot see or write
org B's rows; no org set → zero rows).

```bash
python -m venv .venv
./.venv/bin/pip install pytest ruff sqlalchemy alembic "psycopg[binary]" tldextract

# start a local postgres (compose) for the DB-backed tests
docker compose -f infra/compose.yaml up -d postgres

python scripts/check_no_subprocess.py                    # exec-choke-point gate
ORVEX_ALEMBIC_URL=postgresql+psycopg://postgres:orvex@localhost:5432/orvex \
  ./.venv/bin/alembic upgrade head
ORVEX_TEST_DB_URL=postgresql+psycopg://orvex_app:orvex@localhost:5432/orvex \
  ./.venv/bin/python -m pytest -q                        # 46 passing
```

(Scope/guard/redaction/honesty tests run without a DB; RLS tests skip if none is present.)

### Slice 4 — orchestrator + passive pipeline (done)

The pipeline is an explicit DAG persisted in `scan_stages` (DB is source of truth).

- `packages/core/pipeline.py` — `StageDef` graph + `advance_scan` coordinator: dispatches
  every stage whose deps are DONE and which is enabled in `scan.config`; idempotent so it
  can be re-run to resume after a crash.
- `packages/core/stages.py` — passive stages `subdomains → dns → httpx`, each running its
  engine through `guard.run_tool`, **re-validating every discovered asset against scope
  (Gate 2)** before feeding it onward, and upserting results with `ON CONFLICT` (no dupes).
- `packages/core/orchestrator.py` — `execute_stage` (row transitions) + `run_pipeline_inline`
  (drives the DAG; the Celery task path reuses `execute_stage` unchanged).
- `packages/core/cancel.py` — cooperative cancel flag (`cancel:<scan_id>`; in-memory + Redis).

Verified with an injected engine runner (no binaries/network): a passive scan populates
`subdomains`/`dns_records`/`http_endpoints`, stages advance to DONE and the scan COMPLETEs,
a mid-run cancel halts remaining stages, a re-run adds no duplicate rows, and a discovered
out-of-scope host is stored (`in_scope=false`, "Discovered, not tested") but never fed to a
downstream engine.

### Slice 5 — events + WebSocket + snapshot (done)

Live progress, built for correct reconnection: the client GETs an authoritative snapshot,
then streams throttled deltas; a missed delta is harmless because the next snapshot
reconciles.

- `packages/core/events.py` — event bus (in-memory + Redis pub/sub) + `ScanEventPublisher`
  that throttles per-stage progress to ≤1/s, never throttles milestones, and only streams
  `finding.created` for severity ≥ medium (detailed rows are paged over REST, never streamed).
- `packages/core/snapshot.py` — `build_snapshot`: scan status + per-stage progress + summary
  counts (no detailed rows).
- `packages/core/auth.py` — JWT (HS256) with org + role claims.
- `apps/api/main.py` — `GET /scans/{id}/state` (authoritative snapshot) and
  `WS /scans/{id}/events` (JWT-authed handshake, org-authorized; unauth closed before accept).
- The orchestrator now emits stage/scan events through the publisher.

Verified: throttle drops sub-second progress but always passes milestones; low-severity
findings aren't streamed; the snapshot endpoint enforces auth and org isolation (cross-org →
404); an unauthenticated WS is rejected; an authed WS receives the snapshot then a live delta.

### Slice 6 — app shell + program CRUD + AuthorizationGate wizard (done)

Next.js 14 App Router + TypeScript + Tailwind, i18n **en/ar/fr with RTL** for Arabic,
responsive 390/1440. Under `apps/web/`.

- App shell with locale-aware nav + locale switcher; dashboard; programs list + create form.
- **Scan wizard** (`/[locale]/scans/new`): domains → auto-derived scope rules →
  aggressiveness (with active-probe + fuzzing toggles) → **AuthorizationGate**.
- **AuthorizationGate**: typed attestation (who authorized, three confirmations, and a typed
  "I AM AUTHORIZED" phrase). **Start is disabled until the attestation is complete** — and the
  gating rule lives in a pure, unit-tested module (`src/lib/authorization.ts`), so the safety
  behavior isn't just UI state. Sharp modules (active/fuzzing/aggressive) are blocked in the
  UI unless the program's authorization record permits active testing, mirroring the backend.

Verified: `tsc` clean, ESLint clean, **9 vitest tests pass**, `next build` prerenders all
3 locales × 3 pages. Rendered in a real browser: Start stays disabled until the gate is
completed then enables; at 375px in Arabic RTL there is no horizontal overflow (`dir="rtl"`).

```bash
cd apps/web
pnpm install
pnpm dev          # http://localhost:3000  (set NEXT_PUBLIC_API_BASE to the API)
pnpm typecheck && pnpm lint && pnpm test && pnpm build
```

> Needs Node 22 + pnpm. (This dev session is on a Linux box without Node preinstalled; the
> app was built and verified with a locally-fetched Node 22.)

### Program/scan CRUD API + Gate 1 (done)

The endpoints the wizard drives, with the first scope/authorization gate:

- `packages/core/gate1.py` — `create_scan` admission check: refuses if there's no live
  authorization (missing/expired/revoked) or it forbids automated tools; if the requested
  aggressiveness/active/fuzzing exceeds what the authorization permits; if the scope is empty
  or a seed is out of scope / a special address; or if the run exceeds hard caps (≤50 root
  domains). On success it **freezes a scope-snapshot hash** onto the scan and seeds its stages.
- `apps/api/main.py` — `POST /programs` (name + scope rules + authorization in one call),
  `GET /programs`, and `POST /scans` (runs Gate 1). Writes require the `admin`/`operator`
  role; `viewer` is read-only. All writes go through the RLS org-context session.

Verified over HTTP + against the DB: program create/list, viewer-cannot-write (403),
scan-create success freezes a 64-char scope hash and seeds ≥3 stages, out-of-scope seed →
400, and active/fuzzing without authorization → 403. The web client has `api.createScan`.

### Slice 7 — live scan view + wizard wiring (done)

Closes the demoable spine: **wizard → create scan (Gate 1) → watch it run live**.

- `apps/web/src/lib/useScanEvents.ts` — subscribes to the scan WebSocket (token via the
  `bearer.<token>` subprotocol, never the URL), applies deltas, and re-pulls the snapshot on
  each milestone so counts stay live; auto-reconnects and reconciles from the snapshot.
- `apps/web/src/app/[locale]/scans/[id]/page.tsx` — live view: status badge, live/reconnecting
  indicator, counters, **StageStepper** (per-stage progress), and a **findings feed**
  (severity scale + candidate-vs-confirmed styling).
- The wizard's **Start** now `POST`s `/scans` and routes to the live view; a program selector
  was added, and picking a program reads its `allows_active_testing` to gate sharp modules.
- API: the WS handshake now **echoes the offered subprotocol** (browsers fail the WS
  otherwise); `app_factory` uses the Redis bus when `ORVEX_REDIS_URL` is set; CORS via
  `ORVEX_CORS_ORIGINS`.

Verified **end-to-end in a real browser** against the running API + Redis: create a scan,
open the live view, drive the pipeline (`scripts/demo_run.py`) — stages stream to done over
the WebSocket, counters update live (subdomains 4, http endpoints 3), status → completed, and
the "Live" indicator reflects the connection. `scripts/demo_seed.py` seeds a program +
authorization + scan and prints a token for local demos.

### Slice 8 — recon stages: ports / TLS / WAF / tech (done)

The DAG fans out after `httpx` into four concurrent stages:

- **ports** (`naabu`) → `services`. Runs **only against IPs explicitly in scope** (an ip/cidr
  rule) — a host resolving to an IP never authorises scanning that IP, so shared CDN /
  co-tenant infrastructure is never touched.
- **tls** (`tlsx`) → `tls_info`, flagging weak protocols (TLS ≤ 1.1 / SSLv3).
- **waf** (`wafw00f`) → updates `http_endpoints.waf_vendor`.
- **tech** (`httpx -td`) → `technologies` (idempotent via a non-null version key).

Verified (parsers + DB population): ports produces nothing when the resolved IP isn't
explicitly in scope and services rows when it is; TLS flags a weak protocol; WAF sets the
vendor; tech populates and de-dupes on re-run. Snapshot counters now include tls + technologies.

### Slice 10 — URL discovery + parameters + secrets (done)

- **urls** (`katana` crawl + `gau` historical) → `http_endpoints` + `parameters`. Every
  discovered URL is re-checked against scope (Gate 2); out-of-scope URLs are dropped.
  Query-string params are extracted into `parameters`.
- **secrets** (`trufflehog`) → `secrets`, storing **only a mask (first4…last4) + sha256 +
  detector + location + verified** by default. Full retention is opt-in per engagement
  (`scan.config.retain_secrets`), stored as **AES-256-GCM ciphertext** (`packages/core/crypto.py`,
  key from `ORVEX_SECRET_KEY`) and auto-purgeable.

The raw secret is requested from the guard (`redact_stdout=False`) only to compute the mask +
hash in memory; it is **never logged, never audited, and never stored in the clear**.
Verified by test: after detecting a live-looking AWS key, the DB row holds `AKIA…MPLE` + the
sha256, `ciphertext` is NULL by default, and the plaintext appears in no DB field or audit
event; with retention on, the ciphertext decrypts back to the original only with the key.

### Slice 11 — findings engine (nuclei + CVE catalog) (done)

- **findings** (`nuclei`, allow-tags / deny `-etags dos,intrusive,fuzz,bruteforce`) → typed,
  deduped `findings` with severity, cvss, cve_id, cwe, and req/resp evidence.
- The honesty matrix is a pure, unit-tested function (`packages/core/findings.py`): **CVE
  templates → candidate** (version/banner-based; we don't assert exploitability), **matcher-based
  detections → confirmed** (TLS, missing headers, exposures, misconfig, disclosure, panels,
  takeover). Unknown → candidate. Non-CVE CVSS comes from a fixed severity map; real CVSS only
  for `type=cve` from nuclei's classification.
- Builds the global **CVE catalog** (`cves`) from finding classifications.
- ≥ medium findings are streamed to the live view via `finding.created`.

Verified: findings are typed with the right confidence, CVE carries cve_id + cvss, re-runs
don't duplicate (dedup_key), and — critically — a `confirmed` IDOR is refused both by the model
**and** by the DB CheckConstraint (raw-SQL insert raises).

### Slice 12 — findings view + triage (done)

- API: `GET /scans/{id}/findings` (severity-sorted, filterable by severity/confidence/status,
  paginated) and `PATCH /findings/{id}` (triage status; write-role only).
- Web: `/scans/[id]/findings` groups findings by severity; a **FindingDrawer** shows the
  evidence (request/response, target, CVE/CVSS/CWE) and a status selector. Candidates render
  visually distinct (dashed) from confirmed, with a "needs manual review" note.

Verified over HTTP and **in a real browser**: findings list critical-first with evidence;
confidence filter works; **triage persists** (changed a finding to `false_positive` in the
drawer, confirmed server-side); triage is refused for the `viewer` role and on a bad status.

### Slice 13 — gated active modules: fuzzing, active probes, safe login, IDOR (done)

These are **off by default** and run only when the scan is configured for active testing —
which Gate 1 permits only when the authorization record allows it. All are non-destructive by
default and route through the same guard (scope + rate + attempt caps).

- **fuzzing** (`ffuf`, opt-in): rate-limited, GET, content/parameter discovery → endpoints.
  Discovered URLs are re-checked against scope.
- **active** (`orvex-probe`, opt-in): canary-based, **GET/idempotent by default** (state-changing
  methods are a separate opt-in). XSS/SQLi are reflection/boolean-diff only and are **always
  candidate**; open-redirect (canary in `Location`) and SSRF (OAST callback) may be confirmed
  only when actually proven.
- **login** (`login_probe`, opt-in): brute-force-**protection-exists** + user-enum, **≤5 attempts**
  (requested at 5 and hard-capped by the guard). Asserts presence, never absence — "not observed
  in 5 attempts" is not a finding. Default-cred check is opt-in and never stores a working password.
- **idor** (`orvex-idor`, opt-in): two-session differential; findings are **always candidate**.

Verified: with active testing off, every module refuses to run and creates no findings; fuzzing
drops out-of-scope hits; XSS/SQLi/IDOR can never be confirmed even when the probe output claims
so; login requests are capped at 5 and only assert presence. (The active-probe/IDOR/login engines
are our own bundled tools — the worker image that contains them ships in slice 2.)

### Slice 14 — reporting (HTML / PDF / JSON) (done)

- `packages/core/report.py` — `build_report` assembles a scan into a report structure, with
  `render_html` (house-style, print-friendly), `render_json`, and `render_pdf` (WeasyPrint —
  pure Python, no headless browser / subprocess).
- API: `GET /scans/{id}/report` (data), `/report.html`, `/report.pdf`, `/report.json`.
- Web: `/scans/[id]/report` — severity/confidence/asset summary + PDF/HTML/JSON download.
- Confirmed and candidate findings are separated; candidates carry a "manual verification"
  caveat; secrets appear only as masks. Verified: the report never leaks a plaintext secret,
  and the PDF renders (`%PDF-` header).

### Slice 2 — worker engines image + Gate 3 egress firewall (done)

- `engines/Dockerfile.worker` — bundles the ProjectDiscovery suite + nmap + ffuf + trufflehog +
  gau + wafw00f, **pinned by version and verified against each release's checksums** (Go absent;
  never built from source). nuclei-templates baked at a pinned tag. Runs **non-root**,
  `cap_drop: [ALL]` + `cap_add: [NET_RAW]` with file-caps on naabu/nmap; never `--privileged`.
- `engines/orvex-probe` / `orvex-login-probe` / `orvex-idor` — the custom active engines,
  backed by tested logic in `packages/core/probes.py` (reflection XSS, boolean-diff SQLi,
  canary open-redirect, OAST-gated SSRF, safe login, two-session IDOR — honest labels enforced).
- **Gate 3** (`infra/egress/`) — the worker sits on a no-internet Docker network; the egress
  gateway is its only route out and programs an **nftables allow-list** (default DROP) from the
  per-run resolved in-scope IPs (`packages/core/egress.py`), so a packet can never reach an
  off-scope host even if every app-level check failed. Metadata/private ranges are dropped too.
- `apps/worker/` — Celery app + tasks that drive the DAG via the shared `execute_stage`
  (org threaded through for RLS), plus a `beat` service and compose wiring for all of it.

> Gate 3 and the worker image require a Linux host with `NET_ADMIN` / Docker to run; the
> Dockerfile builds the full engine set and `engines/smoke.sh` version-checks every tool.

## Not yet built

Red-team safety audit (15), full e2e against the Juice Shop lab (16), operator/legal docs (17).
Technology→CVE version matching needs an NVD feed (a `beat` refresh job) + affected-range columns.
