# Orvex Recon — Tool Documentation

Orvex is a platform for **authorized** bug-bounty recon and vulnerability scanning. You give
it the root domains for a program you're allowed to test; it enumerates the attack surface,
fingerprints it, discovers URLs and secrets, runs vulnerability checks, and produces a
browsable, honestly-labelled findings report — all rate-limited, scope-enforced, and
non-destructive by default.

> **Authorized use only.** Orvex will only touch assets that are inside a program's declared
> scope and covered by an authorization record. During development it is pointed exclusively
> at a self-hosted OWASP Juice Shop lab. Never point it at a third-party host you are not
> authorized to test — that is what gets hunters removed from programs, and Orvex is designed
> to prevent it.

---

## 1. What it does (the pipeline)

A scan is an explicit dependency graph (DAG) persisted in the database and executed stage by
stage. Each stage runs a real engine through **one guarded choke point** (scope check → rate
limit → run → secret-redaction) and writes its results to typed tables. Re-running a scan
never duplicates rows (idempotent upserts), and a crashed scan resumes from where it stopped.

| # | Stage | Engine | What it produces |
|---|-------|--------|------------------|
| 1 | Subdomain enumeration | subfinder | `subdomains` (passive sources) |
| 2 | DNS resolution / live hosts | dnsx | `dns_records`, which hosts resolve |
| 3 | HTTP probing | httpx | `http_endpoints` (status, title, length) |
| 4 | Port / service scan | naabu | `services` — **only IPs explicitly in scope** |
| 5 | TLS/SSL analysis | tlsx | `tls_info` (version, issuer, expiry, weak-protocol flag) |
| 6 | WAF / CDN detection | wafw00f | WAF vendor on each endpoint |
| 7 | Tech fingerprinting | httpx `-td` | `technologies` (frameworks, servers, CMS) |
| 8 | URL / endpoint discovery | katana + gau | more `http_endpoints` + `parameters` |
| 9 | Secret / API-key detection | trufflehog | `secrets` (masked; see §4) |
| 10 | Findings engine | nuclei | typed, deduped `findings` + CVE catalog |
| 11 | Fuzzing *(opt-in)* | ffuf | content/parameter discovery |
| 12 | Active probes *(opt-in)* | canary probes | injection/redirect/SSRF candidates |
| 13 | Safe login testing *(opt-in)* | login probe | brute-force-protection / user-enum |
| 14 | IDOR differential *(opt-in)* | two-session probe | IDOR candidates |

Stages 1–10 are the safe default (passive + light active). Stages 11–14 are **sharp** — they
stay off unless the scan is explicitly configured for active testing **and** the program's
authorization record permits it.

---

## 2. What vulnerabilities & issues it can find

Orvex labels every finding by how reliably it can be automated, and the label is enforced in
code and in the database — a heuristic guess can never be stored as a confirmed bug.

### ✅ Confirmed — reliably automatable, reported as findings
- **Open ports & running services** (with product/version where available)
- **TLS/SSL issues** — weak/outdated protocols (TLS ≤ 1.1, SSLv3), expired/self-signed certs
- **WAF / CDN / Cloudflare presence**
- **Technology & version fingerprints** (front-end, back-end, server, CMS)
- **Exposed secrets / API keys** (verified) — stored masked, never in the clear
- **Known-vulnerability & misconfiguration detections** (nuclei matcher-based): exposures,
  misconfigurations, information disclosure, exposed admin panels, backup/log files,
  **subdomain takeover**
- **Missing security headers**
- **User enumeration** (distinct responses for valid vs invalid accounts)
- **Brute-force-protection present** (lockout / 429 / CAPTCHA observed)
- **Default credentials accepted** (opt-in, tiny vendor list, one try each)
- **Open redirect** (canary reflected in `Location`) and **SSRF** (proven by an out-of-band
  callback) — confirmed *only* when actually proven

### 🟠 Candidate — heuristic, flagged for manual review (never called a confirmed bug)
- **CVEs matched by version/banner** (a version match is a lead, not proof of exploitability)
- **Reflected-XSS candidates** (input reflected without execution proof)
- **SQL-injection candidates** (boolean-difference / short time-based signals only)
- **Open-redirect / SSRF candidates** (suspected but not canary/OAST-proven)
- **IDOR candidates** (differential access between two sessions) — **always candidate**

### 🔍 Manual only — the tool assists but never claims a finding
- **Business-logic flaws**
- **Complex access-control / authorization chains**

**Honesty guarantee:** IDOR, broken access control, business logic, and all injection
candidates are *hard-capped* at "candidate" — the code path to mark them "confirmed" does not
exist, and the database rejects it even via a raw insert. In the UI, candidates are rendered
visually distinct from confirmed findings.

---

## 3. How it stays safe & responsible

These are the controls that make Orvex safe to run and keep your submissions eligible:

- **Scope enforcement (one source of truth).** Every target passes a single `is_in_scope()`
  check: default-deny, deny-wins, wildcards match subdomains only (not the apex), IDN/punycode
  normalised (no homograph tricks), and **a hostname being in scope never authorises scanning
  its resolved IP** (avoids hitting shared CDN / co-tenant infra). Metadata/private/loopback
  IPs (e.g. `169.254.169.254`) are refused outright.
- **Authorization record required.** No scan runs without a per-program record (who authorized
  it, type, expiry, whether active testing / automated tools are allowed, and a per-program
  rate cap). At scan creation, **Gate 1** refuses anything out of scope or beyond what the
  authorization permits, and freezes a scope snapshot onto the run.
- **Rate limiting (never DoS).** A token-bucket keyed per registrable domain, defaulting to a
  conservative "Safe" profile; higher profiles are opt-in and clamped to the program's cap.
- **Non-destructive by default.** Active probes are GET/idempotent; nuclei runs with
  `dos,intrusive,fuzz,brute-force` template classes **denied**; login testing is capped at
  **5 attempts** and only ever asserts that protection *exists*, never its absence.
- **Secret safety.** All engine output is redaction-filtered before it hits logs or the DB;
  secrets are stored as a mask + SHA-256 by default, with full values only under opt-in
  AES-256-GCM encryption.
- **Single exec choke point.** Every engine is launched from one guarded function; a CI gate
  fails the build if process execution appears anywhere else.
- **Audit trail.** Scope checks, drops, spawns, and rate waits are recorded per run.

---

## 4. Interface

- **Web app** (Next.js, English/Arabic/French with RTL): create programs, a scan wizard with a
  typed **Authorization Gate** (Start is disabled until you attest authorization), a **live
  scan view** (per-stage progress + counters + findings feed over WebSocket), and a **findings
  view** with an evidence drawer (request/response) and triage that persists.
- **API** (FastAPI): program/scan CRUD, authoritative scan-state snapshot, live-progress
  WebSocket, findings list + triage — all JWT-authed and isolated per organization.

---

## 5. Current status (build progress)

Built and tested (102 backend tests + 9 web tests, all green):

- Scope guard + rate limiter + secret redaction + exec choke point
- Database schema with per-org row-level security
- Orchestrator DAG with resume / cancel / live progress
- All recon + discovery stages (subdomains → dns → httpx → ports/tls/waf/tech → urls → secrets)
- Findings engine (nuclei + CVE catalog) with the honesty matrix
- Gated active modules (fuzzing, active probes, safe login, IDOR)
- Web app: shell, programs, wizard + authorization gate, live view, findings + triage
- Program/scan CRUD API with Gate 1 authorization admission

Not yet built:

- **Worker Docker image (slice 2)** — packages the pinned engine binaries and adds **Gate 3**,
  the kernel-level egress firewall (the final, un-bypassable network control). The custom
  active-probe / IDOR / login engines are wired and gated but their real network scripts ship
  with this image.
- **Reporting (slice 14)** — HTML house-style + PDF + JSON export.
- **Technology→CVE version matching** — needs an NVD feed + affected-range data.
- Red-team safety audit and full end-to-end lab run.

> **Engine note:** the ProjectDiscovery suite (subfinder, dnsx, httpx, naabu, tlsx, katana,
> nuclei) plus nmap, wafw00f, trufflehog, gau and ffuf are standard, widely-used open-source
> security tools. Orvex orchestrates them behind its scope/rate/authorization controls; it
> does not add novel exploitation capability.
