# SentinelAI — Backend API

A real Node.js/Express backend for the SentinelAI MVP: authentication, a
scanning engine, AI-powered explanations (via the Claude API), human-in-the-
loop patch approval, and PDF reporting.

## What's real vs. illustrative

| Feature | Status |
|---|---|
| Auth (register/login, bcrypt + JWT, roles) | **Real** |
| Account lockout after repeated failed logins | **Real** — 5 attempts, 15-minute lockout |
| Multi-tenant workspaces (data isolation) | **Real** — covered by an automated test |
| Asset management (add/remove) | **Real** |
| Subdomain/asset discovery | **Real, honestly scoped** — real DNS lookups against common subdomains of a domain you own. Full "find every device on the LAN" discovery as described in the proposal needs an on-prem agent, which is out of scope for a cloud API (see note in `lib/discovery.js`) |
| Vulnerability scanning (HTTP security headers, TLS cert expiry, DNS) | **Real** — passive, non-intrusive checks |
| Exposed secret detection (.env, .git, client-side JS bundles) | **Real** — checks common publicly-exposed paths and scans fetched content for secret-shaped strings (AWS keys, Stripe keys, API tokens, private key blocks, JWTs). Detected secrets are **redacted before they're ever stored or displayed** — only a masked preview (first/last 4 characters) is kept, covered by an automated test asserting the raw value never leaks into the API response. |
| CORS misconfiguration detection | **Real** — flags reflected-origin CORS combined with credentials allowed |
| CVE correlation | **Real, best-effort** — banner-grabs `Server`/`X-Powered-By` headers and queries the free OSV.dev database for known CVEs in a small starter list of software (nginx, Apache, OpenSSL). Extend the table in `lib/scanner.js` to cover more software. |
| Sensitive path/secret exposure scanning | **Real** — checks for commonly-exposed misconfigurations (`.env`, `.git`, database dumps, credential files, debug pages) and scans public HTML/JS for API-key-shaped strings. Every found secret is redacted to first-4/last-4 characters before it's ever stored or displayed — there's an automated test (`secret detection & redaction` suite) that asserts the raw value never appears anywhere in the output. This is passive path-checking, not credential brute-forcing — see the note in `lib/scanner.js` and `lib/secretScanner.js`. |
| Continuous 24/7 monitoring | **Real** — a background scheduler (`lib/scheduler.js`) re-scans every asset with auto-scan enabled on an interval (`SCAN_INTERVAL_MINUTES`, default 60). Trigger it immediately via `POST /api/monitoring/run-now`. Runs in-process; a production deployment at real scale would move this to a job queue (BullMQ/Redis) so scans survive restarts and can be distributed — noted below. |
| AI plain-language explanations & chat | **Real** — calls the Claude API (`ANTHROPIC_API_KEY` required) |
| Human-in-the-loop patch approval | **Real** — records the decision; does **not** execute scripts on remote servers (by design — see "Absolute Control" in the proposal) |
| PDF executive reports | **Real** — generated with `pdfkit` |
| Notifications | **Real** |
| Audit log | **Real** — every login, asset change, and scan is recorded in `audit_log` for accountability |
| API keys for machine-to-machine access | **Real** — a scoped, **read-only** `/api/v1/*` surface (assets, vulnerabilities, summary) for pulling findings into a SIEM, internal dashboard, or script. Raw key shown once at creation, only its hash stored — same principle as passwords. |
| Outbound webhooks | **Real** — pushes signed (HMAC-SHA256) JSON payloads to Slack/PagerDuty/your own endpoint on critical findings, scan completion, or patch decisions. Delivery never blocks or fails the triggering request (fire-and-forget). |
| Compliance readiness mapping (SOC 2 / ISO 27001 / GDPR) | **Real, explicitly scoped as a readiness aid, not a certification** — maps open findings to the control families a real auditor would ask about, and just as importantly, lists what automated scanning *cannot* assess (policy, training, vendor risk, etc.). Included in the PDF report and a dedicated dashboard view. |
| Security hardening | **Real** — `helmet` security headers, rate limiting (global + tighter on auth routes), CORS allowlist via `ALLOWED_ORIGINS`, structured logging (`pino`), fail-fast on missing `JWT_SECRET` in production |
| Automated tests | **Real** — 12 integration tests (`npm test`) covering auth, lockout, data isolation, live scanning, and patch approval against a real in-memory database |
| Attack Path Mapper | **Real data, honestly scoped** — nodes and findings are your actual assets/vulnerabilities, not a script. It shows external attack surface (internet → each asset, colored by real severity) but deliberately does **not** fabricate multi-hop internal pivot chains ("server A → database B"), since that requires real network topology data this build doesn't collect. See the in-app "Scope note." |
| Team invites / billing / plans in Settings | **Illustrative** — no backend yet; this is listed as future roadmap in the proposal |
| Cloud provider scanning (AWS/Azure/GCP config audits) | **Not implemented** — future work. Honestly labeled as "Roadmap" in the Settings UI; earlier this incorrectly showed AWS as "connected" with fabricated resource counts, which has been fixed. |
| Mobile app / push notifications | **Not implemented** — separate codebase (iOS/Android or React Native); out of scope for this backend/web build |

## Requirements

- Node.js 22.5+ (uses the built-in `node:sqlite` module — no native
  compilation needed, which avoids the typical `better-sqlite3` build
  headaches)

## Setup

```bash
cd server
cp .env.example .env
# edit .env: set JWT_SECRET to a long random string, and ANTHROPIC_API_KEY
# if you want real AI explanations (get one at console.anthropic.com)
npm install
npm run start
```

The API listens on `http://localhost:4000` by default. Health check:

```bash
curl http://localhost:4000/api/health
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PORT` | no (default 4000) | Port the API listens on |
| `JWT_SECRET` | **yes** | Secret used to sign session tokens — use a long random string in production |
| `ANTHROPIC_API_KEY` | no | Enables real AI explanations/chat. Without it, the AI endpoints return a clear fallback message instead of failing. |
| `ANTHROPIC_MODEL` | no (default `claude-sonnet-5`) | Model used for AI explanations |
| `DB_PATH` | no | Override the SQLite file location (defaults to `server/data/sentinelai.db`) |

## API overview

All routes except `/api/auth/register` and `/api/auth/login` require
`Authorization: Bearer <token>`.

- `POST /api/auth/register` — create a user + new workspace
- `POST /api/auth/login`
- `GET  /api/auth/me`
- `GET/POST/DELETE /api/assets`
- `POST /api/scans/assets/:assetId` — run a real scan against an asset
- `GET  /api/vulnerabilities`, `GET /api/vulnerabilities/:id`
- `POST /api/vulnerabilities/:id/explain` — AI plain-language explanation
- `POST /api/vulnerabilities/:id/chat` — AI chat about a specific finding
- `POST /api/vulnerabilities/:id/patch` — approve/reject a fix (`{ decision: 'approved' | 'rejected' }`)
- `PATCH /api/vulnerabilities/:id/status`
- `GET/PATCH /api/notifications`
- `GET /api/reports/summary`, `GET /api/reports/pdf`

## Scanning engine — what it actually checks

`src/lib/scanner.js` performs **passive, non-intrusive** checks against a
target hostname/URL you register as an asset:

1. **DNS resolution** — is the hostname resolvable at all?
2. **HTTP security headers** — checks for `Strict-Transport-Security`,
   `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`
3. **TLS certificate health** — flags certificates that are expired or
   expiring within 21 days

This intentionally avoids anything exploit-like (no credential
brute-forcing, no payload injection, no port sweeps). It's a legitimate,
extensible starting point — production security tools like Mozilla
Observatory or SSL Labs work the same way. You only add assets you're
authorized to scan.

### Why there's no brute-forcing or active exploitation

A natural next request for a tool like this is "add real penetration
testing" — actively trying to break in (password brute-forcing, exploiting
the CVEs it finds, injection attacks). This build deliberately does not do
that, and it's not a matter of not getting around to it yet:

- **It's the same code either way.** A brute-forcer that "only tests
  assets you own" is functionally identical to one that attacks anyone
  else's site — there's no technical way to enforce the "own assets only"
  boundary in the tool itself.
- **Your own proposal already has the right model for this**: the
  "Professional Services" tier delegates active testing to a licensed
  human pentester, which is how real vulnerability-management products
  (Tenable, Rapid7, Qualys) handle it too — automated *passive* scanning,
  human-led *active* testing.
- **Passive scanning already covers a lot of real risk.** Most real-world
  breaches of AI-assisted/vibe-coded apps come from exposed secrets and
  misconfiguration (a `.env` file left public, an API key pasted into
  frontend JS, wildcard CORS) — not from weak passwords. That's exactly
  what the exposed-secret and misconfiguration checks above cover.

## Running the tests

```bash
cd server
npm test
```

12 integration tests run against a real in-memory database and a live
(unbound) instance of the actual Express app — not mocks. They cover
registration/login, account lockout, multi-tenant data isolation, a real
scan against a live host, and the patch-approval workflow.

## Passive scanning vs. penetration testing — an intentional line

SentinelAI's scanner is entirely **passive**: it reads headers, checks
certificate expiry, requests well-known paths to see if they respond, and
reads public HTML/JS for secret-shaped strings. It never attempts to
exploit anything, guess credentials, or bypass authentication. This is a
deliberate design boundary, not a missing feature — the "Professional
Services" tier in the business model (§7 of the proposal) is where
human-led, licensed penetration testing belongs. A tool that autonomously
attempts exploitation is a fundamentally different (and far riskier)
product than one that reports "this door appears unlocked."

## Is this "production ready for a company like Amazon"?

No, and it's worth being direct about that rather than overselling it.
This build closes the gaps in the 3-month MVP scope described in the
proposal (continuous monitoring, discovery, CVE correlation, hardening,
tests) and adds genuine production-hardening basics. But "production ready
for enterprise customers" is a much higher bar that would additionally
need, at minimum:

- A third-party security audit / penetration test
- SOC 2 (or similar) compliance work — audit trails exist now, but formal
  compliance requires a lot more (data retention policies, access reviews,
  vendor risk assessments, etc.)
- A move from SQLite to a managed, replicated database (Postgres) for
  real multi-tenant scale and durability
- Horizontal scaling: the scan scheduler currently runs in-process; at
  scale this needs a real job queue (BullMQ/Redis or similar) so scans
  survive restarts and distribute across workers
- Enterprise auth: SSO/SAML, MFA, IP allowlisting
- Uptime monitoring, on-call rotation, and an SLA — none of which are code,
  they're organizational commitments
- Legal review of the scanning functionality's terms of use (only ever
  scan assets you're authorized to test)

None of that is a knock on the MVP — it's simply a different, much larger
project. This build is a solid, honestly-scoped foundation for the next
phase.

## Deployment

**Backend**: any Node 22+ host works (Render, Railway, Fly.io, a VPS).
The SQLite file needs persistent disk — on platforms with ephemeral
filesystems, mount a persistent volume at the path set in `DB_PATH`, or
swap in Postgres later (the `db/index.js` module is the only file that
would need to change).

**Frontend**: static hosting (Vercel, Netlify, Cloudflare Pages) after
`npm run build`. Set `VITE_API_URL` to your deployed backend's URL before
building.

```bash
# frontend
VITE_API_URL=https://your-backend.example.com npm run build
```

Don't forget to set `JWT_SECRET` and `ANTHROPIC_API_KEY` as environment
variables on your backend host — never commit `.env`.
