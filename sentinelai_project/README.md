# SentinelAI

An AI-powered cybersecurity platform for SMEs, schools, and startups —
continuous monitoring, plain-language vulnerability explanations, and
human-approved remediation. See `PROJECT_PROPOSAL.pdf` for the full product
vision.

This repo has two parts:

```
sentinelai_project/
├── src/            ← React + Vite + Tailwind frontend
└── server/          ← Node/Express backend (API, auth, scanner, AI, PDF)
```

## Quick start (local dev)

**1. Backend**

```bash
cd server
cp .env.example .env
# set JWT_SECRET; optionally set ANTHROPIC_API_KEY for real AI explanations
npm install
npm run start
```

Runs on `http://localhost:4000`.

**2. Frontend** (in a second terminal, from the project root)

```bash
npm install
npm run dev
```

Runs on `http://localhost:5173` (or whatever port your environment maps).
The frontend talks to `http://localhost:4000` by default — override with a
`VITE_API_URL` env var if your backend runs elsewhere.

**3. Use it**

Open the frontend, click "New here? Create a workspace," register an
account, then in the Vulnerabilities tab click **+ Add asset** and give it
a real hostname you're authorized to scan (e.g. your own site). Click
**scan** — SentinelAI will run real passive checks (HTTP security headers,
TLS certificate expiry, DNS) and populate real findings you can click into,
ask the AI assistant about, and approve/reject fixes for.

## What's implemented vs. what's still a demo

See `server/README.md` for the full breakdown. Short version: auth,
scanning, AI explanations/chat, patch approval, PDF reports, and
notifications are real and backend-driven. The Attack Path Mapper's graph
and the team/billing panels in Settings remain illustrative — they're
listed as later-phase work in the original proposal (multi-tenant
dashboard, compliance auditing, SaaS billing).

## Tech stack

- **Frontend**: React 19, Vite, Tailwind CSS v4, Recharts
- **Backend**: Express 5, Node's built-in `node:sqlite` (no native build
  step), JWT auth, bcrypt, pdfkit
- **AI**: Anthropic Claude API (`@anthropic-ai/sdk`)

## Known limitations (be upfront about these in your writeup/demo)

- Scanning is passive/header-based, not a full vulnerability database
  scanner (no CVE database integration yet — that's realistic scope for a
  3-month MVP but worth naming explicitly).
- No email verification or password-reset flow yet.
- No real-time/scheduled background scanning — scans run on demand when
  you click "scan." A production version would add a job queue and cron.
- SQLite is fine for an MVP/demo; a multi-tenant production deployment
  would move to Postgres.
