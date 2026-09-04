import { DatabaseSync } from 'node:sqlite'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import fs from 'node:fs'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const DATA_DIR = path.join(__dirname, '..', '..', 'data')
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true })

const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'sentinelai.db')
export const db = new DatabaseSync(DB_PATH === ':memory:' ? ':memory:' : DB_PATH)

db.exec(`
  PRAGMA journal_mode = WAL;

  CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin', -- admin | analyst | viewer
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    type TEXT NOT NULL, -- website | server | endpoint | database | cloud
    target TEXT NOT NULL, -- hostname/URL/IP that scans run against
    added_by TEXT,
    auto_scan_enabled INTEGER NOT NULL DEFAULT 1,
    last_scanned_at TEXT,
    discovered_via TEXT, -- 'manual' | 'subdomain-discovery'
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    asset_id TEXT NOT NULL REFERENCES assets(id),
    status TEXT NOT NULL DEFAULT 'running', -- running | completed | failed
    trigger TEXT NOT NULL DEFAULT 'manual', -- manual | scheduled
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    summary TEXT
  );

  CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    asset_id TEXT NOT NULL REFERENCES assets(id),
    scan_id TEXT REFERENCES scans(id),
    name TEXT NOT NULL,
    severity TEXT NOT NULL, -- Low | Medium | High | Critical
    category TEXT NOT NULL,
    cve TEXT,
    description TEXT,
    impact TEXT,
    fix TEXT,
    script TEXT,
    redacted_preview TEXT,
    status TEXT NOT NULL DEFAULT 'Open', -- Open | In Review | Patched
    discovered_at TEXT NOT NULL DEFAULT (datetime('now')),
    ai_explanation TEXT
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    title TEXT NOT NULL,
    body TEXT,
    severity TEXT,
    read INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Audit log: who did what, for accountability and compliance readiness.
  CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    user_id TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Machine-to-machine API keys, separate from human JWT sessions. Lets
  -- enterprise customers pull findings into their own SIEM/dashboards
  -- without a human logging in. The raw key is only ever shown once, at
  -- creation time — only its hash is stored, same principle as passwords.
  CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL, -- first 12 chars shown in the UI so admins can tell keys apart, e.g. "sk_live_a1b2"
    created_by TEXT,
    last_used_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Outbound webhooks — push critical findings into Slack, a SIEM, or a
  -- ticketing system's inbound-webhook endpoint, instead of requiring the
  -- customer to poll the API or watch the dashboard.
  CREATE TABLE IF NOT EXISTS webhooks (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    url TEXT NOT NULL,
    secret TEXT NOT NULL, -- used to HMAC-sign delivered payloads so the receiver can verify authenticity
    events TEXT NOT NULL DEFAULT 'critical_finding', -- comma-separated event types
    enabled INTEGER NOT NULL DEFAULT 1,
    last_delivery_at TEXT,
    last_delivery_status TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- MSP / enterprise multi-org support: a parent workspace can oversee
  -- several child workspaces (e.g. an MSP's individual clients, or an
  -- enterprise's separate business units) with strict data isolation
  -- maintained at the query level — parents get an aggregate view, never
  -- direct read access to a child's underlying records.
  CREATE TABLE IF NOT EXISTS workspace_relations (
    id TEXT PRIMARY KEY,
    parent_workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    child_workspace_id TEXT NOT NULL REFERENCES workspaces(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(parent_workspace_id, child_workspace_id)
  );
`)

export function audit(workspaceId, userId, action, targetType, targetId, metadata) {
  db.prepare(
    'INSERT INTO audit_log (id, workspace_id, user_id, action, target_type, target_id, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(newId('audit'), workspaceId, userId, action, targetType || null, targetId || null, metadata ? JSON.stringify(metadata) : null)
}

export function newId(prefix) {
  return `${prefix}_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`
}
