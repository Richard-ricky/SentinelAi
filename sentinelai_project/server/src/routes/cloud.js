import { Router } from 'express'
import { db, newId, audit } from '../db/index.js'
import { requireAuth, requireRole } from '../middleware/auth.js'
import { encryptSecret, decryptSecret } from '../lib/crypto.js'
import { createS3Client, verifyCredentials, scanS3Buckets } from '../lib/awsScanner.js'
import { deliverWebhookEvent } from '../lib/webhookDelivery.js'

const router = Router()
router.use(requireAuth)

function safe(conn) {
  const { encrypted_secret, ...rest } = conn
  // Never return the access key ID in full either — just enough to confirm identity.
  return { ...rest, access_key_id: `${conn.access_key_id.slice(0, 4)}${'•'.repeat(12)}` }
}

router.get('/', (req, res) => {
  const connections = db
    .prepare('SELECT * FROM cloud_connections WHERE workspace_id = ?')
    .all(req.user.workspace_id)
  res.json({ connections: connections.map(safe) })
})

router.post('/aws/connect', requireRole('admin'), async (req, res) => {
  const { accessKeyId, secretAccessKey, region, label } = req.body || {}
  if (!accessKeyId || !secretAccessKey) {
    return res.status(400).json({ error: 'accessKeyId and secretAccessKey are required' })
  }

  // Fail fast: verify the credentials actually work before storing anything.
  // A least-privilege, read-only IAM user is strongly recommended — this
  // call only needs s3:ListAllMyBuckets to succeed.
  const client = createS3Client({ accessKeyId, secretAccessKey, region })
  try {
    await verifyCredentials(client)
  } catch (err) {
    return res.status(400).json({
      error: 'Could not verify these AWS credentials.',
      detail: err.name === 'AccessDenied'
        ? 'The credentials are valid but lack s3:ListAllMyBuckets permission.'
        : String(err.message || err.name || err),
    })
  }

  const existing = db
    .prepare("SELECT id FROM cloud_connections WHERE workspace_id = ? AND provider = 'aws'")
    .get(req.user.workspace_id)

  const encrypted = encryptSecret(secretAccessKey)

  if (existing) {
    db.prepare(
      'UPDATE cloud_connections SET access_key_id = ?, encrypted_secret = ?, region = ?, label = ?, connected_by = ? WHERE id = ?'
    ).run(accessKeyId, encrypted, region || 'us-east-1', label || null, req.user.id, existing.id)
  } else {
    db.prepare(
      'INSERT INTO cloud_connections (id, workspace_id, provider, label, access_key_id, encrypted_secret, region, connected_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(newId('cloud'), req.user.workspace_id, 'aws', label || null, accessKeyId, encrypted, region || 'us-east-1', req.user.id)
  }

  audit(req.user.workspace_id, req.user.id, 'cloud.aws_connected', 'cloud_connection', accessKeyId.slice(0, 8))

  const conn = db
    .prepare("SELECT * FROM cloud_connections WHERE workspace_id = ? AND provider = 'aws'")
    .get(req.user.workspace_id)
  res.status(201).json({ connection: safe(conn) })
})

router.delete('/aws', requireRole('admin'), (req, res) => {
  const conn = db
    .prepare("SELECT * FROM cloud_connections WHERE workspace_id = ? AND provider = 'aws'")
    .get(req.user.workspace_id)
  if (!conn) return res.status(404).json({ error: 'No AWS connection found' })

  db.prepare('DELETE FROM cloud_connections WHERE id = ?').run(conn.id)
  audit(req.user.workspace_id, req.user.id, 'cloud.aws_disconnected', 'cloud_connection', conn.id)
  res.json({ ok: true })
})

router.post('/aws/scan', requireRole('admin', 'analyst'), async (req, res) => {
  const conn = db
    .prepare("SELECT * FROM cloud_connections WHERE workspace_id = ? AND provider = 'aws'")
    .get(req.user.workspace_id)
  if (!conn) return res.status(404).json({ error: 'No AWS account connected. Connect one first.' })

  let secretAccessKey
  try {
    secretAccessKey = decryptSecret(conn.encrypted_secret)
  } catch {
    return res.status(500).json({
      error: 'Could not decrypt stored AWS credentials — this usually means CREDENTIAL_ENCRYPTION_KEY changed since they were saved. Reconnect the account.',
    })
  }

  const client = createS3Client({ accessKeyId: conn.access_key_id, secretAccessKey, region: conn.region })
  // Passed through so awsScanner.js can build a region-specific client when
  // a bucket lives outside the account's default region — without this,
  // cross-region ACL/policy checks fail and get correctly reported as
  // "inconclusive" rather than silently as "safe," but we'd rather they
  // succeed outright when we have the credentials to make that possible.
  const credentials = { accessKeyId: conn.access_key_id, secretAccessKey }

  // Findings need a home in the existing vulnerabilities table, so we
  // represent the connected AWS account as a synthetic "cloud" asset —
  // this lets AWS findings show up in the same dashboard, reports, and
  // webhooks as every other finding, with no special-casing on the frontend.
  let asset = db
    .prepare("SELECT * FROM assets WHERE workspace_id = ? AND type = 'cloud' AND target = ?")
    .get(req.user.workspace_id, `aws:${conn.access_key_id}`)
  if (!asset) {
    const assetId = newId('asset')
    db.prepare(
      "INSERT INTO assets (id, workspace_id, name, type, target, added_by, discovered_via) VALUES (?, ?, ?, 'cloud', ?, ?, 'cloud-connection')"
    ).run(assetId, req.user.workspace_id, conn.label || 'AWS Account', `aws:${conn.access_key_id}`, req.user.id)
    asset = db.prepare('SELECT * FROM assets WHERE id = ?').get(assetId)
  }

  try {
    const findings = await scanS3Buckets(client, credentials)

    // Clear previous open AWS findings for this asset before inserting
    // fresh ones, so a fixed bucket doesn't linger forever as "open."
    db.prepare("DELETE FROM vulnerabilities WHERE asset_id = ? AND status != 'Patched'").run(asset.id)

    const insertVuln = db.prepare(`
      INSERT INTO vulnerabilities (id, workspace_id, asset_id, name, severity, category, description, impact, fix, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open')
    `)
    const createdIds = []
    for (const f of findings) {
      const id = newId('vuln')
      insertVuln.run(id, req.user.workspace_id, asset.id, f.name, f.severity, f.category, f.description, f.impact, f.fix)
      createdIds.push(id)
    }

    db.prepare("UPDATE cloud_connections SET last_scanned_at = datetime('now') WHERE id = ?").run(conn.id)
    audit(req.user.workspace_id, req.user.id, 'cloud.aws_scanned', 'cloud_connection', conn.id, { findings: findings.length })

    const criticalCount = findings.filter((f) => f.severity === 'Critical').length
    if (criticalCount > 0) {
      db.prepare(
        'INSERT INTO notifications (id, workspace_id, title, body, severity) VALUES (?, ?, ?, ?, ?)'
      ).run(
        newId('notif'),
        req.user.workspace_id,
        `Critical AWS exposure found`,
        `Your AWS scan found ${criticalCount} publicly exposed S3 bucket(s) with write access. Review immediately.`,
        'Critical'
      )
      deliverWebhookEvent(req.user.workspace_id, 'critical_finding', {
        asset: { id: asset.id, name: asset.name },
        findings: findings.filter((f) => f.severity === 'Critical'),
      }).catch(() => {})
    }

    const vulnerabilities = createdIds.map((id) => db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(id))
    res.json({ findingCount: findings.length, vulnerabilities })
  } catch (err) {
    res.status(502).json({ error: 'AWS scan failed', detail: String(err.message || err.name || err) })
  }
})

export default router