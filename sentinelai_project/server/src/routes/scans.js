import { Router } from 'express'
import { db, newId, audit } from '../db/index.js'
import { requireAuth, requireRole } from '../middleware/auth.js'
import { runScan } from '../lib/scanner.js'
import { deliverWebhookEvent } from '../lib/webhookDelivery.js'

const router = Router()
router.use(requireAuth)

// Kick off a scan against one asset. Runs synchronously and returns findings —
// for a production deployment this would be queued to a background worker,
// but for MVP scale a direct await keeps the architecture simple.
router.post('/assets/:assetId', requireRole('admin', 'analyst'), async (req, res) => {
  const asset = db
    .prepare('SELECT * FROM assets WHERE id = ? AND workspace_id = ?')
    .get(req.params.assetId, req.user.workspace_id)
  if (!asset) return res.status(404).json({ error: 'Asset not found' })

  const scanId = newId('scan')
  db.prepare(
    'INSERT INTO scans (id, workspace_id, asset_id, status) VALUES (?, ?, ?, ?)'
  ).run(scanId, req.user.workspace_id, asset.id, 'running')

  try {
    const result = await runScan(asset)

    // Clear previous open findings for this asset before inserting fresh
    // ones from this scan, mirroring the AWS cloud-scan route. Without
    // this, re-scanning the same asset repeatedly (e.g. clicking "↻ scan"
    // after fixing something, or on a recurring monitoring schedule) just
    // keeps stacking near-duplicate rows for the same underlying issue —
    // "Missing HSTS header" would get re-inserted every single scan
    // instead of the dashboard reflecting current reality. Patched
    // findings are preserved as your audit trail, exactly as before.
    db.prepare("DELETE FROM vulnerabilities WHERE asset_id = ? AND status != 'Patched'").run(asset.id)

    const insertVuln = db.prepare(`
      INSERT INTO vulnerabilities
        (id, workspace_id, asset_id, scan_id, name, severity, category, cve, description, impact, fix, script, redacted_preview, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open')
    `)
    const created = []
    for (const v of result.vulnerabilities) {
      const id = newId('vuln')
      insertVuln.run(
        id,
        req.user.workspace_id,
        asset.id,
        scanId,
        v.name,
        v.severity,
        v.category,
        v.cve || null,
        v.description,
        v.impact,
        v.fix,
        v.script,
        v.redactedPreview || null
      )
      created.push(id)
    }

    const criticalFindings = created
      .map((id) => db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(id))
      .filter((v) => v.severity === 'Critical')

    if (criticalFindings.length > 0) {
      db.prepare(
        'INSERT INTO notifications (id, workspace_id, title, body, severity) VALUES (?, ?, ?, ?, ?)'
      ).run(
        newId('notif'),
        req.user.workspace_id,
        `Critical risk found on ${asset.name}`,
        'A newly completed scan surfaced a critical-severity finding. Review and approve a fix as soon as possible.',
        'Critical'
      )

      // Deliberately fire-and-forget: a slow or failing webhook receiver
      // must never delay or break the scan response the user is waiting on.
      deliverWebhookEvent(req.user.workspace_id, 'critical_finding', {
        asset: { id: asset.id, name: asset.name, target: asset.target },
        findings: criticalFindings.map((v) => ({ id: v.id, name: v.name, severity: v.severity, category: v.category })),
      }).catch(() => {})
    }

    const summary = `${result.vulnerabilities.length} finding(s) — DNS resolved: ${result.dnsResolved}, reachable: ${result.reachable}`
    db.prepare(
      "UPDATE scans SET status = 'completed', completed_at = datetime('now'), summary = ? WHERE id = ?"
    ).run(summary, scanId)
    db.prepare("UPDATE assets SET last_scanned_at = datetime('now') WHERE id = ?").run(asset.id)
    audit(req.user.workspace_id, req.user.id, 'scan.completed', 'asset', asset.id, { findings: result.vulnerabilities.length })

    deliverWebhookEvent(req.user.workspace_id, 'scan_completed', {
      asset: { id: asset.id, name: asset.name },
      findingCount: result.vulnerabilities.length,
    }).catch(() => {})

    const vulnerabilities = db
      .prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?')
      .all(scanId)

    res.json({ scan: { id: scanId, status: 'completed', summary }, vulnerabilities })
  } catch (err) {
    db.prepare("UPDATE scans SET status = 'failed', completed_at = datetime('now'), summary = ? WHERE id = ?").run(
      String(err.message || err),
      scanId
    )
    res.status(500).json({ error: 'Scan failed', detail: String(err.message || err) })
  }
})

router.get('/', requireAuth, (req, res) => {
  const scans = db
    .prepare('SELECT * FROM scans WHERE workspace_id = ? ORDER BY started_at DESC LIMIT 50')
    .all(req.user.workspace_id)
  res.json({ scans })
})

export default router