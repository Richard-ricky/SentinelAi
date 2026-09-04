import { Router } from 'express'
import { db, newId, audit } from '../db/index.js'
import { requireAuth, requireRole } from '../middleware/auth.js'
import { discoverSubdomains } from '../lib/discovery.js'

const router = Router()
router.use(requireAuth)

router.get('/', (req, res) => {
  const assets = db
    .prepare('SELECT * FROM assets WHERE workspace_id = ? ORDER BY created_at DESC')
    .all(req.user.workspace_id)
  res.json({ assets })
})

router.post('/', requireRole('admin', 'analyst'), (req, res) => {
  const { name, type, target } = req.body || {}
  if (!name || !type || !target) {
    return res.status(400).json({ error: 'name, type, and target are required' })
  }
  const id = newId('asset')
  db.prepare(
    'INSERT INTO assets (id, workspace_id, name, type, target, added_by, discovered_via) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(id, req.user.workspace_id, name, type, target, req.user.id, 'manual')

  db.prepare(
    'INSERT INTO notifications (id, workspace_id, title, body, severity) VALUES (?, ?, ?, ?, ?)'
  ).run(
    newId('notif'),
    req.user.workspace_id,
    'New asset added',
    `${name} was added to asset discovery by ${req.user.name}. Run a scan to check its security posture.`,
    'Info'
  )
  audit(req.user.workspace_id, req.user.id, 'asset.created', 'asset', id, { name, target })

  const asset = db.prepare('SELECT * FROM assets WHERE id = ?').get(id)
  res.status(201).json({ asset })
})

// Real DNS-based subdomain discovery against a domain the user already
// owns/added. Returns candidates for the user to review and add — it does
// not auto-add them, keeping a human in the loop for what gets monitored.
router.post('/discover', requireRole('admin', 'analyst'), async (req, res) => {
  const { domain } = req.body || {}
  if (!domain) return res.status(400).json({ error: 'domain is required' })
  try {
    const found = await discoverSubdomains(domain)
    res.json({ candidates: found })
  } catch (err) {
    res.status(502).json({ error: 'Discovery failed', detail: String(err.message || err) })
  }
})

router.patch('/:id/auto-scan', requireRole('admin', 'analyst'), (req, res) => {
  const { enabled } = req.body || {}
  const asset = db
    .prepare('SELECT * FROM assets WHERE id = ? AND workspace_id = ?')
    .get(req.params.id, req.user.workspace_id)
  if (!asset) return res.status(404).json({ error: 'Asset not found' })

  db.prepare('UPDATE assets SET auto_scan_enabled = ? WHERE id = ?').run(enabled ? 1 : 0, asset.id)
  res.json({ asset: db.prepare('SELECT * FROM assets WHERE id = ?').get(asset.id) })
})

router.delete('/:id', requireRole('admin'), (req, res) => {
  const asset = db
    .prepare('SELECT * FROM assets WHERE id = ? AND workspace_id = ?')
    .get(req.params.id, req.user.workspace_id)
  if (!asset) return res.status(404).json({ error: 'Asset not found' })

  db.prepare('DELETE FROM vulnerabilities WHERE asset_id = ?').run(asset.id)
  db.prepare('DELETE FROM scans WHERE asset_id = ?').run(asset.id)
  db.prepare('DELETE FROM assets WHERE id = ?').run(asset.id)
  audit(req.user.workspace_id, req.user.id, 'asset.deleted', 'asset', asset.id)
  res.json({ ok: true })
})

export default router
