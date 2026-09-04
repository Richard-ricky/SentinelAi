import { Router } from 'express'
import { db } from '../db/index.js'
import { requireApiKey } from '../middleware/auth.js'

// A stable, read-only, versioned surface for enterprise integrations —
// SIEMs, internal dashboards, or scripts pulling findings on a schedule.
// Deliberately separate from the human-facing dashboard API: no mutation
// endpoints live here, so a leaked integration key can only ever read.
const router = Router()
router.use(requireApiKey)

router.get('/vulnerabilities', (req, res) => {
  const { severity, status } = req.query
  let sql = 'SELECT * FROM vulnerabilities WHERE workspace_id = ?'
  const params = [req.workspaceId]
  if (severity) {
    sql += ' AND severity = ?'
    params.push(severity)
  }
  if (status) {
    sql += ' AND status = ?'
    params.push(status)
  }
  sql += ' ORDER BY discovered_at DESC LIMIT 500'

  const rows = db.prepare(sql).all(...params)
  res.json({ vulnerabilities: rows })
})

router.get('/assets', (req, res) => {
  const rows = db.prepare('SELECT * FROM assets WHERE workspace_id = ?').all(req.workspaceId)
  res.json({ assets: rows })
})

router.get('/summary', (req, res) => {
  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE workspace_id = ?').all(req.workspaceId)
  const open = vulns.filter((v) => v.status !== 'Patched')
  const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  for (const v of open) bySeverity[v.severity] = (bySeverity[v.severity] || 0) + 1
  res.json({ openVulnerabilities: open.length, bySeverity })
})

export default router
