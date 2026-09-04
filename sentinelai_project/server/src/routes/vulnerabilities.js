import { Router } from 'express'
import { db, newId, audit } from '../db/index.js'
import { requireAuth, requireRole } from '../middleware/auth.js'
import { explainVulnerability, chatAboutVulnerability, isAiConfigured } from '../lib/ai.js'
import { deliverWebhookEvent } from '../lib/webhookDelivery.js'

const router = Router()
router.use(requireAuth)

// Cost guardrails for the two AI-backed endpoints below: each call is a
// real, billed request to the configured provider (Gemini or Anthropic),
// so an unbounded message/history size is an unbounded cost per click.
const MAX_MESSAGE_LENGTH = 2000
const MAX_HISTORY_MESSAGES = 30
const MAX_HISTORY_MESSAGE_LENGTH = 2000

function withAsset(row) {
  if (!row) return row
  const asset = db.prepare('SELECT name, type FROM assets WHERE id = ?').get(row.asset_id)
  return { ...row, asset_name: asset?.name, asset_type: asset?.type }
}

router.get('/', (req, res) => {
  const rows = db
    .prepare('SELECT * FROM vulnerabilities WHERE workspace_id = ? ORDER BY discovered_at DESC')
    .all(req.user.workspace_id)
  res.json({ vulnerabilities: rows.map(withAsset) })
})

router.get('/:id', (req, res) => {
  const row = db
    .prepare('SELECT * FROM vulnerabilities WHERE id = ? AND workspace_id = ?')
    .get(req.params.id, req.user.workspace_id)
  if (!row) return res.status(404).json({ error: 'Vulnerability not found' })
  res.json({ vulnerability: withAsset(row) })
})

// Real AI-generated plain-language explanation (cached onto the row after first call)
// Explicitly open to every authenticated role, including viewer — this is
// read-only (explains an existing finding, changes nothing), so viewers are
// allowed to use it same as admin/analyst. Kept explicit rather than
// implicit so the intent is documented, not just inherited from having no
// requireRole() call at all.
router.post('/:id/explain', requireRole('admin', 'analyst', 'viewer'), async (req, res) => {
  const row = db
    .prepare('SELECT * FROM vulnerabilities WHERE id = ? AND workspace_id = ?')
    .get(req.params.id, req.user.workspace_id)
  if (!row) return res.status(404).json({ error: 'Vulnerability not found' })

  if (row.ai_explanation) return res.json({ explanation: row.ai_explanation, cached: true })

  try {
    const explanation = await explainVulnerability(withAsset(row))
    db.prepare('UPDATE vulnerabilities SET ai_explanation = ? WHERE id = ?').run(explanation, row.id)
    res.json({ explanation, cached: false, aiConfigured: isAiConfigured() })
  } catch (err) {
    res.status(502).json({ error: 'AI explanation failed', detail: String(err.message || err) })
  }
})

// Freeform chat about a specific vulnerability, real Claude/Gemini API call.
// Same explicit all-roles access as /explain, for the same reason — this
// only reads and discusses an existing finding, it never changes anything.
router.post('/:id/chat', requireRole('admin', 'analyst', 'viewer'), async (req, res) => {
  const row = db
    .prepare('SELECT * FROM vulnerabilities WHERE id = ? AND workspace_id = ?')
    .get(req.params.id, req.user.workspace_id)
  if (!row) return res.status(404).json({ error: 'Vulnerability not found' })

  const { message, history } = req.body || {}
  if (!message || typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({ error: 'message is required' })
  }
  if (message.length > MAX_MESSAGE_LENGTH) {
    return res.status(400).json({ error: `message must be ${MAX_MESSAGE_LENGTH} characters or fewer` })
  }

  let safeHistory = []
  if (history !== undefined) {
    if (!Array.isArray(history)) {
      return res.status(400).json({ error: 'history must be an array' })
    }
    if (history.length > MAX_HISTORY_MESSAGES) {
      return res.status(400).json({ error: `history must contain ${MAX_HISTORY_MESSAGES} messages or fewer` })
    }
    for (const entry of history) {
      if (
        !entry ||
        typeof entry.content !== 'string' ||
        entry.content.length > MAX_HISTORY_MESSAGE_LENGTH ||
        !['user', 'assistant'].includes(entry.role)
      ) {
        return res.status(400).json({
          error: `each history entry must have role 'user' or 'assistant' and content up to ${MAX_HISTORY_MESSAGE_LENGTH} characters`,
        })
      }
    }
    safeHistory = history
  }

  try {
    const reply = await chatAboutVulnerability(withAsset(row), safeHistory, message)
    res.json({ reply })
  } catch (err) {
    res.status(502).json({ error: 'AI chat failed', detail: String(err.message || err) })
  }
})

// Human-in-the-loop patch approval — this NEVER auto-executes on a remote
// server. It only records the decision. Real execution against live
// infrastructure would require a signed-off deployment agent, which is out
// of scope for the MVP by design (see proposal: "Absolute Control").
router.post('/:id/patch', requireRole('admin', 'analyst'), (req, res) => {
  const { decision } = req.body || {} // 'approved' | 'rejected'
  if (!['approved', 'rejected'].includes(decision)) {
    return res.status(400).json({ error: "decision must be 'approved' or 'rejected'" })
  }
  const row = db
    .prepare('SELECT * FROM vulnerabilities WHERE id = ? AND workspace_id = ?')
    .get(req.params.id, req.user.workspace_id)
  if (!row) return res.status(404).json({ error: 'Vulnerability not found' })

  const status = decision === 'approved' ? 'Patched' : 'In Review'
  db.prepare('UPDATE vulnerabilities SET status = ? WHERE id = ?').run(status, row.id)

  db.prepare(
    'INSERT INTO notifications (id, workspace_id, title, body, severity) VALUES (?, ?, ?, ?, ?)'
  ).run(
    newId('notif'),
    req.user.workspace_id,
    decision === 'approved' ? 'Patch approved' : 'Patch rejected',
    `${req.user.name} ${decision} the fix for "${row.name}".`,
    row.severity
  )

  audit(req.user.workspace_id, req.user.id, `vulnerability.patch_${decision}`, 'vulnerability', row.id)
  deliverWebhookEvent(req.user.workspace_id, 'patch_decision', {
    vulnerability: { id: row.id, name: row.name, severity: row.severity },
    decision,
    decidedBy: req.user.name,
  }).catch(() => {})

  res.json({ vulnerability: withAsset({ ...row, status }) })
})

router.patch('/:id/status', requireRole('admin', 'analyst'), (req, res) => {
  const { status } = req.body || {}
  if (!['Open', 'In Review', 'Patched'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' })
  }
  const row = db
    .prepare('SELECT * FROM vulnerabilities WHERE id = ? AND workspace_id = ?')
    .get(req.params.id, req.user.workspace_id)
  if (!row) return res.status(404).json({ error: 'Vulnerability not found' })

  db.prepare('UPDATE vulnerabilities SET status = ? WHERE id = ?').run(status, row.id)
  res.json({ vulnerability: withAsset({ ...row, status }) })
})

export default router