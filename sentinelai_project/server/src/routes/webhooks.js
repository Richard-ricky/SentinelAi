import { Router } from 'express'
import crypto from 'node:crypto'
import { db, newId, audit } from '../db/index.js'
import { requireAuth, requireRole } from '../middleware/auth.js'
import { deliverTestEvent } from '../lib/webhookDelivery.js'

const router = Router()
router.use(requireAuth)

const VALID_EVENTS = ['critical_finding', 'patch_decision', 'scan_completed']

function safe(webhook) {
  const { secret, ...rest } = webhook
  return { ...rest, secretPreview: `${secret.slice(0, 6)}${'•'.repeat(10)}` }
}

router.get('/', (req, res) => {
  const webhooks = db
    .prepare('SELECT * FROM webhooks WHERE workspace_id = ? ORDER BY created_at DESC')
    .all(req.user.workspace_id)
  res.json({ webhooks: webhooks.map(safe) })
})

router.post('/', requireRole('admin'), (req, res) => {
  const { url, events } = req.body || {}
  if (!url) return res.status(400).json({ error: 'url is required' })
  try {
    new URL(url)
  } catch {
    return res.status(400).json({ error: 'url must be a valid URL' })
  }

  const eventList = Array.isArray(events) && events.length ? events.filter((e) => VALID_EVENTS.includes(e)) : ['critical_finding']
  const secret = crypto.randomBytes(24).toString('hex')
  const id = newId('wh')

  db.prepare(
    'INSERT INTO webhooks (id, workspace_id, url, secret, events) VALUES (?, ?, ?, ?, ?)'
  ).run(id, req.user.workspace_id, url, secret, eventList.join(','))

  audit(req.user.workspace_id, req.user.id, 'webhook.created', 'webhook', id, { url })

  const webhook = db.prepare('SELECT * FROM webhooks WHERE id = ?').get(id)
  // Secret is only ever returned in full at creation time — used to verify
  // the HMAC signature on delivered payloads. Store it in your receiver now.
  res.status(201).json({ webhook: safe(webhook), secret })
})

router.post('/:id/test', requireRole('admin'), async (req, res) => {
  const webhook = db
    .prepare('SELECT * FROM webhooks WHERE id = ? AND workspace_id = ?')
    .get(req.params.id, req.user.workspace_id)
  if (!webhook) return res.status(404).json({ error: 'Webhook not found' })

  await deliverTestEvent(webhook)

  const updated = db.prepare('SELECT * FROM webhooks WHERE id = ?').get(webhook.id)
  res.json({ webhook: safe(updated) })
})

router.delete('/:id', requireRole('admin'), (req, res) => {
  const webhook = db
    .prepare('SELECT * FROM webhooks WHERE id = ? AND workspace_id = ?')
    .get(req.params.id, req.user.workspace_id)
  if (!webhook) return res.status(404).json({ error: 'Webhook not found' })

  db.prepare('DELETE FROM webhooks WHERE id = ?').run(webhook.id)
  audit(req.user.workspace_id, req.user.id, 'webhook.deleted', 'webhook', webhook.id)
  res.json({ ok: true })
})

export default router
