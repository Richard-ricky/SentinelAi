import { Router } from 'express'
import { db, newId, audit } from '../db/index.js'
import { requireAuth, requireRole } from '../middleware/auth.js'
import { generateApiKey } from '../lib/apiKeys.js'

const router = Router()
router.use(requireAuth)

function safe(key) {
  const { key_hash, ...rest } = key
  return rest
}

router.get('/', (req, res) => {
  const keys = db
    .prepare('SELECT * FROM api_keys WHERE workspace_id = ? ORDER BY created_at DESC')
    .all(req.user.workspace_id)
  res.json({ apiKeys: keys.map(safe) })
})

router.post('/', requireRole('admin'), (req, res) => {
  const { name } = req.body || {}
  if (!name) return res.status(400).json({ error: 'name is required' })

  const { raw, hash, prefix } = generateApiKey()
  const id = newId('key')
  db.prepare(
    'INSERT INTO api_keys (id, workspace_id, name, key_hash, key_prefix, created_by) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(id, req.user.workspace_id, name, hash, prefix, req.user.id)

  audit(req.user.workspace_id, req.user.id, 'api_key.created', 'api_key', id, { name })

  const key = db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id)
  // The raw key is returned exactly once — the server never stores or
  // displays it again after this response.
  res.status(201).json({ apiKey: safe(key), rawKey: raw })
})

router.delete('/:id', requireRole('admin'), (req, res) => {
  const key = db
    .prepare('SELECT * FROM api_keys WHERE id = ? AND workspace_id = ?')
    .get(req.params.id, req.user.workspace_id)
  if (!key) return res.status(404).json({ error: 'API key not found' })

  db.prepare("UPDATE api_keys SET revoked_at = datetime('now') WHERE id = ?").run(key.id)
  audit(req.user.workspace_id, req.user.id, 'api_key.revoked', 'api_key', key.id)
  res.json({ ok: true })
})

export default router
