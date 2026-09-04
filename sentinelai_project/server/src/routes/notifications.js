import { Router } from 'express'
import { db } from '../db/index.js'
import { requireAuth } from '../middleware/auth.js'

const router = Router()
router.use(requireAuth)

router.get('/', (req, res) => {
  const rows = db
    .prepare('SELECT * FROM notifications WHERE workspace_id = ? ORDER BY created_at DESC LIMIT 100')
    .all(req.user.workspace_id)
  res.json({ notifications: rows })
})

router.patch('/:id/read', (req, res) => {
  db.prepare('UPDATE notifications SET read = 1 WHERE id = ? AND workspace_id = ?').run(
    req.params.id,
    req.user.workspace_id
  )
  res.json({ ok: true })
})

router.post('/read-all', (req, res) => {
  db.prepare('UPDATE notifications SET read = 1 WHERE workspace_id = ?').run(req.user.workspace_id)
  res.json({ ok: true })
})

export default router
