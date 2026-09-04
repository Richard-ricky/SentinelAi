import { Router } from 'express'
import crypto from 'node:crypto'
import bcrypt from 'bcryptjs'
import { db, newId, audit } from '../db/index.js'
import { requireAuth, requireRole } from '../middleware/auth.js'

const router = Router()
router.use(requireAuth)

const VALID_ROLES = ['admin', 'analyst', 'viewer']

function safe(user) {
  const { password_hash, failed_login_attempts, locked_until, ...rest } = user
  return rest
}

router.get('/', (req, res) => {
  const members = db
    .prepare('SELECT * FROM users WHERE workspace_id = ? ORDER BY created_at ASC')
    .all(req.user.workspace_id)
  res.json({ members: members.map(safe) })
})

// Admin adds a teammate directly. There's no email/SMTP configured in this
// MVP, so instead of a real email invite link, we generate a temporary
// password and return it once — the admin shares it with the teammate
// out-of-band (Slack, in person, etc.), same one-time-reveal pattern used
// for API keys and webhook secrets elsewhere in this app.
router.post('/invite', requireRole('admin'), (req, res) => {
  const { name, email, role } = req.body || {}
  if (!name || !email || !role) {
    return res.status(400).json({ error: 'name, email, and role are required' })
  }
  if (!VALID_ROLES.includes(role)) {
    return res.status(400).json({ error: `role must be one of: ${VALID_ROLES.join(', ')}` })
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase())
  if (existing) return res.status(409).json({ error: 'A user with that email already exists' })

  const tempPassword = crypto.randomBytes(9).toString('base64url') // e.g. "k3f9-Xz2p-Qw8r" style, url-safe
  const passwordHash = bcrypt.hashSync(tempPassword, 10)
  const userId = newId('usr')

  db.prepare(
    'INSERT INTO users (id, workspace_id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(userId, req.user.workspace_id, name, email.toLowerCase(), passwordHash, role)

  audit(req.user.workspace_id, req.user.id, 'team.member_invited', 'user', userId, { email, role })

  const member = db.prepare('SELECT * FROM users WHERE id = ?').get(userId)
  res.status(201).json({ member: safe(member), tempPassword })
})

router.patch('/:userId/role', requireRole('admin'), (req, res) => {
  const { role } = req.body || {}
  if (!VALID_ROLES.includes(role)) {
    return res.status(400).json({ error: `role must be one of: ${VALID_ROLES.join(', ')}` })
  }

  const target = db
    .prepare('SELECT * FROM users WHERE id = ? AND workspace_id = ?')
    .get(req.params.userId, req.user.workspace_id)
  if (!target) return res.status(404).json({ error: 'Team member not found' })

  // Guard against locking everyone out of admin access.
  if (target.role === 'admin' && role !== 'admin') {
    const adminCount = db
      .prepare("SELECT COUNT(*) as c FROM users WHERE workspace_id = ? AND role = 'admin'")
      .get(req.user.workspace_id).c
    if (adminCount <= 1) {
      return res.status(400).json({ error: 'Cannot remove the last admin — promote someone else first' })
    }
  }

  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, target.id)
  audit(req.user.workspace_id, req.user.id, 'team.role_changed', 'user', target.id, { from: target.role, to: role })

  const updated = db.prepare('SELECT * FROM users WHERE id = ?').get(target.id)
  res.json({ member: safe(updated) })
})

router.delete('/:userId', requireRole('admin'), (req, res) => {
  const target = db
    .prepare('SELECT * FROM users WHERE id = ? AND workspace_id = ?')
    .get(req.params.userId, req.user.workspace_id)
  if (!target) return res.status(404).json({ error: 'Team member not found' })

  if (target.id === req.user.id) {
    return res.status(400).json({ error: 'You cannot remove yourself from the team' })
  }
  if (target.role === 'admin') {
    const adminCount = db
      .prepare("SELECT COUNT(*) as c FROM users WHERE workspace_id = ? AND role = 'admin'")
      .get(req.user.workspace_id).c
    if (adminCount <= 1) {
      return res.status(400).json({ error: 'Cannot remove the last admin' })
    }
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(target.id)
  audit(req.user.workspace_id, req.user.id, 'team.member_removed', 'user', target.id, { email: target.email })
  res.json({ ok: true })
})

export default router