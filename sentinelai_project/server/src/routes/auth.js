import { Router } from 'express'
import bcrypt from 'bcryptjs'
import { db, newId, audit } from '../db/index.js'
import { signToken, requireAuth } from '../middleware/auth.js'
import { logger } from '../lib/logger.js'

const router = Router()

const MAX_FAILED_ATTEMPTS = 5
const LOCKOUT_MINUTES = 15

// Register: creates a brand-new workspace with this user as its admin.
router.post('/register', (req, res) => {
  const { name, email, password, workspaceName } = req.body || {}
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'name, email, and password are required' })
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' })
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase())
  if (existing) return res.status(409).json({ error: 'An account with that email already exists' })

  const workspaceId = newId('ws')
  const userId = newId('usr')
  const passwordHash = bcrypt.hashSync(password, 10)

  db.prepare('INSERT INTO workspaces (id, name) VALUES (?, ?)').run(
    workspaceId,
    workspaceName || `${name}'s Workspace`
  )
  db.prepare(
    'INSERT INTO users (id, workspace_id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(userId, workspaceId, name, email.toLowerCase(), passwordHash, 'admin')

  const user = { id: userId, workspace_id: workspaceId, name, email: email.toLowerCase(), role: 'admin' }
  const token = signToken(user)
  audit(workspaceId, userId, 'user.registered', 'user', userId)
  logger.info({ userId, workspaceId }, 'New user registered')
  res.status(201).json({ token, user })
})

router.post('/login', (req, res) => {
  const { email, password } = req.body || {}
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' })

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase())

  // Constant-shape response whether or not the account exists, to avoid
  // leaking which emails are registered.
  if (!user) {
    bcrypt.compareSync(password, '$2b$10$5RWq19BZmMdm4P53nz/9yuzDli3jiu3qmlBx487tDfFhzmGTjyfj6')
    return res.status(401).json({ error: 'Invalid email or password' })
  }

  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    const minsLeft = Math.ceil((new Date(user.locked_until) - new Date()) / 60000)
    return res.status(423).json({ error: `Account temporarily locked. Try again in ${minsLeft} minute(s).` })
  }

  const valid = bcrypt.compareSync(password, user.password_hash)
  if (!valid) {
    const attempts = (user.failed_login_attempts || 0) + 1
    const lockedUntil =
      attempts >= MAX_FAILED_ATTEMPTS
        ? new Date(Date.now() + LOCKOUT_MINUTES * 60000).toISOString()
        : null
    db.prepare('UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?').run(
      attempts,
      lockedUntil,
      user.id
    )
    if (lockedUntil) {
      logger.warn({ userId: user.id }, 'Account locked after repeated failed logins')
      return res.status(423).json({ error: `Too many failed attempts. Account locked for ${LOCKOUT_MINUTES} minutes.` })
    }
    return res.status(401).json({ error: 'Invalid email or password' })
  }

  // Successful login — reset lockout counters.
  db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id)

  const token = signToken(user)
  const { password_hash, ...safeUser } = user
  audit(user.workspace_id, user.id, 'user.login', 'user', user.id)
  res.json({ token, user: safeUser })
})

router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user })
})

export default router
