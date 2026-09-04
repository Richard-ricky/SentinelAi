import jwt from 'jsonwebtoken'
import { db } from '../db/index.js'
import { hashApiKey, looksLikeApiKey } from '../lib/apiKeys.js'

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'

export function requireAuth(req, res, next) {
  const header = req.headers.authorization || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token) return res.status(401).json({ error: 'Missing authentication token' })

  try {
    const payload = jwt.verify(token, JWT_SECRET)
    const user = db
      .prepare('SELECT id, workspace_id, name, email, role FROM users WHERE id = ?')
      .get(payload.sub)
    if (!user) return res.status(401).json({ error: 'User no longer exists' })
    req.user = user
    next()
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' })
  }
}

// Machine-to-machine auth for the read-only integration API (/api/v1/*),
// used by SIEMs, dashboards, or scripts pulling findings programmatically
// — deliberately kept separate from human JWT sessions and deliberately
// restricted to read-only routes, so a leaked integration key can't be
// used to change anything.
export function requireApiKey(req, res, next) {
  const header = req.headers.authorization || ''
  const token = header.startsWith('Bearer ') ? header.slice(7) : null
  if (!token || !looksLikeApiKey(token)) {
    return res.status(401).json({ error: 'Missing or invalid API key. Use "Authorization: Bearer sk_live_..."' })
  }

  const hash = hashApiKey(token)
  const key = db.prepare('SELECT * FROM api_keys WHERE key_hash = ?').get(hash)
  if (!key || key.revoked_at) {
    return res.status(401).json({ error: 'API key is invalid or has been revoked' })
  }

  db.prepare("UPDATE api_keys SET last_used_at = datetime('now') WHERE id = ?").run(key.id)
  req.workspaceId = key.workspace_id
  req.apiKeyId = key.id
  next()
}

// Restrict a route to specific roles. Role hierarchy: admin > analyst > viewer
export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' })
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions for this action' })
    }
    next()
  }
}

export function signToken(user) {
  return jwt.sign({ sub: user.id, role: user.role, workspaceId: user.workspace_id }, JWT_SECRET, {
    expiresIn: '12h',
  })
}