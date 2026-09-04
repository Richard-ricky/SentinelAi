import crypto from 'node:crypto'

const PREFIX = 'sk_live_'

// Generates a new API key. The raw value is returned exactly once to the
// caller (who must show it to the user immediately) — only its hash is
// ever persisted, so even a full database leak doesn't hand out working
// credentials.
export function generateApiKey() {
  const raw = PREFIX + crypto.randomBytes(24).toString('base64url')
  const hash = hashApiKey(raw)
  const prefix = raw.slice(0, 12) // shown in the UI so admins can tell keys apart without ever seeing the full value again
  return { raw, hash, prefix }
}

export function hashApiKey(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex')
}

export function looksLikeApiKey(token) {
  return typeof token === 'string' && token.startsWith(PREFIX)
}