import crypto from 'node:crypto'
import { logger } from './logger.js'

// AES-256-GCM encryption for anything sensitive we need to store and later
// retrieve in usable form (unlike passwords/API keys, which we only ever
// hash — cloud credentials need to be decrypted again to make API calls
// on the customer's behalf, so hashing isn't an option here).
//
// Uses a dedicated CREDENTIAL_ENCRYPTION_KEY when set. If it's not set,
// falls back to deriving a key from JWT_SECRET so the app doesn't hard-fail
// in development — but this is a real security tradeoff, not a shortcut to
// skip: a dedicated key means rotating your JWT secret doesn't also
// invalidate every stored cloud credential, and keeps concerns separated.
// Set CREDENTIAL_ENCRYPTION_KEY explicitly before storing real credentials
// in anything resembling production.

let cachedKey = null
let warnedFallback = false

function getKey() {
  if (cachedKey) return cachedKey

  const configured = process.env.CREDENTIAL_ENCRYPTION_KEY
  if (configured) {
    // Accept hex or base64, must resolve to exactly 32 bytes for AES-256.
    let buf
    if (/^[0-9a-fA-F]{64}$/.test(configured)) {
      buf = Buffer.from(configured, 'hex')
    } else {
      buf = Buffer.from(configured, 'base64')
    }
    if (buf.length !== 32) {
      throw new Error('CREDENTIAL_ENCRYPTION_KEY must decode to exactly 32 bytes (64 hex chars, or base64).')
    }
    cachedKey = buf
    return cachedKey
  }

  if (!warnedFallback) {
    logger.warn(
      'CREDENTIAL_ENCRYPTION_KEY not set — deriving a fallback key from JWT_SECRET. ' +
      'Set a dedicated CREDENTIAL_ENCRYPTION_KEY before storing real cloud credentials.'
    )
    warnedFallback = true
  }
  const jwtSecret = process.env.JWT_SECRET || 'dev-secret-change-me'
  cachedKey = crypto.scryptSync(jwtSecret, 'sentinelai-credential-salt', 32)
  return cachedKey
}

export function encryptSecret(plaintext) {
  const key = getKey()
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()
  return Buffer.concat([iv, authTag, ciphertext]).toString('base64')
}

export function decryptSecret(payload) {
  const key = getKey()
  const buf = Buffer.from(payload, 'base64')
  const iv = buf.subarray(0, 12)
  const authTag = buf.subarray(12, 28)
  const ciphertext = buf.subarray(28)
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8')
}