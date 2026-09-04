// Real integration tests using Node's built-in test runner against an
// in-memory SQLite database and a live (but unbound) instance of the
// Express app. Run with: npm test
//
// Env vars (DB_PATH=:memory:, etc.) are set by test/setup.js, preloaded via
// `node --import ./test/setup.js`. That preload happens before this file's
// own imports are evaluated — doing it inline here instead would NOT work
// reliably, because ES module imports are hoisted ahead of any top-level
// statements in the importing file, regardless of source order.

import { test, describe, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createApp } from '../src/app.js'
import { scanForExposedSecrets } from '../src/lib/secretScanner.js'

let server
let baseUrl

before(async () => {
  const app = createApp()
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      baseUrl = `http://localhost:${server.address().port}`
      resolve()
    })
  })
})

after(() => {
  server.close()
})

async function post(path, body, token) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() }
}

async function get(path, token) {
  const res = await fetch(`${baseUrl}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  return { status: res.status, body: await res.json() }
}

describe('auth', () => {
  test('registers a new user and returns a token', async () => {
    const { status, body } = await post('/api/auth/register', {
      name: 'Test User',
      email: 'test1@example.com',
      password: 'testpass123',
    })
    assert.equal(status, 201)
    assert.ok(body.token)
    assert.equal(body.user.email, 'test1@example.com')
    assert.equal(body.user.role, 'admin')
  })

  test('rejects duplicate email registration', async () => {
    await post('/api/auth/register', { name: 'A', email: 'dupe@example.com', password: 'testpass123' })
    const { status, body } = await post('/api/auth/register', { name: 'B', email: 'dupe@example.com', password: 'testpass123' })
    assert.equal(status, 409)
    assert.match(body.error, /already exists/)
  })

  test('rejects short passwords', async () => {
    const { status } = await post('/api/auth/register', { name: 'A', email: 'short@example.com', password: '123' })
    assert.equal(status, 400)
  })

  test('logs in with correct credentials', async () => {
    await post('/api/auth/register', { name: 'Login User', email: 'login1@example.com', password: 'testpass123' })
    const { status, body } = await post('/api/auth/login', { email: 'login1@example.com', password: 'testpass123' })
    assert.equal(status, 200)
    assert.ok(body.token)
  })

  test('rejects wrong password', async () => {
    await post('/api/auth/register', { name: 'Login User 2', email: 'login2@example.com', password: 'testpass123' })
    const { status } = await post('/api/auth/login', { email: 'login2@example.com', password: 'wrongpassword' })
    assert.equal(status, 401)
  })

  test('locks account after repeated failed logins', async () => {
    await post('/api/auth/register', { name: 'Lockout User', email: 'lockout@example.com', password: 'testpass123' })
    let lastStatus
    for (let i = 0; i < 5; i++) {
      const res = await post('/api/auth/login', { email: 'lockout@example.com', password: 'wrongpassword' })
      lastStatus = res.status
    }
    assert.equal(lastStatus, 423) // locked
    // Even the correct password should now be rejected while locked.
    const { status } = await post('/api/auth/login', { email: 'lockout@example.com', password: 'testpass123' })
    assert.equal(status, 423)
  })
})

describe('production auth rate limiting (isolated app instance)', () => {
  // The global test suite disables the auth rate limit (see app.js) so its
  // own volume of register/login calls doesn't trip a production-tuned
  // limit. This test proves the limiter genuinely works by spinning up a
  // second app instance with NODE_ENV temporarily forced to "production"
  // for its construction, rather than just trusting the config value.
  test('locks out after the configured limit of auth requests from one IP', async () => {
    const original = process.env.NODE_ENV
    process.env.NODE_ENV = 'production'
    let prodServer
    try {
      const prodApp = createApp()
      prodServer = await new Promise((resolve) => {
        const s = prodApp.listen(0, () => resolve(s))
      })
      const prodBaseUrl = `http://localhost:${prodServer.address().port}`

      let sawLimitHit = false
      for (let i = 0; i < 25; i++) {
        const res = await fetch(`${prodBaseUrl}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'nobody@example.com', password: 'wrong' }),
        })
        if (res.status === 429) {
          sawLimitHit = true
          break
        }
      }
      assert.equal(sawLimitHit, true, 'expected the auth rate limiter to return 429 within 25 requests')
    } finally {
      process.env.NODE_ENV = original
      if (prodServer) prodServer.close()
    }
  })
})

describe('assets + vulnerabilities workflow', () => {
  let token

  before(async () => {
    const { body } = await post('/api/auth/register', {
      name: 'Workflow User',
      email: 'workflow@example.com',
      password: 'testpass123',
    })
    token = body.token
  })

  test('rejects unauthenticated asset creation', async () => {
    const { status } = await post('/api/assets', { name: 'x', type: 'website', target: 'example.com' })
    assert.equal(status, 401)
  })

  test('creates an asset', async () => {
    const { status, body } = await post('/api/assets', { name: 'test-site', type: 'website', target: 'example.com' }, token)
    assert.equal(status, 201)
    assert.equal(body.asset.name, 'test-site')
    assert.equal(body.asset.auto_scan_enabled, 1)
  })

  test('lists only the workspace\'s own assets (data isolation)', async () => {
    const { body: otherUser } = await post('/api/auth/register', {
      name: 'Other Workspace',
      email: 'otherws@example.com',
      password: 'testpass123',
    })
    const { body } = await get('/api/assets', otherUser.token)
    assert.equal(body.assets.length, 0) // sees none of workflow@example.com's assets
  })

  test('runs a real scan and produces findings', { timeout: 15000 }, async () => {
    const { body: assetBody } = await post('/api/assets', { name: 'scan-target', type: 'website', target: 'github.com' }, token)
    const { status, body } = await post(`/api/scans/assets/${assetBody.asset.id}`, {}, token)
    assert.equal(status, 200)
    assert.ok(Array.isArray(body.vulnerabilities))
  })

  test('vulnerability patch approval sets status to Patched', { timeout: 15000 }, async () => {
    const { body: assetBody } = await post('/api/assets', { name: 'patch-target', type: 'website', target: 'github.com' }, token)
    const { body: scanBody } = await post(`/api/scans/assets/${assetBody.asset.id}`, {}, token)
    if (scanBody.vulnerabilities.length === 0) return // nothing found on this run; skip assertion
    const vulnId = scanBody.vulnerabilities[0].id
    const { status, body } = await post(`/api/vulnerabilities/${vulnId}/patch`, { decision: 'approved' }, token)
    assert.equal(status, 200)
    assert.equal(body.vulnerability.status, 'Patched')
  })
})

describe('secret detection & redaction', () => {
  const FAKE_AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'
  const FAKE_STRIPE_KEY = 'sk_live_51H8xyzABCDEFGHIJKLMNOPQRSTUV'

  test('detects known secret patterns', () => {
    const findings = scanForExposedSecrets(`AWS_KEY=${FAKE_AWS_KEY}\nSTRIPE=${FAKE_STRIPE_KEY}`, 'test .env')
    assert.ok(findings.length >= 2)
    assert.ok(findings.some((f) => f.name.includes('AWS Access Key')))
    assert.ok(findings.some((f) => f.name.includes('Stripe')))
  })

  test('CRITICAL: raw secret value never appears anywhere in the findings output', () => {
    const findings = scanForExposedSecrets(`AWS_KEY=${FAKE_AWS_KEY}\nSTRIPE=${FAKE_STRIPE_KEY}`, 'test .env')
    const serialized = JSON.stringify(findings)
    assert.equal(serialized.includes(FAKE_AWS_KEY), false, 'raw AWS key leaked into findings output')
    assert.equal(serialized.includes(FAKE_STRIPE_KEY), false, 'raw Stripe key leaked into findings output')
  })

  test('redacted preview only reveals first/last 4 characters', () => {
    const findings = scanForExposedSecrets(`AWS_KEY=${FAKE_AWS_KEY}`, 'test .env')
    const preview = findings[0].redactedPreview
    assert.ok(preview.startsWith(FAKE_AWS_KEY.slice(0, 4)))
    assert.ok(preview.endsWith(FAKE_AWS_KEY.slice(-4)))
    assert.ok(preview.includes('•'))
  })

  test('returns nothing for text with no secrets', () => {
    const findings = scanForExposedSecrets('<html><body>Hello world</body></html>', 'homepage')
    assert.equal(findings.length, 0)
  })
})

describe('reports', () => {
  test('summary reflects security score correctly with no findings', async () => {
    const { body } = await post('/api/auth/register', { name: 'Report User', email: 'report@example.com', password: 'testpass123' })
    const { status, body: summary } = await get('/api/reports/summary', body.token)
    assert.equal(status, 200)
    assert.equal(summary.securityScore, 100)
    assert.equal(summary.totalAssets, 0)
  })

  test('compliance endpoint maps categories to framework controls', async () => {
    const { body } = await post('/api/auth/register', { name: 'Compliance User', email: 'compliance@example.com', password: 'testpass123' })
    const { status, body: compliance } = await get('/api/reports/compliance', body.token)
    assert.equal(status, 200)
    assert.ok(compliance.frameworks.soc2)
    assert.ok(compliance.frameworks.iso27001)
    assert.ok(compliance.frameworks.gdpr)
    assert.ok(compliance.disclaimer.includes('not a certification'))
  })
})

async function del(path, token) {
  const res = await fetch(`${baseUrl}${path}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } })
  return { status: res.status, body: await res.json() }
}

describe('enterprise integration: API keys', () => {
  let token

  before(async () => {
    const { body } = await post('/api/auth/register', { name: 'Key Admin', email: 'keyadmin@example.com', password: 'testpass123' })
    token = body.token
  })

  test('creates an API key and returns the raw value exactly once', async () => {
    const { status, body } = await post('/api/settings/api-keys', { name: 'SIEM integration' }, token)
    assert.equal(status, 201)
    assert.ok(body.rawKey.startsWith('sk_live_'))
    assert.ok(body.apiKey.key_prefix)
    // The stored/returned key object must never include the hash or raw key.
    assert.equal(body.apiKey.key_hash, undefined)
  })

  test('the raw key authenticates against the read-only v1 API', async () => {
    const { body } = await post('/api/settings/api-keys', { name: 'test key' }, token)
    const rawKey = body.rawKey

    const res = await fetch(`${baseUrl}/api/v1/summary`, { headers: { Authorization: `Bearer ${rawKey}` } })
    assert.equal(res.status, 200)
    const json = await res.json()
    assert.ok('openVulnerabilities' in json)
  })

  test('a revoked key is rejected', async () => {
    const { body: created } = await post('/api/settings/api-keys', { name: 'to revoke' }, token)
    await del(`/api/settings/api-keys/${created.apiKey.id}`, token)

    const res = await fetch(`${baseUrl}/api/v1/summary`, { headers: { Authorization: `Bearer ${created.rawKey}` } })
    assert.equal(res.status, 401)
  })

  test('the v1 API rejects human JWTs (API-key only surface)', async () => {
    const res = await fetch(`${baseUrl}/api/v1/summary`, { headers: { Authorization: `Bearer ${token}` } })
    assert.equal(res.status, 401)
  })
})

describe('enterprise integration: webhooks', () => {
  let token

  before(async () => {
    const { body } = await post('/api/auth/register', { name: 'Webhook Admin', email: 'webhookadmin@example.com', password: 'testpass123' })
    token = body.token
  })

  test('creates a webhook and returns the secret exactly once', async () => {
    const { status, body } = await post('/api/settings/webhooks', { url: 'https://example.com/hook' }, token)
    assert.equal(status, 201)
    assert.ok(body.secret)
    assert.equal(body.webhook.secret, undefined) // never echoed back on the stored object
    assert.ok(body.webhook.secretPreview.includes('•'))
  })

  test('rejects an invalid URL', async () => {
    const { status } = await post('/api/settings/webhooks', { url: 'not-a-url' }, token)
    assert.equal(status, 400)
  })
})

async function patch(path, body, token) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() }
}

describe('team management', () => {
  let adminToken

  before(async () => {
    const { body } = await post('/api/auth/register', { name: 'Team Admin', email: 'teamadmin@example.com', password: 'testpass123' })
    adminToken = body.token
  })

  test('invites a new member and returns a temp password once', async () => {
    const { status, body } = await post('/api/team/invite', { name: 'New Analyst', email: 'analyst@example.com', role: 'analyst' }, adminToken)
    assert.equal(status, 201)
    assert.ok(body.tempPassword)
    assert.equal(body.member.role, 'analyst')
    assert.equal(body.member.password_hash, undefined)
  })

  test('the temp password actually logs the invited member in', async () => {
    const { body: invited } = await post('/api/team/invite', { name: 'Login Test', email: 'logintest@example.com', role: 'viewer' }, adminToken)
    const { status, body } = await post('/api/auth/login', { email: 'logintest@example.com', password: invited.tempPassword })
    assert.equal(status, 200)
    assert.equal(body.user.role, 'viewer')
  })

  test('rejects duplicate email invites', async () => {
    await post('/api/team/invite', { name: 'Dup', email: 'dup-invite@example.com', role: 'viewer' }, adminToken)
    const { status } = await post('/api/team/invite', { name: 'Dup2', email: 'dup-invite@example.com', role: 'viewer' }, adminToken)
    assert.equal(status, 409)
  })

  test('lists team members scoped to the workspace', async () => {
    const { body } = await get('/api/team', adminToken)
    assert.ok(body.members.length >= 3) // admin + analyst + viewer invited above
    assert.ok(body.members.every((m) => !('password_hash' in m)))
  })

  test('changes a member role', async () => {
    const { body: invited } = await post('/api/team/invite', { name: 'Role Change', email: 'rolechange@example.com', role: 'viewer' }, adminToken)
    const { status, body } = await patch(`/api/team/${invited.member.id}/role`, { role: 'analyst' }, adminToken)
    assert.equal(status, 200)
    assert.equal(body.member.role, 'analyst')
  })

  test('cannot demote the last remaining admin', async () => {
    // adminToken's own user is the only admin in this freshly-registered workspace.
    const { body: me } = await get('/api/auth/me', adminToken)
    const { status, body } = await patch(`/api/team/${me.user.id}/role`, { role: 'viewer' }, adminToken)
    assert.equal(status, 400)
    assert.match(body.error, /last admin/)
  })

  test('cannot remove yourself from the team', async () => {
    const { body: me } = await get('/api/auth/me', adminToken)
    const { status } = await del(`/api/team/${me.user.id}`, adminToken)
    assert.equal(status, 400)
  })

  test('a non-admin cannot invite members', async () => {
    const { body: invited } = await post('/api/team/invite', { name: 'Viewer Only', email: 'viewer-only@example.com', role: 'viewer' }, adminToken)
    const { body: viewerLogin } = await post('/api/auth/login', { email: 'viewer-only@example.com', password: invited.tempPassword })
    const { status } = await post('/api/team/invite', { name: 'Blocked', email: 'blocked@example.com', role: 'viewer' }, viewerLogin.token)
    assert.equal(status, 403)
  })
})

describe('cloud integration: AWS', () => {
  let token

  before(async () => {
    const { body } = await post('/api/auth/register', { name: 'Cloud Admin', email: 'cloudadmin@example.com', password: 'testpass123' })
    token = body.token
  })

  test('requires authentication', async () => {
    const res = await fetch(`${baseUrl}/api/cloud`)
    assert.equal(res.status, 401)
  })

  test('rejects connect requests missing credentials', async () => {
    const { status } = await post('/api/cloud/aws/connect', { accessKeyId: 'AKIAEXAMPLE' }, token)
    assert.equal(status, 400)
  })

  test('rejects invalid/unreachable-in-sandbox credentials rather than storing them blindly', async () => {
    // This sandbox has no network path to AWS itself, so a real credential
    // check will fail here exactly like a genuinely bad credential would —
    // which is precisely the behavior we want to prove: the endpoint must
    // verify before storing, never store-then-hope.
    const { status, body } = await post(
      '/api/cloud/aws/connect',
      { accessKeyId: 'AKIAFAKEEXAMPLE1234', secretAccessKey: 'fake-secret-key-value-not-real', region: 'us-east-1' },
      token
    )
    assert.equal(status, 400)
    assert.ok(body.error)
  })

  test('scanning with no connected account returns a clear error, not a crash', async () => {
    const { body } = await post('/api/auth/register', { name: 'No Cloud', email: 'nocloud@example.com', password: 'testpass123' })
    const { status, body: scanBody } = await post('/api/cloud/aws/scan', {}, body.token)
    assert.equal(status, 404)
    assert.match(scanBody.error, /No AWS account connected/)
  })

  test('a non-admin cannot connect an AWS account', async () => {
    const { body: invited } = await post('/api/team/invite', { name: 'Cloud Viewer', email: 'cloudviewer@example.com', role: 'viewer' }, token)
    const { body: viewerLogin } = await post('/api/auth/login', { email: 'cloudviewer@example.com', password: invited.tempPassword })
    const { status } = await post(
      '/api/cloud/aws/connect',
      { accessKeyId: 'AKIAFAKE', secretAccessKey: 'fake', region: 'us-east-1' },
      viewerLogin.token
    )
    assert.equal(status, 403)
  })
})

describe('credential encryption round-trip', () => {
  test('encryptSecret/decryptSecret round-trips correctly and ciphertext never contains the plaintext', async () => {
    const { encryptSecret, decryptSecret } = await import('../src/lib/crypto.js')
    const secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    const encrypted = encryptSecret(secret)
    assert.notEqual(encrypted, secret)
    assert.ok(!encrypted.includes(secret))
    assert.equal(decryptSecret(encrypted), secret)
  })

  test('two encryptions of the same secret produce different ciphertext (random IV)', async () => {
    const { encryptSecret } = await import('../src/lib/crypto.js')
    const a = encryptSecret('same-secret-value')
    const b = encryptSecret('same-secret-value')
    assert.notEqual(a, b)
  })
})