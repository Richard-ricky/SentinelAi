import crypto from 'node:crypto'
import { db } from '../db/index.js'
import { logger } from './logger.js'

// Delivers a signed JSON payload to every enabled webhook subscribed to
// `eventType` for a workspace. Every delivery is HMAC-SHA256 signed with
// the webhook's own secret (sent as X-SentinelAI-Signature), so the
// receiver can verify the payload actually came from SentinelAI and
// wasn't forged or tampered with in transit — the same pattern Stripe,
// GitHub, and Slack use for their own webhooks.
export async function deliverWebhookEvent(workspaceId, eventType, payload) {
  const webhooks = db
    .prepare('SELECT * FROM webhooks WHERE workspace_id = ? AND enabled = 1')
    .all(workspaceId)
    .filter((w) => w.events.split(',').map((e) => e.trim()).includes(eventType))

  await Promise.all(webhooks.map((webhook) => deliverOne(webhook, eventType, payload)))
}

// Delivers to one specific webhook regardless of its event subscriptions —
// used for the "send test event" button so a test always reaches the
// webhook the admin is actually looking at.
export async function deliverTestEvent(webhook) {
  await deliverOne(webhook, 'test', {
    message: 'This is a test delivery from SentinelAI to confirm your endpoint and signature verification are wired up correctly.',
  })
}

async function deliverOne(webhook, eventType, payload) {
  const body = JSON.stringify({ event: eventType, deliveredAt: new Date().toISOString(), data: payload })
  const signature = crypto.createHmac('sha256', webhook.secret).update(body).digest('hex')

  try {
    const res = await fetch(webhook.url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-SentinelAI-Signature': `sha256=${signature}`,
        'X-SentinelAI-Event': eventType,
      },
      body,
      signal: AbortSignal.timeout(8000),
    })
    db.prepare("UPDATE webhooks SET last_delivery_at = datetime('now'), last_delivery_status = ? WHERE id = ?").run(
      String(res.status),
      webhook.id
    )
    if (!res.ok) {
      logger.warn({ webhookId: webhook.id, status: res.status }, 'Webhook delivery returned non-2xx')
    }
  } catch (err) {
    db.prepare("UPDATE webhooks SET last_delivery_at = datetime('now'), last_delivery_status = 'error' WHERE id = ?").run(
      webhook.id
    )
    logger.warn({ webhookId: webhook.id, err: String(err.message || err) }, 'Webhook delivery failed')
  }
}
