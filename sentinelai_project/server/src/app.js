import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import pinoHttp from 'pino-http'

import authRoutes from './routes/auth.js'
import assetRoutes from './routes/assets.js'
import scanRoutes from './routes/scans.js'
import vulnerabilityRoutes from './routes/vulnerabilities.js'
import notificationRoutes from './routes/notifications.js'
import reportRoutes from './routes/reports.js'
import apiKeyRoutes from './routes/apiKeys.js'
import webhookRoutes from './routes/webhooks.js'
import integrationApiRoutes from './routes/integrationApi.js'
import teamRoutes from './routes/team.js'
import cloudRoutes from './routes/cloud.js'
import { isAiConfigured } from './lib/ai.js'
import { logger } from './lib/logger.js'
import { runMonitoringTickNow } from './lib/scheduler.js'
import { requireAuth, requireRole } from './middleware/auth.js'

export function createApp() {
  const app = express()
  app.set('trust proxy', 1)

  app.use(helmet())
  app.use(
    cors({
      origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : true,
      credentials: true,
    })
  )
  app.use(express.json({ limit: '1mb' }))

  if (process.env.NODE_ENV !== 'test') {
    app.use(pinoHttp({ logger, autoLogging: { ignore: (req) => req.url === '/api/health' } }))
  }

  app.use(
    rateLimit({
      windowMs: 15 * 60 * 1000,
      limit: 600,
      standardHeaders: true,
      legacyHeaders: false,
    })
  )

  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: process.env.NODE_ENV === 'test' ? 100000 : 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many attempts. Please wait a few minutes and try again.' },
  })
  app.use('/api/auth', authLimiter)

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, aiConfigured: isAiConfigured() })
  })

  app.use('/api/auth', authRoutes)
  app.use('/api/assets', assetRoutes)
  app.use('/api/scans', scanRoutes)
  app.use('/api/vulnerabilities', vulnerabilityRoutes)
  app.use('/api/notifications', notificationRoutes)
  app.use('/api/reports', reportRoutes)
  app.use('/api/settings/api-keys', apiKeyRoutes)
  app.use('/api/settings/webhooks', webhookRoutes)
  app.use('/api/v1', integrationApiRoutes)
  app.use('/api/team', teamRoutes)
  app.use('/api/cloud', cloudRoutes)

  app.post('/api/monitoring/run-now', requireAuth, requireRole('admin'), async (_req, res) => {
    runMonitoringTickNow().catch((err) =>
      logger.error({ err: String(err.message || err) }, 'Manual monitoring tick failed')
    )
    res.json({ ok: true, message: 'Continuous monitoring pass triggered.' })
  })

  app.get('/api/monitoring/status', requireAuth, (_req, res) => {
    res.json({
      intervalMinutes: Number(process.env.SCAN_INTERVAL_MINUTES || 60),
      running: true,
    })
  })

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (req.log) req.log.error({ err }, 'Unhandled error')
    else logger.error({ err: String(err?.message || err) }, 'Unhandled error')
    res.status(500).json({ error: 'Internal server error' })
  })

  return app
}