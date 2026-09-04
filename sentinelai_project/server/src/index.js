// Hard safety net: catch literally anything that goes wrong during startup
// and print it with plain console.error — deliberately NOT using the pino
// logger here, since if something is wrong with logging itself, routing
// the error through the same system would be circular and could hide it.
// This must be the very first thing that runs.
process.on('uncaughtException', (err) => {
  console.error('=== UNCAUGHT EXCEPTION — server is exiting ===')
  console.error(err)
  process.exit(1)
})
process.on('unhandledRejection', (reason) => {
  console.error('=== UNHANDLED PROMISE REJECTION — server is exiting ===')
  console.error(reason)
  process.exit(1)
})

console.log('[startup] index.js loaded, beginning imports...')

import 'dotenv/config'
console.log('[startup] dotenv loaded. NODE_ENV =', JSON.stringify(process.env.NODE_ENV))

import { createApp } from './app.js'
console.log('[startup] app.js imported successfully')

import { logger } from './lib/logger.js'
console.log('[startup] logger.js imported successfully')

import { startContinuousMonitoring } from './lib/scheduler.js'
console.log('[startup] scheduler.js imported successfully')

import { isAiConfigured, currentProvider } from './lib/ai.js'
console.log('[startup] ai.js imported successfully — all imports done')

// Fail fast on missing production secrets rather than silently signing
// tokens with a guessable default. Uses console.error (not the pino
// logger) so this is guaranteed to print even if logger init itself is
// somehow the problem.
if (process.env.NODE_ENV === 'production' && (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'dev-secret-change-me')) {
  console.error('JWT_SECRET must be set to a strong random value in production. Refusing to start.')
  process.exit(1)
}

console.log('[startup] creating Express app...')
const app = createApp()
console.log('[startup] Express app created. Binding to port...')

const PORT = process.env.PORT || 4000

app.listen(PORT, () => {
  console.log(`[startup] Listening on port ${PORT} (confirmed via console.log)`)
  logger.info({ port: PORT }, 'SentinelAI API listening')
  const provider = currentProvider()
  if (!isAiConfigured()) {
    const varName = provider === 'gemini' ? 'GEMINI_API_KEY' : 'ANTHROPIC_API_KEY'
    logger.warn(`AI_PROVIDER=${provider} but ${varName} is not set — AI explanations/chat will return a fallback message.`)
  } else {
    logger.info(`AI features enabled via provider: ${provider}`)
  }
  if (process.env.DISABLE_SCHEDULER !== 'true') {
    startContinuousMonitoring()
    console.log('[startup] Continuous monitoring scheduler started')
  }
}).on('error', (err) => {
  console.error('=== app.listen() FAILED ===')
  console.error(err)
  process.exit(1)
})