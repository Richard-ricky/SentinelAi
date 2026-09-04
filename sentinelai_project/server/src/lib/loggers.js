import pino from 'pino'

// IMPORTANT: pino's `transport` option spawns a worker thread to format
// logs, which has been observed to fail silently on some Windows setups —
// the process exits with no error output at all, before ever reaching
// app.listen(). Using pino-pretty as a plain synchronous stream instead
// avoids the worker thread entirely and is far more portable.
let stream
if (process.env.NODE_ENV !== 'production') {
  try {
    const { default: pretty } = await import('pino-pretty')
    stream = pretty({ colorize: true, translateTime: 'HH:MM:ss', ignore: 'pid,hostname' })
  } catch {
    // If pino-pretty can't load for any reason, fall back to plain JSON
    // logging rather than crashing the whole server over cosmetic formatting.
    stream = undefined
  }
}

export const logger = pino({ level: process.env.LOG_LEVEL || 'info' }, stream)