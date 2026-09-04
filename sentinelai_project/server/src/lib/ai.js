import Anthropic from '@anthropic-ai/sdk'
import { GoogleGenAI } from '@google/genai'
import { logger } from './logger.js'

// Supports two AI providers, switchable via AI_PROVIDER — so this app
// isn't locked into one vendor. Defaults to Gemini, which has a usable
// free tier (Anthropic currently does not). Set AI_PROVIDER=anthropic
// (with ANTHROPIC_API_KEY set) to switch back at any time — no code
// changes needed, just the env var.
const PROVIDER = (process.env.AI_PROVIDER || 'gemini').toLowerCase()

const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-5'
// gemini-2.5-flash is the free-tier-eligible model as of this writing —
// gemini-2.5-pro requires a paid plan. If Google changes free-tier terms
// again, override via GEMINI_MODEL without touching this file.
const GEMINI_MODEL = process.env.GEMINI_MODEL || 'gemini-3.6-flash'

let anthropicClient = null
function getAnthropicClient() {
  if (!process.env.ANTHROPIC_API_KEY) return null
  if (!anthropicClient) anthropicClient = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY })
  return anthropicClient
}

let geminiClient = null
function getGeminiClient() {
  if (!process.env.GEMINI_API_KEY) return null
  if (!geminiClient) geminiClient = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY })
  return geminiClient
}

const SYSTEM_PROMPT = `You are the AI Security Assistant inside SentinelAI, a cybersecurity platform for
small business owners and IT teams who are not security experts. When explaining a vulnerability:
- Use plain, non-technical English a busy business owner could understand in one read.
- Be concrete about real-world impact ("what could actually go wrong"), not jargon.
- Keep it to 3-5 short sentences unless asked for more detail.
- Never claim you have executed or will execute any fix yourself — SentinelAI only applies
  patches after a human explicitly clicks "Approve & Apply."
- If asked for a remediation script, provide a clearly-labeled draft script and remind the
  user it requires their review and approval before running.`

export function isAiConfigured() {
  if (PROVIDER === 'gemini') return Boolean(process.env.GEMINI_API_KEY)
  return Boolean(process.env.ANTHROPIC_API_KEY)
}

export function currentProvider() {
  return PROVIDER
}

function missingKeyMessage() {
  const varName = PROVIDER === 'gemini' ? 'GEMINI_API_KEY' : 'ANTHROPIC_API_KEY'
  return `AI features are unavailable because no ${varName} is configured on the server (current AI_PROVIDER=${PROVIDER}).`
}

// messages: [{ role: 'user' | 'assistant', content: string }]
// Returns plain text. Dispatches to whichever provider is configured.
async function chatComplete(systemPrompt, messages) {
  if (PROVIDER === 'gemini') return chatCompleteGemini(systemPrompt, messages)
  return chatCompleteAnthropic(systemPrompt, messages)
}

async function chatCompleteAnthropic(systemPrompt, messages) {
  const client = getAnthropicClient()
  if (!client) throw new Error('Anthropic client not configured')

  const message = await client.messages.create({
    model: ANTHROPIC_MODEL,
    max_tokens: 500,
    system: systemPrompt,
    messages,
  })

  return message.content
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('\n')
    .trim()
}

async function chatCompleteGemini(systemPrompt, messages) {
  const client = getGeminiClient()
  if (!client) throw new Error('Gemini client not configured')

  // Gemini uses 'user'/'model' roles (not 'user'/'assistant' like
  // Anthropic/OpenAI) and expects turns to alternate starting with 'user'.
  const contents = messages.map((m) => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }],
  }))

  const response = await client.models.generateContent({
    model: GEMINI_MODEL,
    contents,
    config: { systemInstruction: systemPrompt },
  })

  return (response.text || '').trim()
}

export async function explainVulnerability(vuln) {
  if (!isAiConfigured()) {
    return vuln.description || missingKeyMessage()
  }

  const prompt = `Explain this vulnerability finding to a non-technical business owner:

Name: ${vuln.name}
Severity: ${vuln.severity}
Category: ${vuln.category}
Asset: ${vuln.asset_name || vuln.asset || 'unknown asset'}
${vuln.cve ? `CVE: ${vuln.cve}` : ''}
Raw description: ${vuln.description || 'n/a'}

Explain what it means, why it matters for their business, and what happens if it's ignored.`

  try {
    const text = await chatComplete(SYSTEM_PROMPT, [{ role: 'user', content: prompt }])
    return text || 'The AI provider returned an empty response. Try again in a moment.'
  } catch (err) {
    logger.error({ err: String(err.message || err), provider: PROVIDER }, 'AI explanation request failed')
    throw err
  }
}

export async function chatAboutVulnerability(vuln, history, question) {
  if (!isAiConfigured()) {
    return missingKeyMessage()
  }

  const context = `The user is asking about this specific vulnerability finding:
Name: ${vuln.name}
Severity: ${vuln.severity}
Category: ${vuln.category}
Description: ${vuln.description || 'n/a'}
Impact: ${vuln.impact || 'n/a'}
Suggested fix: ${vuln.fix || 'n/a'}`

  const messages = [
    { role: 'user', content: context },
    { role: 'assistant', content: 'Understood — I have the context on this finding. What would you like to know?' },
    ...history.map((m) => ({ role: m.role, content: m.content })),
    { role: 'user', content: question },
  ]

  try {
    const text = await chatComplete(SYSTEM_PROMPT, messages)
    return text || 'The AI provider returned an empty response. Try again in a moment.'
  } catch (err) {
    logger.error({ err: String(err.message || err), provider: PROVIDER }, 'AI chat request failed')
    throw err
  }
}