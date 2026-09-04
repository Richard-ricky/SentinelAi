// Detects common secret/API-key patterns in publicly-fetched content and
// redacts them immediately. The raw secret value is NEVER stored, logged,
// or returned — only a masked preview (first 4 + last 4 characters) and
// enough context to tell the user where to look and what to rotate. This
// matters even for a security tool: a report full of live credentials
// would itself become a leak (e.g. sitting in a PDF export, a database
// row, or a screen-shared demo).

// Provider-prefixed patterns (self-contained — no assignment context
// needed, since the key format itself is distinctive).
const PREFIXED_PATTERNS = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key (context)', pattern: /aws_secret_access_key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi },
  { name: 'Stripe secret key', pattern: /sk_live_[0-9a-zA-Z]{16,}/g },
  { name: 'Stripe restricted key', pattern: /rk_live_[0-9a-zA-Z]{16,}/g },
  { name: 'Anthropic API key', pattern: /sk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'OpenAI API key', pattern: /sk-[A-Za-z0-9]{20,}/g },
  { name: 'Google API key', pattern: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: 'Google OAuth client secret', pattern: /GOCSPX-[A-Za-z0-9_-]{20,}/g },
  { name: 'GitHub personal access token', pattern: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { name: 'GitHub fine-grained token', pattern: /github_pat_[A-Za-z0-9_]{22,}/g },
  { name: 'Slack token', pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'Slack webhook URL', pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g },
  { name: 'Twilio API key', pattern: /SK[0-9a-fA-F]{32}/g },
  { name: 'Twilio Account SID (context)', pattern: /account_sid["']?\s*[:=]\s*["']?(AC[0-9a-fA-F]{32})["']?/gi },
  { name: 'SendGrid API key', pattern: /SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g },
  { name: 'Mailgun API key', pattern: /key-[0-9a-zA-Z]{32}/g },
  { name: 'npm access token', pattern: /npm_[A-Za-z0-9]{36}/g },
  { name: 'Square access token', pattern: /sq0(?:atp|csp)-[0-9A-Za-z\-_]{22,}/g },
  { name: 'PayPal/Braintree access token', pattern: /access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}/g },
  { name: 'Heroku API key (context)', pattern: /heroku[_-]?api[_-]?key["']?\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?/gi },
  { name: 'Azure Storage connection string', pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}/g },
  { name: 'Firebase server key', pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}/g },
  { name: 'GCP service account private key', pattern: /"type":\s*"service_account"[\s\S]{0,2000}?"private_key":\s*"-----BEGIN PRIVATE KEY-----/g },
  { name: 'Private key block', pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: 'JWT-looking token', pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { name: 'Basic Auth credentials in URL', pattern: /[a-z]+:\/\/[^\s"'/:@]+:[^\s"'/:@]+@[^\s"'/]+/gi },
]

// Assignment-style patterns: KEY = VALUE, where the value may or may not
// be quoted. Handles both JS/JSON style ("apiKey": "abc...") and .env /
// shell style (API_KEY=abc..., no quotes, terminated by newline/whitespace
// instead). This is the pattern class that previously only matched the
// quoted form — .env files (the single most common real-world leak
// format this scanner is actually pointed at) are almost always unquoted,
// so the quoted-only version was silently missing them.
const ASSIGNMENT_PATTERNS = [
  {
    name: 'Generic API key assignment',
    // value: quoted string OR an unquoted run of non-whitespace chars
    pattern: /(?:api[_-]?key|apikey)["']?\s*[:=]\s*(?:["']([A-Za-z0-9_\-./+=]{16,})["']|([A-Za-z0-9_\-./+=]{16,})(?=\s|$|["';,]))/gim,
  },
  {
    name: 'Generic secret/token/password assignment',
    pattern: /(?:secret|token|passwd|password)["']?\s*[:=]\s*(?:["']([A-Za-z0-9_\-./+=]{12,})["']|([A-Za-z0-9_\-./+=]{12,})(?=\s|$|["';,]))/gim,
  },
]

function redact(value) {
  if (value.length <= 8) return '••••••••'
  return `${value.slice(0, 4)}${'•'.repeat(Math.min(value.length - 8, 20))}${value.slice(-4)}`
}

// Skips obvious non-secrets that would otherwise satisfy the generic
// assignment patterns' length/charset rules — placeholder values that show
// up constantly in example configs, docs, and boilerplate, which would
// otherwise generate noisy false positives on every scan.
// Exact-match placeholders (whole value is exactly this token).
const PLACEHOLDER_EXACT = /^(xxxx+|placeholder|example|changeme|change[_-]?me|todo|redacted|<[^>]+>|\$\{[^}]+\}|none|null|undefined|test|dummy)$/i
// Substring markers — real credentials never contain these words, but
// placeholder text commonly wraps them with a prefix/suffix, e.g.
// "your_api_key_here", "xxx-your-secret-xxx", "INSERT_TOKEN_HERE".
const PLACEHOLDER_SUBSTRING = /your[_-]?(api[_-]?)?key|_here$|^here_|insert[_-]|replace[_-]?(me|this)|<[^>]*>|\$\{.*\}|example[_-]?(key|secret|token)|dummy|sample[_-]?(key|secret|token)/i

function isPlaceholder(value) {
  if (PLACEHOLDER_EXACT.test(value)) return true
  if (PLACEHOLDER_SUBSTRING.test(value)) return true
  // A string that's the same character repeated (e.g. "aaaaaaaaaaaaaaaa") is
  // never a real credential.
  if (/^(.)\1+$/.test(value)) return true
  return false
}

// Scans a chunk of publicly-fetched text (HTML, JS bundle, .env contents)
// for secret-shaped strings. Returns findings with the value already
// redacted — callers should never have access to the raw match.
export function scanForExposedSecrets(text, sourceLabel) {
  if (!text) return []
  const findings = []
  const seenValues = new Set() // de-dupe by raw value so one leaked secret
  // that happens to satisfy two different patterns (e.g. a generic
  // "token=" assignment that is also JWT-shaped) is only reported once.

  const allPatterns = [...PREFIXED_PATTERNS, ...ASSIGNMENT_PATTERNS]

  for (const { name, pattern } of allPatterns) {
    const matches = text.matchAll(pattern)
    for (const match of matches) {
      const raw = match[1] || match[2] || match[0]
      if (!raw || isPlaceholder(raw)) continue
      if (seenValues.has(raw)) continue
      seenValues.add(raw)

      findings.push({
        name: `Exposed ${name} in ${sourceLabel}`,
        severity: 'Critical',
        category: 'Secret Exposure',
        description: `A string matching the pattern for a ${name} was found publicly accessible in ${sourceLabel}. The value has been redacted here for safety — SentinelAI never stores or displays exposed secrets in full.`,
        impact: 'Anyone who views this publicly-accessible content can copy this credential and use it to access whatever service it authenticates — cloud infrastructure, a payment processor, an AI API, or your database, depending on what it is.',
        fix: `Rotate this credential immediately (treat it as compromised — assume it has already been seen), remove it from ${sourceLabel}, and move it to a server-side environment variable that is never sent to the browser or committed to source control.`,
        redactedPreview: redact(raw),
      })
    }
  }
  return findings
}