// SentinelAI Scanning Engine
//
// Performs passive, non-intrusive checks against a target the user has added
// as one of their own assets: HTTP response headers, TLS certificate/protocol
// health, DNS resolution, cookie flags, subdomain takeover fingerprints,
// mixed content, information disclosure, outdated client-side libraries, and
// email-spoofing (SPF/DMARC) posture. This intentionally avoids anything
// exploit-like (no credential brute-forcing, no payload injection, no port
// sweeps of hosts outside what the user has registered). Every check here is
// either a single ordinary GET/HEAD request, a TLS handshake, or a DNS
// lookup — the same things a browser or curious visitor's browser already
// does. Findings are mapped to severity-rated vulnerability records the same
// way a real scanner would.

import tls from 'node:tls'
import dns from 'node:dns/promises'
import { logger } from './logger.js'
import { scanForExposedSecrets } from './secretScanner.js'

// ---------------------------------------------------------------------------
// Banner -> CVE correlation (OSV.dev)
// ---------------------------------------------------------------------------

// Maps a common server banner (e.g. "nginx/1.18.0") to an OSV.dev
// ecosystem + package name so we can query for known CVEs. This is a
// small, extensible table — real coverage would grow this list.
const BANNER_ECOSYSTEM_MAP = [
  { pattern: /nginx\/([\d.]+)/i, ecosystem: 'Debian', name: 'nginx' },
  { pattern: /apache\/([\d.]+)/i, ecosystem: 'Debian', name: 'apache2' },
  { pattern: /openssl\/([\d.]+)/i, ecosystem: 'OSS-Fuzz', name: 'openssl' },
  { pattern: /php\/([\d.]+)/i, ecosystem: 'PyPI', name: 'php' }, // best-effort; OSV PHP coverage is limited
]

// Best-effort banner → CVE correlation using the free OSV.dev API (no key
// required). Network access to api.osv.dev must be permitted from wherever
// this server is deployed — it fails soft (returns no findings) if the
// request can't be made, so it never blocks a scan.
export async function correlateBannerCves(headers) {
  const banner = [headers.get('server'), headers.get('x-powered-by')].filter(Boolean).join(' ')
  if (!banner) return []

  const findings = []
  for (const rule of BANNER_ECOSYSTEM_MAP) {
    const match = banner.match(rule.pattern)
    if (!match) continue
    const version = match[1]
    try {
      const res = await fetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ version, package: { name: rule.name, ecosystem: rule.ecosystem } }),
        signal: AbortSignal.timeout(6000),
      })
      if (!res.ok) continue
      const data = await res.json()
      for (const vuln of (data.vulns || []).slice(0, 5)) {
        findings.push({
          name: `Known vulnerability in ${rule.name} ${version}${vuln.aliases?.[0] ? ` (${vuln.aliases[0]})` : ''}`,
          severity: severityFromOsv(vuln),
          category: 'Software Vulnerability',
          cve: vuln.aliases?.find((a) => a.startsWith('CVE-')) || vuln.id,
          description: (vuln.summary || vuln.details || `A known vulnerability affects ${rule.name} ${version}.`).slice(0, 500),
          impact: 'This software version has a publicly disclosed vulnerability. Depending on the flaw, an attacker may be able to compromise the service.',
          fix: `Upgrade ${rule.name} past version ${version} to a patched release, then re-scan to confirm.`,
        })
      }
    } catch (err) {
      logger.warn({ err: String(err.message || err), rule: rule.name }, 'OSV lookup failed, skipping')
    }
  }
  return findings
}

function severityFromOsv(vuln) {
  const severityStr = JSON.stringify(vuln.severity || vuln.database_specific || '').toLowerCase()
  if (severityStr.includes('critical')) return 'Critical'
  if (severityStr.includes('high')) return 'High'
  if (severityStr.includes('medium') || severityStr.includes('moderate')) return 'Medium'
  return 'Low'
}

// ---------------------------------------------------------------------------
// Exposed sensitive files
// ---------------------------------------------------------------------------

// Checks for accidentally-exposed sensitive files. Every one of these is a
// single, ordinary GET request to a path a browser could load — this is
// exactly the same "did you leave the door unlocked" check any scanner
// (or a curious stranger) could do, not an exploitation technique.
const SENSITIVE_PATHS = [
  { path: '/.env', looksExposed: (body) => /^[A-Z0-9_]+=.+/m.test(body) },
  { path: '/.env.local', looksExposed: (body) => /^[A-Z0-9_]+=.+/m.test(body) },
  { path: '/.git/config', looksExposed: (body) => body.includes('[core]') || body.includes('[remote') },
  { path: '/.git/HEAD', looksExposed: (body) => body.trim().startsWith('ref:') },
  { path: '/package.json', looksExposed: (body) => body.includes('"dependencies"') || body.includes('"name"') },
  { path: '/config.json', looksExposed: (body) => body.trim().startsWith('{') },
  { path: '/.aws/credentials', looksExposed: (body) => body.includes('aws_access_key_id') },
  { path: '/id_rsa', looksExposed: (body) => body.includes('PRIVATE KEY') },
  { path: '/.htpasswd', looksExposed: (body) => /^[^:\s]+:\$/m.test(body) },
  { path: '/backup.sql', looksExposed: (body) => /create table|insert into/i.test(body) },
  { path: '/database.sql', looksExposed: (body) => /create table|insert into/i.test(body) },
  { path: '/dump.sql', looksExposed: (body) => /create table|insert into/i.test(body) },
  { path: '/wp-config.php.bak', looksExposed: (body) => body.includes('DB_PASSWORD') || body.includes('<?php') },
  { path: '/config.php.bak', looksExposed: (body) => body.includes('<?php') || /password/i.test(body) },
  { path: '/server-status', looksExposed: (body) => body.includes('Apache Server Status') },
  { path: '/phpinfo.php', looksExposed: (body) => body.includes('phpinfo()') || body.includes('PHP Version') },
]

async function checkExposedFiles(hostname) {
  const findings = []
  for (const { path, looksExposed } of SENSITIVE_PATHS) {
    try {
      const res = await fetch(`https://${hostname}${path}`, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(5000),
      })
      if (res.status !== 200) continue
      const body = await res.text()
      if (!looksExposed(body)) continue

      if (path === '/.env' || path === '/.env.local') {
        findings.push({
          name: `Publicly accessible ${path} file`,
          severity: 'Critical',
          category: 'Secret Exposure',
          description: `The ${path} file, which typically holds database credentials, API keys, and other secrets, is directly downloadable from the web root.`,
          impact: 'Anyone can download this file and obtain every secret your application uses, including database and third-party API credentials.',
          fix: `Remove ${path} from the public web root (it should never be deployed alongside static assets), rotate every credential it contained, and add it to your deployment ignore rules.`,
        })
        findings.push(...scanForExposedSecrets(body, `${path} file`).map((f) => ({ ...f })))
      } else if (path.startsWith('/.git')) {
        findings.push({
          name: 'Publicly accessible .git directory',
          severity: 'High',
          category: 'Source Exposure',
          description: `The ${path} file is publicly downloadable, meaning your application's git repository (potentially including full source code and commit history) may be reconstructable.`,
          impact: 'Source code, commit history, and anything ever committed (including old secrets that were later "removed") can be extracted by an attacker.',
          fix: 'Block access to dotfiles/.git at your web server or CDN layer (this is a one-line rule in nginx/Apache/most CDNs), and treat any secret ever committed as compromised.',
        })
      } else if (path === '/package.json') {
        findings.push({
          name: 'package.json publicly accessible',
          severity: 'Low',
          category: 'Information Disclosure',
          description: 'Your package.json, listing exact dependency versions, is served directly.',
          impact: 'Low risk on its own, but it hands an attacker a precise map of your dependency versions to check against known vulnerabilities.',
          fix: 'Not usually worth blocking directly, but make sure your deployment only serves your build output directory, not your whole project folder.',
        })
      } else if (path === '/id_rsa' || path === '/.htpasswd' || path === '/.aws/credentials') {
        findings.push({
          name: `Credential file (${path}) publicly exposed`,
          severity: 'Critical',
          category: 'Secret Exposure',
          description: `${path} is directly downloadable from the web root. SentinelAI confirmed it exists and matches the expected format for this file type — the contents themselves were not read into this report.`,
          impact: 'This file format is specifically used to store credentials or private keys. Anyone can download and use it directly.',
          fix: `Remove ${path} from the public web root immediately and rotate/revoke whatever it authenticates (SSH key, password hash file, or AWS keys).`,
        })
      } else if (['/backup.sql', '/database.sql', '/dump.sql'].includes(path)) {
        findings.push({
          name: 'Database backup file publicly exposed',
          severity: 'Critical',
          category: 'Secret Exposure',
          description: `${path} is publicly downloadable and its content matches the structure of a SQL database dump. SentinelAI did not read or store its contents beyond this structural check.`,
          impact: 'A database dump can expose your entire user/customer table, including password hashes and personal data, to anyone who finds this URL.',
          fix: `Remove ${path} from the public web root immediately, and treat every credential/PII in it as compromised — force a password reset if user password hashes were included.`,
        })
      } else if (path.includes('config.php.bak')) {
        findings.push({
          name: 'Backup config file publicly exposed',
          severity: 'High',
          category: 'Secret Exposure',
          description: `${path} is publicly downloadable. Backup files (.bak, ~, .old) are typically not processed as code by the web server, so their raw contents — often including database credentials — are served as plain text.`,
          impact: 'Database and application credentials in this file could give an attacker direct access to your backend systems.',
          fix: `Remove ${path} from the public web root, and audit your deploy process for other stray backup files (search for *.bak, *~, *.old, *.orig).`,
        })
      } else if (path === '/server-status') {
        findings.push({
          name: 'Apache server-status page publicly exposed',
          severity: 'Medium',
          category: 'Information Disclosure',
          description: 'The mod_status diagnostic page is publicly accessible, revealing live request data, internal IPs, and server configuration.',
          impact: 'Gives an attacker real-time visibility into server internals and traffic patterns.',
          fix: 'Restrict /server-status to localhost or a trusted IP range in your Apache config, or disable mod_status if unused.',
        })
      } else if (path === '/phpinfo.php') {
        findings.push({
          name: 'phpinfo() debug page publicly exposed',
          severity: 'High',
          category: 'Information Disclosure',
          description: 'A phpinfo() output page is publicly accessible, revealing detailed server configuration, file system paths, and installed module versions.',
          impact: 'Gives an attacker a detailed map of your server environment to identify further attack vectors.',
          fix: 'Delete this file from production — phpinfo() should never be deployed to a live server.',
        })
      } else {
        findings.push({
          name: `Publicly accessible ${path}`,
          severity: 'Medium',
          category: 'Information Disclosure',
          description: `${path} is directly downloadable and appears to contain configuration or credential data.`,
          impact: 'Configuration details or credentials in this file could aid an attacker in understanding or accessing your systems.',
          fix: `Remove ${path} from your public web root, or restrict access to it at your web server/CDN.`,
        })
      }
    } catch {
      continue // unreachable path is not a finding — that's the expected/safe state
    }
  }
  return findings
}

// ---------------------------------------------------------------------------
// Client-side secret exposure
// ---------------------------------------------------------------------------

// Checks the homepage's rendered HTML/JS for secrets baked into client-side
// code — extremely common when an API key meant for server-side use gets
// pasted into frontend code (a frequent mistake in AI-assisted app builds,
// since generated frontend snippets often call third-party APIs directly).
async function checkClientSideSecrets(hostname) {
  try {
    const res = await fetch(`https://${hostname}`, { redirect: 'follow', signal: AbortSignal.timeout(8000) })
    const html = await res.text()
    const findings = scanForExposedSecrets(html, 'the homepage HTML/JS')

    // Follow same-origin script tags one level deep — this is where secrets
    // baked into a bundled JS file usually actually live.
    const scriptSrcs = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
      .map((m) => m[1])
      .filter((src) => !src.startsWith('http') || src.includes(hostname))
      .slice(0, 5) // cap how many bundles we fetch per scan

    for (const src of scriptSrcs) {
      try {
        const scriptUrl = src.startsWith('http') ? src : new URL(src, `https://${hostname}`).toString()
        const scriptRes = await fetch(scriptUrl, { signal: AbortSignal.timeout(6000) })
        const js = await scriptRes.text()
        findings.push(...scanForExposedSecrets(js, `a client-side JS bundle (${src})`))
      } catch {
        continue
      }
    }
    return findings
  } catch {
    return []
  }
}

// ---------------------------------------------------------------------------
// CORS misconfiguration
// ---------------------------------------------------------------------------

// Flags a dangerously permissive CORS configuration: wildcard origin
// combined with credentials allowed is invalid per spec in browsers, but
// misconfigured servers sometimes reflect the request's Origin header
// instead, which effectively grants any website read access to
// authenticated responses.
async function checkCorsMisconfiguration(hostname) {
  try {
    const probeOrigin = 'https://sentinelai-cors-probe.example'
    const res = await fetch(`https://${hostname}`, {
      headers: { Origin: probeOrigin },
      signal: AbortSignal.timeout(6000),
    })
    const allowOrigin = res.headers.get('access-control-allow-origin')
    const allowCreds = res.headers.get('access-control-allow-credentials')
    if (allowOrigin === probeOrigin && allowCreds === 'true') {
      return [{
        name: 'Permissive CORS configuration reflects any origin',
        severity: 'High',
        category: 'Web Application Security',
        description: 'The server reflects any Origin header back in Access-Control-Allow-Origin while also allowing credentials, rather than restricting to a known allowlist.',
        impact: 'Any website a logged-in user visits could make authenticated requests to this API on their behalf and read the response — a common route to account takeover.',
        fix: 'Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins instead of reflecting the request origin, especially on any endpoint that also sets Access-Control-Allow-Credentials: true.',
      }]
    }
  } catch {
    // ignore
  }
  return []
}

// ---------------------------------------------------------------------------
// NEW: Cookie security flags
// ---------------------------------------------------------------------------

// Parses raw Set-Cookie header values (fetch's Headers merges multiple
// Set-Cookie into one comma-joined string in some runtimes, so we split
// defensively) and flags cookies missing Secure/HttpOnly/SameSite.
function splitSetCookieHeader(raw) {
  if (!raw) return []
  // Set-Cookie values can legitimately contain commas (inside Expires=...),
  // so split only on a comma that is followed by a new "name=value" pair,
  // recognizable by not being immediately preceded by a weekday-style date.
  return raw.split(/,(?=\s*[^=;,\s]+=)/g).map((s) => s.trim())
}

function checkCookieSecurity(rawSetCookieHeader, isHttps) {
  const cookies = splitSetCookieHeader(rawSetCookieHeader)
  const findings = []
  for (const cookie of cookies) {
    const [nameValue] = cookie.split(';')
    const cookieName = (nameValue || '').split('=')[0]?.trim() || 'unnamed cookie'
    const lower = cookie.toLowerCase()
    const looksLikeSessionCookie = /session|auth|token|sid|jwt|login/i.test(cookieName)

    const missing = []
    if (isHttps && !lower.includes('secure')) missing.push('Secure')
    if (!lower.includes('httponly')) missing.push('HttpOnly')
    if (!lower.includes('samesite')) missing.push('SameSite')

    if (missing.length === 0) continue

    findings.push({
      name: `Cookie "${cookieName}" missing ${missing.join(', ')} flag${missing.length > 1 ? 's' : ''}`,
      severity: looksLikeSessionCookie && missing.includes('HttpOnly') ? 'High' : 'Medium',
      category: 'Cookie Security',
      description: `The "${cookieName}" cookie is set without the ${missing.join(', ')} attribute${missing.length > 1 ? 's' : ''}.`,
      impact: missing.includes('HttpOnly')
        ? 'Without HttpOnly, this cookie is readable by JavaScript — if an attacker ever manages to inject a script (XSS), they could steal this cookie directly, including session tokens.'
        : missing.includes('Secure')
          ? 'Without Secure, this cookie can be sent over plain HTTP, so it could be intercepted on an untrusted network (e.g. public Wi-Fi).'
          : 'Without SameSite, this cookie is sent on cross-site requests, which can enable cross-site request forgery (CSRF) attacks.',
      fix: `Add the ${missing.join(' and ')} attribute${missing.length > 1 ? 's' : ''} when setting this cookie (e.g. Set-Cookie: ${cookieName}=...; Secure; HttpOnly; SameSite=Lax).`,
    })
  }
  return findings
}

// ---------------------------------------------------------------------------
// NEW: TLS depth — protocol version, self-signed, hostname mismatch
// (also replaces the old expiry-only checkTlsCertificate)
// ---------------------------------------------------------------------------

const WEAK_TLS_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'])

function hostnameMatchesCert(hostname, cert) {
  // Node already validates this for us via socket.authorized when we don't
  // pass rejectUnauthorized:false — but we intentionally disable that below
  // so we can inspect *why* a cert is invalid rather than just failing the
  // connection, so we re-derive a best-effort match here for reporting.
  const names = new Set()
  if (cert.subject?.CN) names.add(cert.subject.CN.toLowerCase())
  const san = cert.subjectaltname || ''
  for (const entry of san.split(',')) {
    const m = entry.trim().match(/^DNS:(.+)$/i)
    if (m) names.add(m[1].toLowerCase())
  }
  const target = hostname.toLowerCase()
  for (const name of names) {
    if (name === target) return true
    if (name.startsWith('*.') && target.endsWith(name.slice(1))) return true
  }
  return false
}

async function checkTlsCertificate(hostname) {
  return new Promise((resolve) => {
    const findings = []
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        timeout: 8000,
        // Deliberately accept invalid/expired/self-signed certs at the
        // handshake level — the whole point of this check is to inspect
        // *why* a cert is broken and report it, not to fail silently the
        // way a normal HTTPS client would.
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate()
        const protocol = socket.getProtocol() // e.g. 'TLSv1.2', 'TLSv1.3'
        const authorized = socket.authorized
        const authError = socket.authorizationError

        if (!cert || Object.keys(cert).length === 0) {
          socket.end()
          return resolve({ findings, protocol })
        }

        // Expiry
        if (cert.valid_to) {
          const expiresAt = new Date(cert.valid_to)
          const daysLeft = Math.floor((expiresAt.getTime() - Date.now()) / 86400000)
          if (daysLeft < 0) {
            findings.push({
              name: 'Expired TLS certificate',
              severity: 'Critical',
              category: 'Transport Security',
              description: `The TLS certificate for ${hostname} expired on ${cert.valid_to}.`,
              impact: 'Visitors will see security warnings and modern browsers may block access entirely, and any encrypted traffic guarantees are void.',
              fix: 'Renew the TLS certificate immediately through your certificate authority or hosting provider, then restart the web server.',
            })
          } else if (daysLeft < 21) {
            findings.push({
              name: 'TLS certificate expiring soon',
              severity: 'Medium',
              category: 'Transport Security',
              description: `The TLS certificate for ${hostname} expires in ${daysLeft} day(s) (on ${cert.valid_to}).`,
              impact: 'If it lapses, visitors will see browser security warnings and encrypted connections may fail.',
              fix: "Renew the certificate now, and consider automating renewal (e.g. via Let's Encrypt/certbot) to prevent this recurring.",
            })
          }
        }

        // Self-signed / untrusted issuer
        const isSelfSigned = cert.issuerCertificate === cert || (!authorized && /self signed/i.test(authError || ''))
        if (isSelfSigned || (!authorized && /self.signed|unable to verify the first certificate|unable to get local issuer/i.test(authError || ''))) {
          findings.push({
            name: 'Self-signed or untrusted TLS certificate',
            severity: 'Critical',
            category: 'Transport Security',
            description: `The certificate presented for ${hostname} is not signed by a certificate authority trusted by browsers (${authError || 'self-signed'}).`,
            impact: 'Every visitor will see a "connection is not private" browser warning, and no real encryption/identity guarantee is provided — this trains users to click through security warnings, which attackers exploit elsewhere.',
            fix: "Issue a certificate from a trusted CA (e.g. via Let's Encrypt, which is free) instead of a self-signed one, and configure your web server to use it.",
          })
        } else if (!authorized && authError && !/expire/i.test(authError)) {
          // Any other trust failure not already covered above (e.g. chain issues)
          findings.push({
            name: 'TLS certificate is not trusted',
            severity: 'High',
            category: 'Transport Security',
            description: `The TLS certificate chain for ${hostname} failed validation: ${authError}.`,
            impact: 'Browsers will warn visitors that the connection may not be secure, and automated clients/integrations may refuse to connect at all.',
            fix: 'Ensure the full certificate chain (leaf + intermediates) is installed on the server, from a CA trusted by major browsers.',
          })
        }

        // Hostname mismatch
        if (!hostnameMatchesCert(hostname, cert)) {
          findings.push({
            name: 'TLS certificate does not match hostname',
            severity: 'Critical',
            category: 'Transport Security',
            description: `The certificate served for ${hostname} was not issued for this hostname (CN/SAN mismatch).`,
            impact: "Browsers will block or heavily warn on this mismatch, and it likely means visitors are reaching the wrong certificate (misconfigured server block, or a sign of a man-in-the-middle) — either way the site's identity can't be verified.",
            fix: 'Issue or install a certificate whose Common Name or Subject Alternative Names include this exact hostname.',
          })
        }

        // Weak protocol version
        if (protocol && WEAK_TLS_PROTOCOLS.has(protocol)) {
          findings.push({
            name: `Outdated TLS protocol in use (${protocol})`,
            severity: protocol.startsWith('SSL') ? 'Critical' : 'High',
            category: 'Transport Security',
            description: `The server negotiated ${protocol}, which is deprecated and known to have cryptographic weaknesses.`,
            impact: 'Modern browsers are phasing out or already blocking these protocol versions, and known attacks (e.g. POODLE, BEAST) target them specifically.',
            fix: 'Disable TLS 1.0/1.1 and all SSL versions in your web server config, requiring TLS 1.2 or, ideally, TLS 1.3 only.',
          })
        }

        socket.end()
        resolve({ findings, protocol })
      }
    )
    socket.on('error', () => resolve({ findings: [], protocol: null }))
    socket.on('timeout', () => {
      socket.destroy()
      resolve({ findings: [], protocol: null })
    })
  })
}

// ---------------------------------------------------------------------------
// NEW: HTTP -> HTTPS redirect enforcement + mixed content
// ---------------------------------------------------------------------------

async function checkHttpRedirectEnforcement(hostname) {
  const findings = []
  try {
    const res = await fetch(`http://${hostname}`, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(6000),
    })
    const location = res.headers.get('location') || ''
    const redirectsToHttps = [301, 302, 307, 308].includes(res.status) && location.startsWith('https://')
    if (!redirectsToHttps) {
      findings.push({
        name: 'Plain HTTP is not redirected to HTTPS',
        severity: 'Medium',
        category: 'Transport Security',
        description: `Requesting http://${hostname} directly did not redirect to an https:// URL (status ${res.status}).`,
        impact: 'Visitors who type the address without "https://", or follow an old http:// link, may load the site — or enter data — over an unencrypted connection that can be intercepted or tampered with.',
        fix: 'Configure your web server or load balancer to redirect all HTTP (port 80) traffic to HTTPS with a 301 redirect.',
      })
    }
  } catch {
    // Port 80 not listening at all is not itself a finding — HTTPS-only
    // hosting behind some CDNs legitimately does this.
  }
  return findings
}

async function checkMixedContent(hostname) {
  try {
    const res = await fetch(`https://${hostname}`, { redirect: 'follow', signal: AbortSignal.timeout(8000) })
    const html = await res.text()
    const insecureRefs = new Set()
    const patterns = [/src=["']http:\/\/([^"']+)["']/gi, /href=["']http:\/\/([^"']+)["']/gi]
    for (const pattern of patterns) {
      for (const match of html.matchAll(pattern)) {
        insecureRefs.add(match[1].split('/')[0])
      }
    }
    if (insecureRefs.size === 0) return []
    return [{
      name: 'Mixed content: insecure HTTP resources on an HTTPS page',
      severity: 'Medium',
      category: 'Transport Security',
      description: `The homepage (served over HTTPS) loads ${insecureRefs.size} resource(s) over plain HTTP, including from: ${[...insecureRefs].slice(0, 5).join(', ')}.`,
      impact: 'Browsers may block these resources outright or show a "not fully secure" warning, and each insecure resource is a point where content could be intercepted or tampered with in transit.',
      fix: 'Change every http:// resource reference on the page to https:// (or a protocol-relative // URL), including images, scripts, and stylesheets pulled from third parties.',
    }]
  } catch {
    return []
  }
}

// ---------------------------------------------------------------------------
// NEW: robots.txt / sitemap.xml disclosure
// ---------------------------------------------------------------------------

const INTERESTING_ROBOTS_PATTERNS = [
  /admin/i, /staging/i, /dev(?:elop)?/i, /internal/i, /backup/i, /test/i, /\.php$/i, /private/i, /api/i, /wp-admin/i,
]

async function checkRobotsAndSitemapDisclosure(hostname) {
  const findings = []
  try {
    const res = await fetch(`https://${hostname}/robots.txt`, { signal: AbortSignal.timeout(5000) })
    if (res.status === 200) {
      const body = await res.text()
      const disallowLines = body
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => /^Disallow:/i.test(l))
      const interesting = disallowLines.filter((l) => INTERESTING_ROBOTS_PATTERNS.some((p) => p.test(l)))
      if (interesting.length > 0) {
        findings.push({
          name: 'robots.txt discloses sensitive-looking paths',
          severity: 'Low',
          category: 'Information Disclosure',
          description: `robots.txt lists ${interesting.length} path(s) that look sensitive, e.g.: ${interesting.slice(0, 5).join(' | ')}.`,
          impact: "robots.txt is asking well-behaved crawlers not to index these paths, but it also hands anyone a directory of exactly which paths you'd rather they not find, including any that hint at admin panels or staging environments.",
          fix: "Don't rely on robots.txt to hide sensitive paths — it's publicly readable by design. Instead, require authentication on anything sensitive, and only list paths in robots.txt that are fine to be publicly known.",
        })
      }
    }
  } catch {
    // no robots.txt is fine
  }

  try {
    const res = await fetch(`https://${hostname}/sitemap.xml`, { signal: AbortSignal.timeout(5000) })
    if (res.status === 200) {
      const body = await res.text()
      const urls = [...body.matchAll(/<loc>(.*?)<\/loc>/gi)].map((m) => m[1])
      const interesting = urls.filter((u) => INTERESTING_ROBOTS_PATTERNS.some((p) => p.test(u)))
      if (interesting.length > 0) {
        findings.push({
          name: 'sitemap.xml discloses sensitive-looking URLs',
          severity: 'Low',
          category: 'Information Disclosure',
          description: `sitemap.xml lists ${interesting.length} URL(s) that look sensitive, e.g.: ${interesting.slice(0, 5).join(' | ')}.`,
          impact: 'A public sitemap is meant for search engines, but anyone can read it — including anyone looking for admin, staging, or internal-only pages that were accidentally included.',
          fix: 'Remove any admin, staging, internal, or test URLs from your public sitemap; keep it limited to pages meant for public search visibility.',
        })
      }
    }
  } catch {
    // no sitemap.xml is fine
  }

  return findings
}

// ---------------------------------------------------------------------------
// NEW: Directory listing enabled
// ---------------------------------------------------------------------------

const COMMON_DIRS_TO_PROBE = ['/images/', '/uploads/', '/assets/', '/files/', '/backup/', '/static/', '/media/']

function looksLikeDirectoryListing(body) {
  return /Index of \//i.test(body) || /<title>Index of/i.test(body) || /\[To Parent Directory\]/i.test(body)
}

async function checkDirectoryListing(hostname) {
  const findings = []
  for (const dir of COMMON_DIRS_TO_PROBE) {
    try {
      const res = await fetch(`https://${hostname}${dir}`, { method: 'GET', signal: AbortSignal.timeout(5000) })
      if (res.status !== 200) continue
      const body = await res.text()
      if (!looksLikeDirectoryListing(body)) continue
      findings.push({
        name: `Directory listing enabled at ${dir}`,
        severity: 'Medium',
        category: 'Information Disclosure',
        description: `Requesting ${dir} returns a browsable file listing instead of a 403/404 or an index page.`,
        impact: 'Anyone can browse and download every file in this directory, including ones never meant to be linked publicly (old backups, draft documents, unpublished images).',
        fix: 'Disable directory autoindexing in your web server config (e.g. "autoindex off;" in nginx, "Options -Indexes" in Apache) for any directory that should not be publicly browsable.',
      })
      break // one confirmed instance is enough signal; avoid noisy duplicate findings
    } catch {
      continue
    }
  }
  return findings
}

// ---------------------------------------------------------------------------
// NEW: Outdated / vulnerable client-side JS libraries
// ---------------------------------------------------------------------------

// Best-effort, small "known safe minimum version" table for extremely common
// libraries with well-documented old CVEs. Not exhaustive — real coverage
// would use a feed like the retire.js database — but catches the most common
// stale-library findings seen in the wild.
const JS_LIBRARY_VERSION_CHECKS = [
  {
    name: 'jQuery',
    detect: /jquery[.-](\d+\.\d+\.\d+)/i,
    minSafe: [3, 5, 0],
    advisory: 'Older jQuery versions have known XSS vulnerabilities in their HTML-parsing and attribute-handling functions (e.g. CVE-2020-11022, CVE-2020-11023).',
  },
  {
    name: 'Bootstrap',
    detect: /bootstrap[.-](\d+\.\d+\.\d+)/i,
    minSafe: [4, 3, 1],
    advisory: 'Older Bootstrap versions have known XSS vulnerabilities in tooltip/popover/carousel data attribute handling.',
  },
  {
    name: 'Lodash',
    detect: /lodash[.-@](\d+\.\d+\.\d+)/i,
    minSafe: [4, 17, 21],
    advisory: 'Older Lodash versions have known prototype-pollution vulnerabilities (e.g. CVE-2020-8203, CVE-2021-23337).',
  },
  {
    name: 'Angular.js (legacy AngularJS)',
    detect: /angular[.-](\d+\.\d+\.\d+)/i,
    minSafe: [1, 8, 3],
    advisory: 'Legacy AngularJS (1.x) reached end-of-life; older builds have known sandbox-bypass XSS vulnerabilities, and the whole 1.x line no longer receives security patches.',
  },
]

function isVersionBelow(version, minSafe) {
  const parts = version.split('.').map((n) => parseInt(n, 10))
  for (let i = 0; i < minSafe.length; i++) {
    const a = parts[i] || 0
    const b = minSafe[i]
    if (a < b) return true
    if (a > b) return false
  }
  return false
}

async function checkOutdatedJsLibraries(hostname) {
  const findings = []
  try {
    const res = await fetch(`https://${hostname}`, { redirect: 'follow', signal: AbortSignal.timeout(8000) })
    const html = await res.text()

    const scriptSrcs = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1]).slice(0, 15)
    const haystacks = [html, ...scriptSrcs] // library version is often visible right in the filename/URL

    // Also pull in the actual bundle text for same-origin scripts, one level
    // deep, since minified filenames sometimes strip the version number.
    for (const src of scriptSrcs.filter((s) => !s.startsWith('http') || s.includes(hostname)).slice(0, 5)) {
      try {
        const scriptUrl = src.startsWith('http') ? src : new URL(src, `https://${hostname}`).toString()
        const scriptRes = await fetch(scriptUrl, { signal: AbortSignal.timeout(6000) })
        haystacks.push(await scriptRes.text())
      } catch {
        continue
      }
    }

    const combined = haystacks.join('\n')
    const seen = new Set()
    for (const lib of JS_LIBRARY_VERSION_CHECKS) {
      const match = combined.match(lib.detect)
      if (!match) continue
      const version = match[1]
      if (seen.has(lib.name)) continue
      seen.add(lib.name)
      if (isVersionBelow(version, lib.minSafe)) {
        findings.push({
          name: `Outdated ${lib.name} version in use (${version})`,
          severity: 'Medium',
          category: 'Software Vulnerability',
          description: `${lib.name} version ${version} is loaded on the homepage. Versions before ${lib.minSafe.join('.')} have known public vulnerabilities.`,
          impact: lib.advisory,
          fix: `Upgrade ${lib.name} to the latest stable release (at least ${lib.minSafe.join('.')} or newer), then re-scan to confirm.`,
        })
      }
    }
  } catch {
    // homepage unreachable is reported elsewhere
  }
  return findings
}

// ---------------------------------------------------------------------------
// NEW: Subdomain takeover fingerprinting
// ---------------------------------------------------------------------------

// A small, well-known set of "dangling CNAME" fingerprints: text that
// appears on a service's default/unclaimed-page response. If a subdomain's
// CNAME points at one of these services but the service says nothing is
// configured there, an attacker can often register that endpoint themselves
// and serve content from the victim's subdomain.
const TAKEOVER_FINGERPRINTS = [
  { service: 'GitHub Pages', cnameHint: /github\.io$/i, bodyHint: /There isn't a GitHub Pages site here/i },
  { service: 'Heroku', cnameHint: /herokuapp\.com$/i, bodyHint: /No such app/i },
  { service: 'AWS S3', cnameHint: /s3.*amazonaws\.com$/i, bodyHint: /NoSuchBucket/i },
  { service: 'Shopify', cnameHint: /myshopify\.com$/i, bodyHint: /Sorry, this shop is currently unavailable/i },
  { service: 'Fastly', cnameHint: /fastly\.net$/i, bodyHint: /Fastly error: unknown domain/i },
  { service: 'Netlify', cnameHint: /netlify\.app$/i, bodyHint: /Not Found - Request ID/i },
  { service: 'Zendesk', cnameHint: /zendesk\.com$/i, bodyHint: /Help Center Closed/i },
  { service: 'Vercel', cnameHint: /vercel-dns\.com$|vercel\.app$/i, bodyHint: /DEPLOYMENT_NOT_FOUND/i },
]

// A short, common list of subdomains to probe when the user hasn't run
// dedicated subdomain discovery. This is intentionally small (common,
// low-noise names only) — full enumeration belongs in the "Discover
// subdomains" feature, not baked silently into every routine scan.
const COMMON_SUBDOMAINS = ['www', 'blog', 'shop', 'app', 'docs', 'status', 'help', 'cdn', 'static', 'staging', 'dev', 'api']

async function checkSubdomainTakeover(hostname) {
  const findings = []
  const apex = hostname.replace(/^www\./, '')

  for (const sub of COMMON_SUBDOMAINS) {
    const candidate = `${sub}.${apex}`
    if (candidate === hostname) continue
    let cnameChain = []
    try {
      cnameChain = await dns.resolveCname(candidate)
    } catch {
      continue // no CNAME (or subdomain doesn't exist) — nothing to check
    }
    if (cnameChain.length === 0) continue
    const cname = cnameChain[cnameChain.length - 1]

    const fingerprint = TAKEOVER_FINGERPRINTS.find((f) => f.cnameHint.test(cname))
    if (!fingerprint) continue

    try {
      const res = await fetch(`https://${candidate}`, { signal: AbortSignal.timeout(6000), redirect: 'follow' })
      const body = await res.text()
      if (fingerprint.bodyHint.test(body)) {
        findings.push({
          name: `Possible subdomain takeover: ${candidate}`,
          severity: 'Critical',
          category: 'Subdomain Takeover',
          description: `${candidate} has a CNAME pointing to ${cname} (${fingerprint.service}), but that service reports nothing is currently configured there.`,
          impact: `An attacker who notices this can often register/claim that ${fingerprint.service} endpoint themselves, and content will start serving from ${candidate} as if it were your own subdomain — commonly used for phishing, malware hosting, or stealing cookies scoped to your domain.`,
          fix: `Either remove the unused DNS CNAME record for ${candidate}, or re-claim/reconfigure the ${fingerprint.service} resource it points to.`,
        })
      }
    } catch {
      // If the dangling endpoint doesn't even respond, treat the DNS
      // pointer itself as the finding — it's still worth cleaning up.
      findings.push({
        name: `Dangling DNS record: ${candidate}`,
        severity: 'Medium',
        category: 'Subdomain Takeover',
        description: `${candidate} has a CNAME pointing to ${cname} (${fingerprint.service}), which did not respond — this may be an unused/dangling DNS record.`,
        impact: 'An unused DNS record pointing at a third-party service is a common precursor to subdomain takeover if that service resource is ever claimed by someone else.',
        fix: `Remove the CNAME record for ${candidate} if it's no longer in use, or confirm the ${fingerprint.service} resource is still correctly owned by you.`,
      })
    }
  }
  return findings
}

// ---------------------------------------------------------------------------
// NEW: Email spoofing posture — SPF / DMARC
// ---------------------------------------------------------------------------

async function checkEmailSecurity(hostname) {
  const apex = hostname.replace(/^www\./, '')
  const findings = []

  try {
    const txtRecords = await dns.resolveTxt(apex)
    const flat = txtRecords.map((r) => r.join(''))
    const spf = flat.find((r) => r.toLowerCase().startsWith('v=spf1'))
    if (!spf) {
      findings.push({
        name: 'No SPF record found',
        severity: 'Medium',
        category: 'Email Security',
        description: `No SPF (Sender Policy Framework) TXT record was found for ${apex}.`,
        impact: 'Without SPF, receiving mail servers have no way to verify that email claiming to be from your domain actually came from your authorized mail servers — making it easier for attackers to send convincing phishing emails that appear to come from your business.',
        fix: `Add a TXT record at ${apex} listing your authorized mail senders, e.g. "v=spf1 include:_spf.yourmailprovider.com ~all".`,
      })
    } else if (/[~?]all/.test(spf) === false && /-all/.test(spf) === false) {
      findings.push({
        name: 'SPF record does not specify an enforcement policy',
        severity: 'Low',
        category: 'Email Security',
        description: `The SPF record for ${apex} doesn't end with an explicit "~all" or "-all" mechanism.`,
        impact: 'Without a clear catch-all rule, SPF enforcement for unlisted senders is ambiguous, weakening its ability to block spoofed mail.',
        fix: 'End your SPF record with "~all" (soft fail) or "-all" (hard fail) once you\'ve confirmed all legitimate senders are listed.',
      })
    }
  } catch {
    findings.push({
      name: 'No SPF record found',
      severity: 'Medium',
      category: 'Email Security',
      description: `No TXT records (and therefore no SPF record) could be resolved for ${apex}.`,
      impact: 'Without SPF, it is easier for attackers to send phishing email that appears to come from your domain.',
      fix: `Add a TXT record at ${apex} listing your authorized mail senders, e.g. "v=spf1 include:_spf.yourmailprovider.com ~all".`,
    })
  }

  try {
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${apex}`)
    const flat = dmarcRecords.map((r) => r.join(''))
    const dmarc = flat.find((r) => r.toLowerCase().startsWith('v=dmarc1'))
    if (!dmarc) {
      findings.push({
        name: 'No DMARC record found',
        severity: 'Medium',
        category: 'Email Security',
        description: `No DMARC TXT record was found at _dmarc.${apex}.`,
        impact: 'Without DMARC, there is no policy telling receiving mail servers what to do with email that fails authentication checks, and you get no visibility (via DMARC reports) into who is sending email claiming to be from your domain — a common phishing/impersonation vector against your customers.',
        fix: `Add a TXT record at _dmarc.${apex}, e.g. "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${apex}" — start with "p=none" to monitor before enforcing.`,
      })
    } else if (/p=none/i.test(dmarc)) {
      findings.push({
        name: 'DMARC policy set to monitor-only (p=none)',
        severity: 'Low',
        category: 'Email Security',
        description: `The DMARC record for ${apex} is set to "p=none", which reports on failures but doesn't act on them.`,
        impact: 'Spoofed email impersonating your domain will still be delivered to recipients — monitor-only DMARC provides visibility but no actual protection.',
        fix: 'Once you\'ve reviewed DMARC reports and confirmed all legitimate senders pass, move the policy to "p=quarantine" and eventually "p=reject".',
      })
    }
  } catch {
    findings.push({
      name: 'No DMARC record found',
      severity: 'Medium',
      category: 'Email Security',
      description: `No DMARC TXT record could be resolved at _dmarc.${apex}.`,
      impact: 'Without DMARC, spoofed email impersonating your domain has no defined handling policy and you get no visibility into abuse of your domain in phishing attempts.',
      fix: `Add a TXT record at _dmarc.${apex}, e.g. "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${apex}".`,
    })
  }

  return findings
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

const SECURITY_HEADERS = [
  {
    header: 'strict-transport-security',
    name: 'Missing HSTS header',
    severity: 'Medium',
    category: 'Transport Security',
    description:
      'The site does not send a Strict-Transport-Security header, so browsers are not told to always use HTTPS for this domain.',
    impact:
      'Visitors on untrusted networks could be silently downgraded to an insecure HTTP connection and have their traffic intercepted.',
    fix: 'Add a Strict-Transport-Security response header (e.g. max-age=31536000; includeSubDomains) at your web server or CDN layer.',
  },
  {
    header: 'content-security-policy',
    name: 'Missing Content-Security-Policy header',
    severity: 'Medium',
    category: 'Web Application Security',
    description:
      'No Content-Security-Policy header was found, so the browser has no restrictions on which scripts or resources the page is allowed to load.',
    impact:
      'If an attacker manages to inject a script into a page (e.g. via a form field), the browser will run it with no restrictions, enabling data theft or session hijacking.',
    fix: 'Define a Content-Security-Policy header that whitelists only the script, style, and resource sources your app actually uses.',
  },
  {
    header: 'x-frame-options',
    name: 'Missing X-Frame-Options header',
    severity: 'Low',
    category: 'Web Application Security',
    description:
      'The site does not send an X-Frame-Options header, so it can be embedded inside another site\'s iframe.',
    impact:
      'This opens the door to "clickjacking," where an attacker overlays invisible buttons on your page to trick users into unintended clicks.',
    fix: "Add 'X-Frame-Options: DENY' or a frame-ancestors directive in your Content-Security-Policy header.",
  },
  {
    header: 'x-content-type-options',
    name: 'Missing X-Content-Type-Options header',
    severity: 'Low',
    category: 'Web Application Security',
    description:
      'The site does not send X-Content-Type-Options: nosniff, so browsers may guess ("sniff") file types instead of trusting the declared type.',
    impact:
      'An attacker-controlled file (e.g. an uploaded image) could be interpreted as executable script in some older browsers.',
    fix: "Add 'X-Content-Type-Options: nosniff' to your server's default response headers.",
  },
]

function generateFixScript(assetName, finding) {
  return `#!/bin/bash
# SentinelAI Suggested Fix — ${assetName}
# ${finding.name}
#
# Review carefully before running. This script is a DRAFT only —
# SentinelAI never executes patches without explicit human approval.

echo "[SentinelAI] Recommended remediation for: ${finding.name}"
echo "${finding.fix}"
echo
echo "[SentinelAI] No changes have been made. Apply this fix in your"
echo "web server, reverse proxy, or CDN configuration, then re-scan"
echo "this asset to confirm the header is now present."
`
}

async function checkHttpHeaders(hostname) {
  const results = []
  for (const scheme of ['https']) {
    try {
      const res = await fetch(`${scheme}://${hostname}`, {
        method: 'GET',
        redirect: 'follow',
        signal: AbortSignal.timeout(8000),
      })
      const headers = res.headers
      for (const check of SECURITY_HEADERS) {
        if (!headers.get(check.header)) {
          results.push({ ...check })
        }
      }
      results.__reachable = true
      results.__headers = headers
      return results
    } catch {
      continue
    }
  }
  results.__reachable = false
  return results
}

function normalizeHostname(target) {
  try {
    if (target.includes('://')) return new URL(target).hostname
    return new URL(`https://${target}`).hostname
  } catch {
    return target
  }
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

export async function runScan(asset) {
  const hostname = normalizeHostname(asset.target)
  const findings = []
  let reachable = true
  let dnsResolved = true

  try {
    await dns.lookup(hostname)
  } catch {
    dnsResolved = false
  }

  if (dnsResolved) {
    const headerFindings = await checkHttpHeaders(hostname)
    reachable = headerFindings.__reachable !== false
    findings.push(...headerFindings)

    if (reachable) {
      const tlsResult = await checkTlsCertificate(hostname)
      findings.push(...tlsResult.findings)

      if (headerFindings.__headers) {
        const cveFindings = await correlateBannerCves(headerFindings.__headers)
        findings.push(...cveFindings)

        const setCookieFindings = checkCookieSecurity(headerFindings.__headers.get('set-cookie'), true)
        findings.push(...setCookieFindings)
      }

      // Passive exposure + posture checks — every one of these is a single
      // ordinary GET/HEAD request, a TLS handshake, or a DNS lookup, run
      // in parallel to keep total scan time reasonable.
      const [
        exposedFileFindings,
        clientSecretFindings,
        corsFindings,
        redirectFindings,
        mixedContentFindings,
        robotsFindings,
        dirListingFindings,
        outdatedJsFindings,
        subdomainFindings,
        emailSecurityFindings,
      ] = await Promise.all([
        checkExposedFiles(hostname),
        checkClientSideSecrets(hostname),
        checkCorsMisconfiguration(hostname),
        checkHttpRedirectEnforcement(hostname),
        checkMixedContent(hostname),
        checkRobotsAndSitemapDisclosure(hostname),
        checkDirectoryListing(hostname),
        checkOutdatedJsLibraries(hostname),
        checkSubdomainTakeover(hostname),
        checkEmailSecurity(hostname),
      ])
      findings.push(
        ...exposedFileFindings,
        ...clientSecretFindings,
        ...corsFindings,
        ...redirectFindings,
        ...mixedContentFindings,
        ...robotsFindings,
        ...dirListingFindings,
        ...outdatedJsFindings,
        ...subdomainFindings,
        ...emailSecurityFindings,
      )
    }
  }

  if (!dnsResolved) {
    findings.push({
      name: 'Asset unreachable — DNS resolution failed',
      severity: 'High',
      category: 'Availability',
      description: `SentinelAI could not resolve ${hostname}. The asset may be offline, misconfigured, or the hostname may be incorrect.`,
      impact: 'Monitoring cannot assess this asset\'s security posture until it is reachable.',
      fix: 'Confirm the hostname is correct and that DNS records are published and propagated.',
    })
  } else if (!reachable) {
    findings.push({
      name: 'Asset unreachable over HTTPS',
      severity: 'Medium',
      category: 'Availability',
      description: `SentinelAI resolved ${hostname} but could not establish an HTTPS connection within the timeout window.`,
      impact: 'Monitoring cannot fully assess this asset\'s security posture while it is unreachable.',
      fix: 'Verify the web server is running and listening on port 443, and that firewall rules allow inbound HTTPS.',
    })
  }

  const vulnerabilities = findings.map((f) => ({
    ...f,
    script: generateFixScript(asset.name, f),
  }))

  return {
    hostname,
    dnsResolved,
    reachable,
    vulnerabilities,
  }
}