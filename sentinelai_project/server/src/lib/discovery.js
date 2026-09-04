// Real asset discovery, scoped honestly to what's achievable from a
// server-side scanner (no agent installed on the customer's LAN).
//
// Full "network discovery" as described in the proposal (finding every
// laptop, printer, and IoT device on a business's local network) requires
// an on-premises agent or network tap — that's a real product component,
// not something a cloud API can do by itself. What a cloud service *can*
// legitimately do is enumerate an organization's internet-facing footprint:
// common subdomains of a domain the user already owns. This is the same
// technique real tools like Amass or Sublist3r use for external attack
// surface discovery.

import dns from 'node:dns/promises'

const COMMON_SUBDOMAINS = [
  'www', 'api', 'app', 'admin', 'staging', 'dev', 'test', 'mail',
  'portal', 'dashboard', 'vpn', 'remote', 'shop', 'store', 'blog',
  'cdn', 'static', 'media', 'docs', 'status', 'support', 'help',
]

export async function discoverSubdomains(rootDomain, { limit = 12 } = {}) {
  const clean = rootDomain.replace(/^https?:\/\//, '').replace(/\/.*$/, '')
  const candidates = COMMON_SUBDOMAINS.map((sub) => `${sub}.${clean}`)

  const results = await Promise.allSettled(
    candidates.map(async (host) => {
      const addresses = await dns.resolve4(host).catch(() => dns.resolve6(host))
      return { host, addresses }
    })
  )

  const found = results
    .filter((r) => r.status === 'fulfilled' && r.value.addresses?.length)
    .map((r) => r.value)

  return found.slice(0, limit)
}
