import { useState, useEffect } from 'react'
import type { AuthUser } from '../lib/api'
import { api, ApiError } from '../lib/api'

const PLANS = [
  {
    id: 'free',
    name: 'Free',
    price: '$0',
    period: '/mo',
    tagline: 'Get started',
    features: [
      { text: 'Up to 5 assets monitored', included: true },
      { text: 'Weekly automated scans', included: true },
      { text: 'Basic vulnerability list', included: true },
      { text: 'Email alerts', included: true },
      { text: 'AI plain-language explanations', included: false },
      { text: 'Attack path graph', included: false },
      { text: 'Human-approval patch workflow', included: false },
    ],
    current: false,
    cta: 'Downgrade to Free',
  },
  {
    id: 'premium',
    name: 'Premium Monitoring',
    price: '$149',
    period: '/mo',
    tagline: 'For growing teams',
    features: [
      { text: 'Up to 100 assets monitored', included: true },
      { text: 'Continuous 24/7 scanning', included: true },
      { text: 'AI plain-language explanations', included: true },
      { text: 'Interactive attack path mapper', included: true },
      { text: 'Human-approval patch workflow', included: true },
      { text: 'Executive PDF reports', included: true },
      { text: 'Dedicated CSM & SSO', included: false },
    ],
    current: true,
    cta: 'Current plan',
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: 'Custom',
    period: '',
    tagline: 'For large organizations',
    features: [
      { text: 'Unlimited assets monitored', included: true },
      { text: 'Continuous 24/7 scanning', included: true },
      { text: 'AI plain-language explanations', included: true },
      { text: 'Interactive attack path mapper', included: true },
      { text: 'Human-approval patch workflow', included: true },
      { text: 'Executive PDF reports', included: true },
      { text: 'Dedicated CSM, SSO & multi-tenant', included: true },
    ],
    current: false,
    cta: 'Contact sales',
  },
]

// Cloud provider scanning (auditing S3 buckets, security groups, IAM
// policies via each provider's own API) is real, valuable enterprise
// functionality — and genuinely not built yet. Showing it as "connected"
// with fake resource counts would be a false claim, so every entry here
// is honestly labeled as not yet available rather than faked.
const INTEGRATIONS = [
  { name: 'Microsoft Azure', short: 'Azure', status: 'roadmap' as const, icon: '◈', color: '#0089D6', detail: 'Not yet built — planned: audit storage account access policies and network security groups' },
  { name: 'Google Cloud Platform', short: 'GCP', status: 'roadmap' as const, icon: '◉', color: '#4285F4', detail: 'Not yet built — planned: audit Cloud Storage bucket ACLs and firewall rules' },
]

type Tab = 'users' | 'integrations' | 'developer' | 'billing'

export default function Settings({ user }: { user?: AuthUser }) {
  const [tab, setTab] = useState<Tab>('users')

  return (
    <div className="animate-fade-in-up" style={{ maxWidth: 920 }}>
      {/* Workspace header */}
      <div style={{
        background: '#131A22',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: 12,
        padding: '20px 24px',
        marginBottom: 20,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16,
      }}>
        <div>
          <div style={{ fontSize: 10, color: '#4A5D70', fontWeight: 700, letterSpacing: '0.6px', textTransform: 'uppercase', marginBottom: 5 }}>
            Current Workspace
          </div>
          <div style={{ fontSize: 20, fontWeight: 800, letterSpacing: '-0.4px', lineHeight: 1 }}>
            {user ? `${user.name}'s Workspace` : 'Your Workspace'}
          </div>
          <div style={{ fontSize: 11, color: '#4A5D70', marginTop: 5, fontFamily: "'JetBrains Mono', monospace" }}>
            {user ? `${user.email} · role: ${user.role}` : 'ws-id: unknown'}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 10 }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 7,
            padding: '8px 14px',
            background: 'rgba(34,197,94,0.07)', border: '1px solid rgba(34,197,94,0.18)',
            borderRadius: 8, fontSize: 12, color: '#22C55E', fontWeight: 600,
          }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            Data isolated from other workspaces
          </div>
          <TabBtn active={false} onClick={() => {}} label="Switch workspace" subtle />
        </div>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 20 }}>
        {([
          { id: 'users', label: 'Users & Roles' },
          { id: 'integrations', label: 'Cloud Integrations' },
          { id: 'developer', label: 'API & Webhooks' },
          { id: 'billing', label: 'Billing & Plans' },
        ] as const).map(t => (
          <TabBtn key={t.id} active={tab === t.id} onClick={() => setTab(t.id)} label={t.label} />
        ))}
      </div>

      {/* Tab: Users */}
      {tab === 'users' && <TeamTab currentUser={user} />}

      {/* Tab: Integrations */}
      {tab === 'integrations' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <AwsIntegrationCard canManage={user?.role === 'admin' || user?.role === 'analyst'} />
          {INTEGRATIONS.map(integ => (
            <IntegrationRow key={integ.name} integ={integ} />
          ))}
          <div style={{
            padding: '16px 20px',
            background: 'rgba(0,212,255,0.03)',
            border: '1px dashed rgba(0,212,255,0.15)',
            borderRadius: 12,
            fontSize: 12, color: '#4A5D70', textAlign: 'center',
          }}>
            More integrations coming soon: GitLab, Cloudflare, DigitalOcean, on-premise network scanners.
          </div>
        </div>
      )}

      {/* Tab: Developer (real API keys + webhooks) */}
      {tab === 'developer' && <DeveloperTab />}

      {/* Tab: Billing */}
      {tab === 'billing' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 14 }}>
          {PLANS.map(plan => (
            <PlanCard key={plan.id} plan={plan} />
          ))}
        </div>
      )}
    </div>
  )
}

function TabBtn({ active, onClick, label, subtle }: { active: boolean; onClick: () => void; label: string; subtle?: boolean }) {
  const [hovered, setHovered] = useState(false)
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        padding: '8px 16px', borderRadius: 8,
        background: active ? 'rgba(0,212,255,0.1)' : hovered ? 'rgba(255,255,255,0.05)' : subtle ? 'transparent' : 'rgba(255,255,255,0.03)',
        border: active ? '1px solid rgba(0,212,255,0.25)' : '1px solid rgba(255,255,255,0.07)',
        color: active ? '#00D4FF' : hovered ? '#C8D5E3' : '#8A9BB0',
        fontSize: 13, fontWeight: active ? 700 : 500,
        cursor: 'pointer',
        transition: 'all 0.12s',
      }}
    >
      {label}
    </button>
  )
}

function DeveloperTab() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{
        padding: '14px 18px', background: 'rgba(0,212,255,0.04)',
        border: '1px dashed rgba(0,212,255,0.18)', borderRadius: 10,
        fontSize: 12, color: '#8A9BB0', lineHeight: 1.6,
      }}>
        Built for enterprise integration: pull findings into your own SIEM, dashboard, or
        scripts with a scoped, read-only API key — or get pushed alerts the moment a
        critical finding shows up, via a signed webhook to Slack, PagerDuty, or your own endpoint.
      </div>
      <ApiKeysSection />
      <WebhooksSection />
    </div>
  )
}

function ApiKeysSection() {
  const [keys, setKeys] = useState<any[] | null>(null)
  const [name, setName] = useState('')
  const [creating, setCreating] = useState(false)
  const [revealedKey, setRevealedKey] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = () => api.apiKeys.list().then(r => setKeys(r.apiKeys)).catch(() => setKeys([]))
  useEffect(() => { load() }, [])

  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    setCreating(true)
    setError(null)
    try {
      const { rawKey } = await api.apiKeys.create(name.trim())
      setRevealedKey(rawKey)
      setName('')
      load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not create API key.')
    } finally {
      setCreating(false)
    }
  }

  const revoke = async (id: string) => {
    await api.apiKeys.revoke(id)
    load()
  }

  return (
    <div style={{ background: '#131A22', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12, padding: '18px 20px' }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: '#E8EFF7', marginBottom: 4 }}>API Keys</div>
      <div style={{ fontSize: 11.5, color: '#4A5D70', marginBottom: 14 }}>
        Read-only access to <code style={{ color: '#8A9BB0' }}>/api/v1/*</code> — assets, vulnerabilities, and summary. Cannot modify anything.
      </div>

      {revealedKey && (
        <div style={{
          padding: '12px 14px', marginBottom: 14, background: 'rgba(34,197,94,0.06)',
          border: '1px solid rgba(34,197,94,0.25)', borderRadius: 8,
        }}>
          <div style={{ fontSize: 11, color: '#22C55E', fontWeight: 700, marginBottom: 6 }}>
            ✓ Key created — copy it now, it won't be shown again
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <code style={{
              flex: 1, fontSize: 11.5, color: '#E8EFF7', background: '#0B0F14',
              padding: '7px 10px', borderRadius: 6, overflowX: 'auto', whiteSpace: 'nowrap',
            }}>
              {revealedKey}
            </code>
            <button onClick={() => navigator.clipboard.writeText(revealedKey)} style={{
              padding: '7px 10px', borderRadius: 6, background: 'rgba(255,255,255,0.06)',
              border: '1px solid rgba(255,255,255,0.1)', color: '#C8D5E3', fontSize: 11, cursor: 'pointer',
            }}>Copy</button>
            <button onClick={() => setRevealedKey(null)} style={{
              padding: '7px 10px', borderRadius: 6, background: 'transparent',
              border: 'none', color: '#4A5D70', fontSize: 11, cursor: 'pointer',
            }}>Dismiss</button>
          </div>
        </div>
      )}

      <form onSubmit={create} style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <input
          value={name} onChange={e => setName(e.target.value)}
          placeholder="e.g. Splunk integration"
          style={{
            flex: 1, padding: '8px 12px', background: '#0B0F14',
            border: '1px solid rgba(255,255,255,0.1)', borderRadius: 7,
            color: '#E8EFF7', fontSize: 12.5, outline: 'none',
          }}
        />
        <button type="submit" disabled={creating} style={{
          padding: '8px 16px', borderRadius: 7, background: '#00D4FF', border: 'none',
          color: '#0B0F14', fontSize: 12.5, fontWeight: 800, cursor: creating ? 'default' : 'pointer',
        }}>
          {creating ? 'Creating…' : '+ New key'}
        </button>
      </form>
      {error && <div style={{ fontSize: 11, color: '#FF7070', marginBottom: 12 }}>{error}</div>}

      {keys === null ? (
        <div style={{ fontSize: 12, color: '#4A5D70' }}>Loading…</div>
      ) : keys.length === 0 ? (
        <div style={{ fontSize: 12, color: '#4A5D70' }}>No API keys yet.</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {keys.map(k => (
            <div key={k.id} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '9px 12px', background: '#0B0F14', borderRadius: 7,
              border: '1px solid rgba(255,255,255,0.05)',
              opacity: k.revoked_at ? 0.5 : 1,
            }}>
              <div>
                <span style={{ fontSize: 12.5, fontWeight: 600, color: '#E8EFF7' }}>{k.name}</span>
                <span style={{ fontSize: 10.5, color: '#4A5D70', marginLeft: 10, fontFamily: "'JetBrains Mono', monospace" }}>
                  {k.key_prefix}… {k.revoked_at ? '(revoked)' : k.last_used_at ? `· last used ${k.last_used_at}` : '· never used'}
                </span>
              </div>
              {!k.revoked_at && (
                <button onClick={() => revoke(k.id)} style={{
                  padding: '4px 10px', borderRadius: 6, background: 'rgba(255,59,59,0.06)',
                  border: '1px solid rgba(255,59,59,0.2)', color: '#FF7070', fontSize: 11, cursor: 'pointer',
                }}>Revoke</button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function WebhooksSection() {
  const [webhooks, setWebhooks] = useState<any[] | null>(null)
  const [url, setUrl] = useState('')
  const [creating, setCreating] = useState(false)
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [testingId, setTestingId] = useState<string | null>(null)

  const load = () => api.webhooks.list().then(r => setWebhooks(r.webhooks)).catch(() => setWebhooks([]))
  useEffect(() => { load() }, [])

  const create = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!url.trim()) return
    setCreating(true)
    setError(null)
    try {
      const { secret } = await api.webhooks.create(url.trim())
      setRevealedSecret(secret)
      setUrl('')
      load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not create webhook.')
    } finally {
      setCreating(false)
    }
  }

  const test = async (id: string) => {
    setTestingId(id)
    try {
      await api.webhooks.test(id)
      load()
    } finally {
      setTestingId(null)
    }
  }

  const remove = async (id: string) => {
    await api.webhooks.remove(id)
    load()
  }

  return (
    <div style={{ background: '#131A22', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12, padding: '18px 20px' }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: '#E8EFF7', marginBottom: 4 }}>Webhooks</div>
      <div style={{ fontSize: 11.5, color: '#4A5D70', marginBottom: 14 }}>
        Pushes a signed JSON payload the moment a critical finding, scan, or patch decision happens — no polling required.
      </div>

      {revealedSecret && (
        <div style={{
          padding: '12px 14px', marginBottom: 14, background: 'rgba(34,197,94,0.06)',
          border: '1px solid rgba(34,197,94,0.25)', borderRadius: 8,
        }}>
          <div style={{ fontSize: 11, color: '#22C55E', fontWeight: 700, marginBottom: 6 }}>
            ✓ Webhook created — save this signing secret, it won't be shown again
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <code style={{
              flex: 1, fontSize: 11.5, color: '#E8EFF7', background: '#0B0F14',
              padding: '7px 10px', borderRadius: 6, overflowX: 'auto', whiteSpace: 'nowrap',
            }}>
              {revealedSecret}
            </code>
            <button onClick={() => navigator.clipboard.writeText(revealedSecret)} style={{
              padding: '7px 10px', borderRadius: 6, background: 'rgba(255,255,255,0.06)',
              border: '1px solid rgba(255,255,255,0.1)', color: '#C8D5E3', fontSize: 11, cursor: 'pointer',
            }}>Copy</button>
          </div>
          <div style={{ fontSize: 10.5, color: '#4A5D70', marginTop: 6 }}>
            Verify deliveries using HMAC-SHA256 against the <code>X-SentinelAI-Signature</code> header.
          </div>
        </div>
      )}

      <form onSubmit={create} style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <input
          value={url} onChange={e => setUrl(e.target.value)}
          placeholder="https://hooks.slack.com/services/…"
          style={{
            flex: 1, padding: '8px 12px', background: '#0B0F14',
            border: '1px solid rgba(255,255,255,0.1)', borderRadius: 7,
            color: '#E8EFF7', fontSize: 12.5, outline: 'none',
          }}
        />
        <button type="submit" disabled={creating} style={{
          padding: '8px 16px', borderRadius: 7, background: '#00D4FF', border: 'none',
          color: '#0B0F14', fontSize: 12.5, fontWeight: 800, cursor: creating ? 'default' : 'pointer',
        }}>
          {creating ? 'Creating…' : '+ Add webhook'}
        </button>
      </form>
      {error && <div style={{ fontSize: 11, color: '#FF7070', marginBottom: 12 }}>{error}</div>}

      {webhooks === null ? (
        <div style={{ fontSize: 12, color: '#4A5D70' }}>Loading…</div>
      ) : webhooks.length === 0 ? (
        <div style={{ fontSize: 12, color: '#4A5D70' }}>No webhooks configured yet.</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {webhooks.map(w => (
            <div key={w.id} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '9px 12px', background: '#0B0F14', borderRadius: 7,
              border: '1px solid rgba(255,255,255,0.05)',
            }}>
              <div style={{ minWidth: 0 }}>
                <span style={{ fontSize: 12, fontWeight: 600, color: '#E8EFF7', wordBreak: 'break-all' }}>{w.url}</span>
                <div style={{ fontSize: 10.5, color: '#4A5D70', marginTop: 2, fontFamily: "'JetBrains Mono', monospace" }}>
                  {w.events} {w.last_delivery_status ? `· last delivery: ${w.last_delivery_status}` : '· never delivered'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                <button onClick={() => test(w.id)} disabled={testingId === w.id} style={{
                  padding: '4px 10px', borderRadius: 6, background: 'rgba(0,212,255,0.06)',
                  border: '1px solid rgba(0,212,255,0.2)', color: '#00D4FF', fontSize: 11, cursor: 'pointer',
                }}>{testingId === w.id ? 'Sending…' : 'Send test'}</button>
                <button onClick={() => remove(w.id)} style={{
                  padding: '4px 10px', borderRadius: 6, background: 'rgba(255,59,59,0.06)',
                  border: '1px solid rgba(255,59,59,0.2)', color: '#FF7070', fontSize: 11, cursor: 'pointer',
                }}>Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ActionBtn({ label, primary, small, disabled, onClick }: { label: string; primary?: boolean; small?: boolean; disabled?: boolean; onClick?: () => void }) {
  const [hovered, setHovered] = useState(false)
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        padding: small ? '5px 12px' : '8px 16px',
        borderRadius: 8,
        background: disabled
          ? 'rgba(255,255,255,0.03)'
          : primary
          ? hovered ? '#00BFEA' : '#00D4FF'
          : hovered ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.05)',
        border: primary && !disabled ? 'none' : '1px solid rgba(255,255,255,0.08)',
        color: disabled ? '#3A4A5A' : primary ? '#0B0F14' : '#8A9BB0',
        fontSize: small ? 12 : 13, fontWeight: 700,
        cursor: disabled ? 'default' : 'pointer',
        transition: 'all 0.12s',
        whiteSpace: 'nowrap',
      }}
    >
      {label}
    </button>
  )
}

function TeamTab({ currentUser }: { currentUser?: AuthUser }) {
  const [members, setMembers] = useState<any[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showInvite, setShowInvite] = useState(false)
  const [revealedInvite, setRevealedInvite] = useState<{ email: string; tempPassword: string } | null>(null)

  const load = () => api.team.list().then(r => setMembers(r.members)).catch(() => setMembers([]))
  useEffect(() => { load() }, [])

  const isAdmin = currentUser?.role === 'admin'

  const handleRoleChange = async (userId: string, role: string) => {
    setError(null)
    try {
      await api.team.setRole(userId, role)
      load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not change role.')
    }
  }

  const handleRemove = async (userId: string) => {
    setError(null)
    try {
      await api.team.remove(userId)
      load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not remove member.')
    }
  }

  return (
    <div style={{ background: '#131A22', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12, overflow: 'hidden' }}>
      <div style={{ padding: '16px 22px', borderBottom: '1px solid rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#E8EFF7' }}>Team Members</div>
          <div style={{ fontSize: 12, color: '#4A5D70', marginTop: 2 }}>Manage who has access and what they can do.</div>
        </div>
        {isAdmin && <ActionBtn label="+ Invite member" primary onClick={() => setShowInvite(true)} />}
      </div>

      {error && (
        <div style={{ margin: '14px 22px 0', padding: '10px 14px', background: 'rgba(255,59,59,0.08)', border: '1px solid rgba(255,59,59,0.2)', borderRadius: 8, fontSize: 12, color: '#FF7070' }}>
          {error}
        </div>
      )}

      {revealedInvite && (
        <div style={{ margin: '14px 22px 0', padding: '12px 14px', background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.25)', borderRadius: 8 }}>
          <div style={{ fontSize: 11, color: '#22C55E', fontWeight: 700, marginBottom: 6 }}>
            ✓ {revealedInvite.email} added — share this temporary password with them (shown once)
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <code style={{ flex: 1, fontSize: 12, color: '#E8EFF7', background: '#0B0F14', padding: '7px 10px', borderRadius: 6 }}>
              {revealedInvite.tempPassword}
            </code>
            <button onClick={() => navigator.clipboard.writeText(revealedInvite.tempPassword)} style={{
              padding: '7px 10px', borderRadius: 6, background: 'rgba(255,255,255,0.06)',
              border: '1px solid rgba(255,255,255,0.1)', color: '#C8D5E3', fontSize: 11, cursor: 'pointer',
            }}>Copy</button>
            <button onClick={() => setRevealedInvite(null)} style={{ padding: '7px 10px', background: 'transparent', border: 'none', color: '#4A5D70', fontSize: 11, cursor: 'pointer' }}>Dismiss</button>
          </div>
        </div>
      )}

      {showInvite && (
        <InviteMemberForm
          onCreated={(member, tempPassword) => {
            setShowInvite(false)
            setRevealedInvite({ email: member.email, tempPassword })
            load()
          }}
          onCancel={() => setShowInvite(false)}
        />
      )}

      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ background: 'rgba(255,255,255,0.02)' }}>
            {['Member', 'Email', 'Role', 'Last active', ''].map((h, i) => (
              <th key={i} style={{
                padding: '10px 20px', textAlign: 'left',
                fontSize: 10, fontWeight: 700, color: '#4A5D70',
                letterSpacing: '0.6px', textTransform: 'uppercase',
                borderBottom: '1px solid rgba(255,255,255,0.06)',
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {members === null ? (
            <tr><td colSpan={5} style={{ padding: '20px', fontSize: 12, color: '#4A5D70' }}>Loading…</td></tr>
          ) : members.length === 0 ? (
            <tr><td colSpan={5} style={{ padding: '20px', fontSize: 12, color: '#4A5D70' }}>No team members found.</td></tr>
          ) : (
            members.map(m => (
              <TeamMemberRow
                key={m.id}
                member={m}
                isSelf={m.id === currentUser?.id}
                canManage={isAdmin}
                onRoleChange={(role) => handleRoleChange(m.id, role)}
                onRemove={() => handleRemove(m.id)}
              />
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}

function InviteMemberForm({ onCreated, onCancel }: { onCreated: (member: any, tempPassword: string) => void; onCancel: () => void }) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('viewer')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim() || !email.trim()) return
    setSubmitting(true)
    setError(null)
    try {
      const { member, tempPassword } = await api.team.invite(name.trim(), email.trim(), role)
      onCreated(member, tempPassword)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not invite member.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <form onSubmit={submit} style={{
      margin: '14px 22px 0', padding: '14px 16px',
      background: '#0B0F14', border: '1px dashed rgba(0,212,255,0.2)', borderRadius: 8,
      display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end',
    }}>
      <div>
        <label style={{ display: 'block', fontSize: 10, color: '#4A5D70', marginBottom: 4 }}>Name</label>
        <input value={name} onChange={e => setName(e.target.value)} autoFocus required style={{
          padding: '7px 10px', background: '#131A22', border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 6, color: '#E8EFF7', fontSize: 12.5, outline: 'none', width: 150,
        }} />
      </div>
      <div>
        <label style={{ display: 'block', fontSize: 10, color: '#4A5D70', marginBottom: 4 }}>Email</label>
        <input type="email" value={email} onChange={e => setEmail(e.target.value)} required style={{
          padding: '7px 10px', background: '#131A22', border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 6, color: '#E8EFF7', fontSize: 12.5, outline: 'none', width: 200,
        }} />
      </div>
      <div>
        <label style={{ display: 'block', fontSize: 10, color: '#4A5D70', marginBottom: 4 }}>Role</label>
        <select value={role} onChange={e => setRole(e.target.value)} style={{
          padding: '7px 10px', background: '#131A22', border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 6, color: '#E8EFF7', fontSize: 12.5, outline: 'none',
        }}>
          <option value="admin">Admin</option>
          <option value="analyst">Analyst</option>
          <option value="viewer">Viewer</option>
        </select>
      </div>
      <button type="submit" disabled={submitting} style={{
        padding: '8px 16px', borderRadius: 6, background: '#00D4FF', border: 'none',
        color: '#0B0F14', fontSize: 12.5, fontWeight: 800, cursor: submitting ? 'default' : 'pointer',
      }}>
        {submitting ? 'Adding…' : 'Add'}
      </button>
      <button type="button" onClick={onCancel} style={{
        padding: '8px 14px', borderRadius: 6, background: 'transparent', border: '1px solid rgba(255,255,255,0.1)',
        color: '#8A9BB0', fontSize: 12.5, cursor: 'pointer',
      }}>
        Cancel
      </button>
      {error && <div style={{ width: '100%', fontSize: 11, color: '#FF7070' }}>{error}</div>}
    </form>
  )
}

function TeamMemberRow({ member, isSelf, canManage, onRoleChange, onRemove }: {
  member: any; isSelf: boolean; canManage: boolean; onRoleChange: (role: string) => void; onRemove: () => void
}) {
  const [hovered, setHovered] = useState(false)
  const initials = member.name.split(' ').map((p: string) => p[0]).slice(0, 2).join('').toUpperCase()
  const roleColor: Record<string, string> = { admin: '#00D4FF', analyst: '#9B7FFF', viewer: '#8A9BB0' }

  return (
    <tr
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{ background: hovered ? 'rgba(255,255,255,0.02)' : 'transparent', transition: 'background 0.1s' }}
    >
      <td style={{ padding: '13px 20px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 32, height: 32, borderRadius: '50%',
            background: `${roleColor[member.role]}22`,
            border: `1px solid ${roleColor[member.role]}40`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 11, fontWeight: 800, color: roleColor[member.role],
            flexShrink: 0,
          }}>
            {initials}
          </div>
          <span style={{ fontSize: 13, fontWeight: 600, color: '#E8EFF7' }}>{member.name}{isSelf ? ' (you)' : ''}</span>
        </div>
      </td>
      <td style={{ padding: '13px 20px', borderBottom: '1px solid rgba(255,255,255,0.04)', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#8A9BB0' }}>
        {member.email}
      </td>
      <td style={{ padding: '13px 20px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
        {canManage ? (
          <select
            value={member.role}
            onChange={e => onRoleChange(e.target.value)}
            style={{
              padding: '4px 8px', borderRadius: 5, fontSize: 11, fontWeight: 700,
              background: `${roleColor[member.role]}18`, color: roleColor[member.role],
              border: `1px solid ${roleColor[member.role]}40`, cursor: 'pointer',
            }}
          >
            <option value="admin">admin</option>
            <option value="analyst">analyst</option>
            <option value="viewer">viewer</option>
          </select>
        ) : (
          <RoleBadge role={member.role} />
        )}
      </td>
      <td style={{ padding: '13px 20px', borderBottom: '1px solid rgba(255,255,255,0.04)', fontSize: 12, color: '#4A5D70', fontFamily: "'JetBrains Mono', monospace" }}>
        {member.last_login_at ?? 'never logged in'}
      </td>
      <td style={{ padding: '13px 20px', borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
        {canManage && !isSelf && (
          <button onClick={onRemove} style={{
            padding: '4px 10px', borderRadius: 6, background: 'rgba(255,59,59,0.06)',
            border: '1px solid rgba(255,59,59,0.2)', color: '#FF7070', fontSize: 11, cursor: 'pointer',
          }}>
            Remove
          </button>
        )}
      </td>
    </tr>
  )
}

function RoleBadge({ role }: { role: string }) {
  const colors: Record<string, { color: string; bg: string }> = {
    admin: { color: '#00D4FF', bg: 'rgba(0,212,255,0.1)' },
    analyst: { color: '#9B7FFF', bg: 'rgba(155,127,255,0.1)' },
    viewer: { color: '#8A9BB0', bg: 'rgba(138,155,176,0.1)' },
  }
  const s = colors[role] ?? colors.viewer
  return (
    <span style={{ padding: '3px 9px', borderRadius: 5, background: s.bg, color: s.color, fontSize: 11, fontWeight: 700, textTransform: 'capitalize' }}>
      {role}
    </span>
  )
}

function AwsIntegrationCard({ canManage }: { canManage: boolean }) {
  const [connection, setConnection] = useState<any | null | undefined>(undefined) // undefined = loading, null = not connected
  const [showConnectForm, setShowConnectForm] = useState(false)
  const [accessKeyId, setAccessKeyId] = useState('')
  const [secretAccessKey, setSecretAccessKey] = useState('')
  const [region, setRegion] = useState('us-east-1')
  const [connecting, setConnecting] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [scanResult, setScanResult] = useState<string | null>(null)

  const load = () => {
    api.cloud.list().then(r => {
      const aws = r.connections.find((c: any) => c.provider === 'aws')
      setConnection(aws ?? null)
    }).catch(() => setConnection(null))
  }
  useEffect(() => { load() }, [])

  const connect = async (e: React.FormEvent) => {
    e.preventDefault()
    setConnecting(true)
    setError(null)
    try {
      await api.cloud.connectAws(accessKeyId.trim(), secretAccessKey, region)
      setShowConnectForm(false)
      setAccessKeyId('')
      setSecretAccessKey('')
      load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not connect this AWS account.')
    } finally {
      setConnecting(false)
    }
  }

  const disconnect = async () => {
    await api.cloud.disconnectAws()
    load()
  }

  const scan = async () => {
    setScanning(true)
    setError(null)
    setScanResult(null)
    try {
      const { findingCount } = await api.cloud.scanAws()
      setScanResult(
        findingCount === 0
          ? 'Scan complete — no publicly exposed S3 buckets found.'
          : `Scan complete — ${findingCount} finding(s). Check the Vulnerabilities tab for details.`
      )
      load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'AWS scan failed.')
    } finally {
      setScanning(false)
    }
  }

  return (
    <div style={{
      background: '#131A22', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12, padding: '16px 20px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: connection || showConnectForm ? 14 : 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{
            width: 38, height: 38, borderRadius: 9, background: 'rgba(255,153,0,0.1)',
            border: '1px solid rgba(255,153,0,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 17, color: '#FF9900', flexShrink: 0,
          }}>⬡</div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 14, fontWeight: 700, color: '#E8EFF7' }}>Amazon Web Services</span>
              {connection && (
                <span style={{ padding: '2px 8px', borderRadius: 5, background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.25)', fontSize: 10, fontWeight: 700, color: '#22C55E' }}>
                  ✓ Connected
                </span>
              )}
            </div>
            <div style={{ fontSize: 12, color: '#4A5D70', fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>
              {connection === undefined ? 'Checking connection…' :
               connection ? `${connection.access_key_id} · ${connection.region}${connection.last_scanned_at ? ` · last scanned ${connection.last_scanned_at}` : ' · never scanned'}` :
               'Detects S3 buckets left publicly readable or writable'}
            </div>
          </div>
        </div>
        {canManage && connection === null && !showConnectForm && (
          <ActionBtn label="Connect" primary onClick={() => setShowConnectForm(true)} />
        )}
        {canManage && connection && (
          <div style={{ display: 'flex', gap: 8 }}>
            <ActionBtn label={scanning ? 'Scanning…' : 'Scan now'} primary disabled={scanning} onClick={scan} />
            <ActionBtn label="Disconnect" onClick={disconnect} />
          </div>
        )}
      </div>

      {error && (
        <div style={{ marginTop: 10, padding: '10px 14px', background: 'rgba(255,59,59,0.08)', border: '1px solid rgba(255,59,59,0.2)', borderRadius: 8, fontSize: 12, color: '#FF7070' }}>
          {error}
        </div>
      )}
      {scanResult && (
        <div style={{ marginTop: 10, padding: '10px 14px', background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 8, fontSize: 12, color: '#22C55E' }}>
          {scanResult}
        </div>
      )}

      {showConnectForm && (
        <form onSubmit={connect} style={{
          marginTop: 4, padding: '14px 16px', background: '#0B0F14',
          border: '1px dashed rgba(255,153,0,0.25)', borderRadius: 8,
          display: 'flex', flexDirection: 'column', gap: 10,
        }}>
          <div style={{ fontSize: 11.5, color: '#8A9BB0', lineHeight: 1.6 }}>
            Use a dedicated, <strong>read-only</strong> IAM user — SentinelAI only needs{' '}
            <code style={{ color: '#C8D5E3' }}>s3:ListAllMyBuckets</code>,{' '}
            <code style={{ color: '#C8D5E3' }}>s3:GetBucketAcl</code>,{' '}
            <code style={{ color: '#C8D5E3' }}>s3:GetBucketPolicyStatus</code>, and{' '}
            <code style={{ color: '#C8D5E3' }}>s3:GetPublicAccessBlock</code>. Never use root account keys.
            Your secret key is encrypted at rest and never displayed again after this form.
          </div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <div style={{ flex: 1, minWidth: 200 }}>
              <label style={{ display: 'block', fontSize: 10, color: '#4A5D70', marginBottom: 4 }}>Access Key ID</label>
              <input value={accessKeyId} onChange={e => setAccessKeyId(e.target.value)} required placeholder="AKIA…" style={{
                width: '100%', padding: '8px 10px', background: '#131A22', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 6, color: '#E8EFF7', fontSize: 12.5, outline: 'none', boxSizing: 'border-box',
              }} />
            </div>
            <div style={{ flex: 1, minWidth: 200 }}>
              <label style={{ display: 'block', fontSize: 10, color: '#4A5D70', marginBottom: 4 }}>Secret Access Key</label>
              <input type="password" value={secretAccessKey} onChange={e => setSecretAccessKey(e.target.value)} required style={{
                width: '100%', padding: '8px 10px', background: '#131A22', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 6, color: '#E8EFF7', fontSize: 12.5, outline: 'none', boxSizing: 'border-box',
              }} />
            </div>
            <div style={{ width: 140 }}>
              <label style={{ display: 'block', fontSize: 10, color: '#4A5D70', marginBottom: 4 }}>Region</label>
              <input value={region} onChange={e => setRegion(e.target.value)} style={{
                width: '100%', padding: '8px 10px', background: '#131A22', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 6, color: '#E8EFF7', fontSize: 12.5, outline: 'none', boxSizing: 'border-box',
              }} />
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button type="submit" disabled={connecting} style={{
              padding: '8px 16px', borderRadius: 6, background: '#00D4FF', border: 'none',
              color: '#0B0F14', fontSize: 12.5, fontWeight: 800, cursor: connecting ? 'default' : 'pointer',
            }}>
              {connecting ? 'Verifying…' : 'Verify & Connect'}
            </button>
            <button type="button" onClick={() => setShowConnectForm(false)} style={{
              padding: '8px 14px', borderRadius: 6, background: 'transparent', border: '1px solid rgba(255,255,255,0.1)',
              color: '#8A9BB0', fontSize: 12.5, cursor: 'pointer',
            }}>
              Cancel
            </button>
          </div>
        </form>
      )}
    </div>
  )
}

function IntegrationRow({ integ }: { integ: typeof INTEGRATIONS[0] }) {
  const [hovered, setHovered] = useState(false)
  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: hovered ? '#161F2C' : '#131A22',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: 12, padding: '18px 22px',
        display: 'flex', alignItems: 'center', gap: 16,
        transition: 'background 0.15s',
      }}
    >
      <div style={{
        width: 44, height: 44, borderRadius: 10, flexShrink: 0,
        background: `${integ.color}12`,
        border: `1px solid ${integ.color}25`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 22, color: integ.color,
      }}>
        {integ.icon}
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 3 }}>
          <span style={{ fontSize: 14, fontWeight: 700, color: '#E8EFF7' }}>{integ.name}</span>
          <span style={{
            padding: '2px 8px', borderRadius: 5,
            background: 'rgba(255,255,255,0.05)',
            border: '1px solid rgba(255,255,255,0.08)',
            fontSize: 10, fontWeight: 700,
            color: '#4A5D70',
          }}>
            Roadmap — not yet built
          </span>
        </div>
        <div style={{ fontSize: 12, color: '#4A5D70', fontFamily: "'JetBrains Mono', monospace" }}>
          {integ.detail}
        </div>
      </div>
      <ActionBtn label="Coming soon" disabled />
    </div>
  )
}

function PlanCard({ plan }: { plan: typeof PLANS[0] }) {
  const [hovered, setHovered] = useState(false)
  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: plan.current ? 'linear-gradient(160deg, #131A22 0%, #141D2E 100%)' : '#131A22',
        border: `1px solid ${plan.current ? 'rgba(0,212,255,0.3)' : hovered ? 'rgba(255,255,255,0.12)' : 'rgba(255,255,255,0.07)'}`,
        borderRadius: 12, padding: '22px 20px',
        position: 'relative',
        transition: 'border-color 0.15s',
      }}
    >
      {plan.current && (
        <div style={{
          position: 'absolute', top: -11, left: '50%', transform: 'translateX(-50%)',
          padding: '3px 14px',
          background: '#00D4FF', borderRadius: 20,
          fontSize: 10, fontWeight: 800, color: '#0B0F14',
          letterSpacing: '0.5px', whiteSpace: 'nowrap',
        }}>
          CURRENT PLAN
        </div>
      )}

      <div style={{ fontSize: 12, color: '#4A5D70', marginBottom: 4 }}>{plan.tagline}</div>
      <div style={{ fontSize: 16, fontWeight: 800, color: '#E8EFF7', marginBottom: 10 }}>{plan.name}</div>

      <div style={{ display: 'flex', alignItems: 'baseline', gap: 2, marginBottom: 18 }}>
        <span style={{ fontSize: 30, fontWeight: 800, letterSpacing: '-1.5px', color: plan.current ? '#00D4FF' : '#E8EFF7', lineHeight: 1 }}>
          {plan.price}
        </span>
        {plan.period && <span style={{ fontSize: 13, color: '#4A5D70' }}>{plan.period}</span>}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 9, marginBottom: 22 }}>
        {plan.features.map((f, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, opacity: f.included ? 1 : 0.3 }}>
            <span style={{ color: f.included ? '#22C55E' : '#4A5D70', flexShrink: 0, fontSize: 13, marginTop: 0.5 }}>
              {f.included ? '✓' : '✗'}
            </span>
            <span style={{ fontSize: 12, color: f.included ? '#C8D5E3' : '#4A5D70', lineHeight: 1.4 }}>
              {f.text}
            </span>
          </div>
        ))}
      </div>

      <button
        style={{
          width: '100%', padding: '11px 0',
          background: plan.current ? '#00D4FF' : 'rgba(255,255,255,0.06)',
          border: plan.current ? 'none' : '1px solid rgba(255,255,255,0.1)',
          borderRadius: 8, fontSize: 13, fontWeight: 700,
          color: plan.current ? '#0B0F14' : '#8A9BB0',
          cursor: plan.current ? 'default' : 'pointer',
          transition: 'all 0.12s',
        }}
        disabled={plan.current}
      >
        {plan.cta}
      </button>
    </div>
  )
}