import { useEffect, useState } from 'react'
import type { NavPage } from '../App'
import SecurityScore from './shared/SecurityScore'
import SeverityBadge from './shared/SeverityBadge'
import type { Severity } from './shared/SeverityBadge'
import { api } from '../lib/api'

interface Props {
  onNavigate: (page: NavPage) => void
}

interface Summary {
  securityScore: number
  totalAssets: number
  openVulnerabilities: number
  patchedVulnerabilities: number
  bySeverity: Record<Severity, number>
}

const SEVERITY_COLOR: Record<Severity, string> = {
  Critical: 'var(--critical)',
  High: 'var(--high)',
  Medium: 'var(--medium)',
  Low: 'var(--low)',
}

export default function Dashboard({ onNavigate }: Props) {
  const [summary, setSummary] = useState<Summary | null>(null)
  const [assets, setAssets] = useState<any[]>([])
  const [activity, setActivity] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [monitoring, setMonitoring] = useState<{ intervalMinutes: number; running: boolean } | null>(null)

  const load = async () => {
    setError(null)
    try {
      const [summaryData, assetsData, notifData, monitoringData] = await Promise.all([
        api.reports.summary(),
        api.assets.list(),
        api.notifications.list(),
        api.monitoring.status().catch(() => null),
      ])
      setSummary(summaryData)
      setAssets(assetsData.assets)
      setActivity(notifData.notifications.slice(0, 6))
      setMonitoring(monitoringData)
    } catch (err: any) {
      setError(err.message || 'Could not load dashboard data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const runAllScans = async () => {
    if (assets.length === 0) {
      onNavigate('vulnerabilities')
      return
    }
    setScanning(true)
    try {
      for (const asset of assets) {
        await api.scans.run(asset.id)
      }
      await load()
    } catch (err: any) {
      setError(err.message || 'Scan failed')
    } finally {
      setScanning(false)
    }
  }

  if (loading) {
    return <div style={{ color: 'var(--text-tertiary)', fontSize: 13 }}>Loading dashboard…</div>
  }

  if (error) {
    return (
      <div style={{
        background: 'color-mix(in srgb, var(--critical) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--critical) 20%, transparent)',
        borderRadius: 12, padding: 20, color: 'var(--critical)', fontSize: 13,
      }}>
        {error}
      </div>
    )
  }

  const score = summary?.securityScore ?? 100
  const severityCounts = summary?.bySeverity ?? { Critical: 0, High: 0, Medium: 0, Low: 0 }
  const scoreColor = score >= 80 ? 'var(--low)' : score >= 50 ? 'var(--medium)' : 'var(--critical)'

  return (
    <div className="animate-fade-in-up" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Row 1: Score + summary cards */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>
        {/* Security score card */}
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid color-mix(in srgb, var(--text-primary) 7%, transparent)',
          borderRadius: 12,
          padding: '22px 24px',
          display: 'flex', alignItems: 'center', gap: 22,
        }}>
          <SecurityScore score={score} size={120} />
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-tertiary)', fontWeight: 700, letterSpacing: '0.5px', textTransform: 'uppercase', marginBottom: 6 }}>
              Security Score
            </div>
            <div style={{ fontSize: 32, fontWeight: 800, color: scoreColor, letterSpacing: '-1.5px', lineHeight: 1 }}>
              {score}
              <span style={{ fontSize: 18, color: 'var(--text-faint)', fontWeight: 400 }}> / 100</span>
            </div>
            <div style={{ marginTop: 10, fontSize: 11, color: 'var(--text-tertiary)', lineHeight: 1.6 }}>
              {severityCounts.Critical > 0
                ? <>Fix {severityCounts.Critical} critical issue{severityCounts.Critical !== 1 ? 's' : ''} → score improves significantly</>
                : 'No critical issues open — nice work.'}
            </div>
          </div>
        </div>

        {/* Assets */}
        <StatCard
          label="Assets Monitored"
          value={String(summary?.totalAssets ?? 0)}
          sub={assets.length === 0 ? 'No assets yet — add one to start scanning' : `${assets.length} asset(s) registered`}
          color="var(--accent)"
          icon={<ServerIcon />}
        />

        {/* Live status */}
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid color-mix(in srgb, var(--text-primary) 7%, transparent)',
          borderRadius: 12,
          padding: '20px 22px',
          display: 'flex', flexDirection: 'column', justifyContent: 'space-between',
        }}>
          <div style={{ fontSize: 11, color: 'var(--text-tertiary)', fontWeight: 700, letterSpacing: '0.5px', textTransform: 'uppercase' }}>
            Monitor Status
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 10 }}>
              <div
                className="animate-pulse-live"
                style={{
                  width: 8, height: 8, borderRadius: '50%',
                  background: 'var(--low)',
                  boxShadow: '0 0 8px color-mix(in srgb, var(--low) 80%, transparent)',
                }}
              />
              <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--low)' }}>
                {monitoring ? `Continuous monitoring — every ${monitoring.intervalMinutes} min` : 'API connected'}
              </span>
            </div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: 'var(--text-faint)' }}>
              {assets.length} asset(s) under management
            </div>
          </div>
          <button
            onClick={runAllScans}
            disabled={scanning}
            style={{
              padding: '8px 0',
              background: 'color-mix(in srgb, var(--accent) 8%, transparent)',
              border: '1px solid color-mix(in srgb, var(--accent) 20%, transparent)',
              borderRadius: 7, fontSize: 12, fontWeight: 600,
              color: 'var(--accent)', cursor: scanning ? 'default' : 'pointer',
              transition: 'all 0.12s',
              opacity: scanning ? 0.6 : 1,
            }}
            onMouseEnter={e => { if (!scanning) (e.currentTarget as HTMLElement).style.background = 'color-mix(in srgb, var(--accent) 14%, transparent)' }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'color-mix(in srgb, var(--accent) 8%, transparent)' }}
          >
            {scanning ? 'Scanning…' : assets.length === 0 ? 'Add an asset →' : 'Run scan now'}
          </button>
        </div>
      </div>

      {/* Row 2: Severity breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 14 }}>
        {(['Critical', 'High', 'Medium', 'Low'] as Severity[]).map(sev => (
          <SeverityCard
            key={sev}
            severity={sev}
            count={severityCounts[sev] ?? 0}
            onClick={() => onNavigate('vulnerabilities')}
          />
        ))}
      </div>

      {/* Row 3: Activity feed + Attack path promo */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 360px', gap: 16 }}>
        {/* Activity feed */}
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid color-mix(in srgb, var(--text-primary) 7%, transparent)',
          borderRadius: 12,
          padding: '18px 22px',
        }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-tertiary)', letterSpacing: '0.5px', textTransform: 'uppercase', marginBottom: 16 }}>
            Recent Activity
          </div>
          {activity.length === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--text-faint)' }}>
              No activity yet. Add an asset and run a scan to get started.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {activity.map((item, i) => (
                <ActivityItem key={item.id} item={item} last={i === activity.length - 1} />
              ))}
            </div>
          )}
        </div>

        {/* Attack path promo */}
        <AttackPathPromo onNavigate={onNavigate} />
      </div>
    </div>
  )
}

function SeverityCard({ severity, count, onClick }: { severity: Severity; count: number; onClick: () => void }) {
  const [hovered, setHovered] = useState(false)
  const color = SEVERITY_COLOR[severity]
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') onClick() }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: hovered ? 'var(--bg-surface-hover)' : 'var(--bg-surface)',
        border: `1px solid ${hovered ? `${color}30` : 'color-mix(in srgb, var(--text-primary) 7%, transparent)'}`,
        borderRadius: 12,
        padding: '18px 20px',
        cursor: 'pointer',
        transition: 'all 0.15s',
      }}
    >
      <div style={{ marginBottom: 10 }}>
        <SeverityBadge severity={severity} size="sm" />
      </div>
      <div style={{
        fontSize: 42, fontWeight: 800,
        color, letterSpacing: '-2px', lineHeight: 1,
        textShadow: hovered ? `0 0 20px ${color}40` : 'none',
        transition: 'text-shadow 0.15s',
      }}>
        {count}
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 4 }}>
        open issue{count !== 1 ? 's' : ''}
      </div>
    </div>
  )
}

const SEVERITY_ICON_COLOR: Record<string, string> = {
  Critical: 'var(--critical)', High: 'var(--high)', Medium: 'var(--medium)', Low: 'var(--low)', Info: 'var(--accent)',
}
const SEVERITY_ICON_BG: Record<string, string> = {
  Critical: 'color-mix(in srgb, var(--critical) 10%, transparent)', High: 'color-mix(in srgb, var(--high) 10%, transparent)', Medium: 'color-mix(in srgb, var(--medium) 8%, transparent)',
  Low: 'color-mix(in srgb, var(--low) 8%, transparent)', Info: 'color-mix(in srgb, var(--accent) 7%, transparent)',
}

function timeAgo(iso: string) {
  const then = new Date(iso.replace(' ', 'T') + 'Z').getTime()
  const diffMs = Date.now() - then
  const mins = Math.floor(diffMs / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs} hr ago`
  return `${Math.floor(hrs / 24)} day(s) ago`
}

function ActivityItem({ item, last }: { item: any; last: boolean }) {
  const sev = item.severity || 'Info'
  const col = SEVERITY_ICON_COLOR[sev] ?? 'var(--text-tertiary)'
  const bg = SEVERITY_ICON_BG[sev] ?? 'color-mix(in srgb, var(--text-primary) 5%, transparent)'
  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: 12,
      paddingBottom: last ? 0 : 12,
      marginBottom: last ? 0 : 12,
      borderBottom: last ? 'none' : '1px solid color-mix(in srgb, var(--text-primary) 4%, transparent)',
    }}>
      <div style={{
        width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
        background: bg,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: 11, color: col,
        fontWeight: 700,
      }}>
        {sev === 'Critical' ? '⊗' : '●'}
      </div>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.4 }}>{item.title}</div>
        {item.body && <div style={{ fontSize: 11, color: 'var(--text-tertiary)', marginTop: 2, lineHeight: 1.4 }}>{item.body}</div>}
        <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 3, fontFamily: "'JetBrains Mono', monospace" }}>
          {timeAgo(item.created_at)}
        </div>
      </div>
    </div>
  )
}

function AttackPathPromo({ onNavigate }: { onNavigate: (page: NavPage) => void }) {
  const [hovered, setHovered] = useState(false)
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onNavigate('attack-paths')}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') onNavigate('attack-paths') }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: 'linear-gradient(145deg, var(--bg-surface) 0%, color-mix(in srgb, var(--critical) 10%, var(--bg-surface)) 100%)',
        border: `1px solid ${hovered ? 'color-mix(in srgb, var(--critical) 40%, transparent)' : 'color-mix(in srgb, var(--critical) 20%, transparent)'}`,
        borderRadius: 12,
        padding: '22px 22px',
        cursor: 'pointer',
        position: 'relative',
        overflow: 'hidden',
        transition: 'border-color 0.2s',
      }}
    >
      <div style={{
        position: 'absolute', top: -60, right: -60,
        width: 220, height: 220,
        background: 'radial-gradient(circle, color-mix(in srgb, var(--critical) 7%, transparent) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />

      <div style={{
        display: 'inline-flex', alignItems: 'center', gap: 7,
        padding: '4px 10px',
        background: 'color-mix(in srgb, var(--critical) 10%, transparent)',
        border: '1px solid color-mix(in srgb, var(--critical) 28%, transparent)',
        borderRadius: 20, marginBottom: 14,
      }}>
        <div className="animate-pulse-live" style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--critical)', boxShadow: '0 0 5px var(--critical)' }} />
        <span style={{ fontSize: 10, color: 'var(--critical)', fontWeight: 800, letterSpacing: '0.5px' }}>SAMPLE VISUALIZATION</span>
      </div>

      <h3 style={{ margin: '0 0 8px', fontSize: 18, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.3px' }}>
        Attack Path Mapper
      </h3>
      <p style={{ margin: '0 0 18px', fontSize: 12.5, color: 'var(--text-tertiary)', lineHeight: 1.65 }}>
        Explore how an attacker could chain findings across assets to reach sensitive systems.
      </p>

      <svg width="100%" height="72" viewBox="0 0 290 72" style={{ display: 'block', marginBottom: 16 }}>
        <defs>
          <filter id="dash-glow">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
        <path
          d="M 16 36 C 70 36, 100 18, 145 36 S 210 54, 274 36"
          stroke="var(--critical)" strokeWidth="2" fill="none"
          strokeDasharray="7 4"
          filter="url(#dash-glow)"
          style={{ animation: 'dash-flow 1.8s linear infinite' }}
        />
        {[
          { x: 16, label: 'WEB', col: 'var(--critical)' },
          { x: 97, label: 'SRV', col: 'var(--high)' },
          { x: 193, label: 'NET', col: 'var(--high)' },
          { x: 274, label: 'DB', col: 'var(--critical)' },
        ].map((n, i) => (
          <g key={i}>
            <circle cx={n.x} cy={36} r={i === 0 || i === 3 ? 12 : 9}
              fill={`${n.col}18`} stroke={n.col} strokeWidth="1.5"
              filter="url(#dash-glow)"
            />
            <text x={n.x} y={36} textAnchor="middle" dominantBaseline="middle"
              fill={n.col} fontSize="7" fontFamily="'JetBrains Mono', monospace" fontWeight="700">
              {n.label}
            </text>
            <text x={n.x} y={56} textAnchor="middle"
              fill="var(--text-faint)" fontSize="7.5" fontFamily="'Manrope', sans-serif">
              {['Internet', 'Marketing', 'App Server', 'Customer DB'][i]}
            </text>
          </g>
        ))}
      </svg>

      <div style={{
        display: 'flex', alignItems: 'center', gap: 6,
        color: hovered ? 'var(--accent)' : 'var(--text-tertiary)',
        fontSize: 12.5, fontWeight: 700,
        transition: 'color 0.15s',
      }}>
        View full attack graph
        <span style={{ transition: 'transform 0.15s', transform: hovered ? 'translateX(3px)' : 'none', display: 'inline-block' }}>→</span>
      </div>
    </div>
  )
}

function StatCard({ label, value, sub, color, icon }: {
  label: string; value: string; sub: string; color: string; icon: React.ReactNode
}) {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid color-mix(in srgb, var(--text-primary) 7%, transparent)',
      borderRadius: 12,
      padding: '20px 22px',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
        <div style={{ fontSize: 11, color: 'var(--text-tertiary)', fontWeight: 700, letterSpacing: '0.5px', textTransform: 'uppercase' }}>
          {label}
        </div>
        <div style={{ color, opacity: 0.7 }}>{icon}</div>
      </div>
      <div style={{ fontSize: 36, fontWeight: 800, color, letterSpacing: '-1.5px', lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 11, color: 'var(--text-faint)', marginTop: 5, lineHeight: 1.5 }}>{sub}</div>
    </div>
  )
}

function ServerIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round">
      <rect x="2" y="2" width="20" height="8" rx="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" />
      <line x1="6" y1="6" x2="6.01" y2="6" />
      <line x1="6" y1="18" x2="6.01" y2="18" />
    </svg>
  )
}