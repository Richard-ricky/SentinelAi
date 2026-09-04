import { useState } from 'react'
import type { NavPage } from '../App'
import type { AuthUser } from '../lib/api'
import ShieldIcon from './icons/ShieldIcon'

interface Props {
  currentPage: NavPage
  onNavigate: (page: NavPage) => void
  user?: AuthUser
  onLogout?: () => void
}

const NAV: { id: NavPage; label: string; icon: React.ReactNode }[] = [
  { id: 'dashboard', label: 'Overview', icon: <GridIcon /> },
  { id: 'vulnerabilities', label: 'Vulnerabilities', icon: <BugIcon /> },
  { id: 'attack-paths', label: 'Attack Paths', icon: <NetworkIcon /> },
  { id: 'reports', label: 'Analytics', icon: <ChartIcon /> },
  { id: 'notifications', label: 'Alerts', icon: <BellIcon /> },
  { id: 'settings', label: 'Settings', icon: <GearIcon /> },
]

export default function Sidebar({ currentPage, onNavigate, user, onLogout }: Props) {
  return (
    <aside style={{
      width: 220,
      minWidth: 220,
      background: 'var(--bg-app)',
      borderRight: '1px solid color-mix(in srgb, var(--text-primary) 6%, transparent)',
      display: 'flex',
      flexDirection: 'column',
      padding: '20px 0 0',
    }}>
      {/* Wordmark */}
      <div style={{ padding: '0 18px', marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 34, height: 34,
            background: 'color-mix(in srgb, var(--accent) 8%, transparent)',
            border: '1px solid color-mix(in srgb, var(--accent) 22%, transparent)',
            borderRadius: 9,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <ShieldIcon size={18} color="var(--accent)" />
          </div>
          <div>
            <div style={{ fontSize: 15, fontWeight: 800, letterSpacing: '-0.3px', color: 'var(--text-primary)', lineHeight: 1 }}>
              SentinelAI
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-faint)', fontFamily: "'JetBrains Mono', monospace", marginTop: 3, letterSpacing: '0.5px' }}>
              {user ? `${user.name.split(' ')[0].toUpperCase()}'S WORKSPACE` : 'SECURITY OPERATIONS'}
            </div>
          </div>
        </div>
      </div>

      {/* Live indicator */}
      <div style={{ padding: '0 14px', marginBottom: 22 }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '8px 12px',
          background: 'color-mix(in srgb, var(--low) 5%, transparent)',
          border: '1px solid color-mix(in srgb, var(--low) 12%, transparent)',
          borderRadius: 8,
        }}>
          <div
            className="animate-pulse-live"
            style={{
              width: 7, height: 7, borderRadius: '50%',
              background: 'var(--low)',
              boxShadow: '0 0 6px color-mix(in srgb, var(--low) 80%, transparent)',
              flexShrink: 0,
            }}
          />
          <span style={{ fontSize: 10, color: 'var(--low)', fontWeight: 700, letterSpacing: '0.5px' }}>
            MONITORING LIVE
          </span>
        </div>
      </div>

      {/* Section label */}
      <div style={{ padding: '0 18px', marginBottom: 6 }}>
        <span style={{ fontSize: 9, color: 'var(--text-faint)', fontWeight: 700, letterSpacing: '0.8px', textTransform: 'uppercase' }}>
          Navigation
        </span>
      </div>

      {/* Nav items */}
      <nav role="navigation" style={{ flex: 1, padding: '0 10px', display: 'flex', flexDirection: 'column', gap: 1 }}>
        {NAV.map(item => (
          <NavItem
            key={item.id}
            item={item}
            active={currentPage === item.id}
            onClick={() => onNavigate(item.id)}
          />
        ))}
      </nav>

      {/* User */}
      <div style={{
        padding: '14px 18px',
        borderTop: '1px solid color-mix(in srgb, var(--text-primary) 5%, transparent)',
        marginTop: 'auto',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 30, height: 30, borderRadius: '50%', flexShrink: 0,
            background: 'color-mix(in srgb, var(--accent) 15%, transparent)',
            border: '1px solid color-mix(in srgb, var(--accent) 30%, transparent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 11, fontWeight: 800, color: 'var(--accent)',
          }}>
            {user ? user.name.split(' ').map(p => p[0]).slice(0, 2).join('').toUpperCase() : '—'}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{
              fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)', lineHeight: 1.2,
              whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
            }}>
              {user?.name ?? 'Not signed in'}
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-faint)', fontFamily: "'JetBrains Mono', monospace", marginTop: 2, textTransform: 'capitalize' }}>
              {user?.role ?? '—'}
            </div>
          </div>
          {onLogout && (
            <button
              aria-label="Sign out"
              title="Sign out"
              onClick={onLogout}
              style={{
                background: 'none', border: 'none',
                color: 'var(--text-faint)', cursor: 'pointer', padding: 4,
                lineHeight: 1, fontSize: 14,
                borderRadius: 4,
              }}
            >
              ⋯
            </button>
          )}
        </div>
      </div>
    </aside>
  )
}

function NavItem({
  item,
  active,
  onClick,
}: {
  item: { label: string; icon: React.ReactNode }
  active: boolean
  onClick: () => void
}) {
  const [hovered, setHovered] = useState(false)

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      aria-pressed={active}
      style={{
        display: 'flex', alignItems: 'center', gap: 10,
        padding: '8px 12px',
        borderRadius: 8,
        background: active
          ? 'color-mix(in srgb, var(--accent) 10%, transparent)'
          : hovered
          ? 'color-mix(in srgb, var(--text-primary) 4%, transparent)'
          : 'transparent',
        border: active
          ? '1px solid color-mix(in srgb, var(--accent) 20%, transparent)'
          : '1px solid transparent',
        color: active ? 'var(--accent)' : hovered ? 'var(--text-secondary)' : 'var(--text-tertiary)',
        cursor: 'pointer',
        fontSize: 13,
        fontWeight: active ? 700 : 500,
        textAlign: 'left',
        width: '100%',
        transition: 'all 0.12s',
      }}
    >
      <span style={{ flexShrink: 0, display: 'flex', alignItems: 'center', opacity: active ? 1 : hovered ? 0.9 : 0.65 }}>
        {item.icon}
      </span>
      {item.label}
    </button>
  )
}

function GridIcon() {
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>
}
function BugIcon() {
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="11" r="4"/><path d="M12 7V3"/><path d="M8 11H4"/><path d="M20 11h-4"/><path d="M8.5 17.5 6 20"/><path d="M15.5 17.5 18 20"/><path d="M12 15v4"/></svg>
}
function NetworkIcon() {
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="4" r="2"/><circle cx="4" cy="20" r="2"/><circle cx="20" cy="20" r="2"/><path d="m12 6-4.5 12"/><path d="m12 6 4.5 12"/><path d="M6 20h12"/></svg>
}
function ChartIcon() {
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
}
function BellIcon() {
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
}
function GearIcon() {
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
}