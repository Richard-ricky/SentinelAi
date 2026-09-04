import { useState } from 'react'
import type { NavPage } from '../App'
import type { AuthUser } from '../lib/api'

interface Props {
  page: NavPage
  darkMode: boolean
  onToggleDark: () => void
  notifCount: number
  onNavigate: (page: NavPage) => void
  user?: AuthUser
  onLogout?: () => void
}

const PAGE_TITLE: Record<NavPage, string> = {
  dashboard: 'Security Overview',
  vulnerabilities: 'Vulnerability Assessment Center',
  'attack-paths': 'Attack Path Mapper',
  reports: 'Analytics & Reports',
  notifications: 'Notifications',
  settings: 'Settings',
}

export default function TopBar({ page, darkMode, onToggleDark, notifCount, onNavigate, user, onLogout }: Props) {
  const [searchValue, setSearchValue] = useState('')

  return (
    <header style={{
      height: 54,
      background: 'var(--bg-app)',
      borderBottom: '1px solid color-mix(in srgb, var(--text-primary) 6%, transparent)',
      display: 'flex', alignItems: 'center',
      padding: '0 24px',
      gap: 12,
      flexShrink: 0,
    }}>
      {/* Page title */}
      <div style={{ flex: '0 0 auto' }}>
        <h1 style={{
          margin: 0,
          fontSize: 14, fontWeight: 700,
          letterSpacing: '-0.1px', color: 'var(--text-primary)',
          lineHeight: 1,
        }}>
          {PAGE_TITLE[page]}
        </h1>
      </div>

      <div style={{ flex: 1 }} />

      {/* Search */}
      <div style={{ position: 'relative' }}>
        <svg
          style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }}
          width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="color-mix(in srgb, var(--text-tertiary) 60%, transparent)" strokeWidth="2.2"
        >
          <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
        </svg>
        <input
          type="search"
          placeholder="Search assets, CVEs, IPs…"
          value={searchValue}
          onChange={e => setSearchValue(e.target.value)}
          aria-label="Search"
          style={{
            background: 'color-mix(in srgb, var(--text-primary) 4%, transparent)',
            border: '1px solid color-mix(in srgb, var(--text-primary) 8%, transparent)',
            borderRadius: 8,
            padding: '7px 12px 7px 32px',
            color: 'var(--text-primary)',
            fontSize: 12,
            width: 230,
            outline: 'none',
            transition: 'border-color 0.15s',
          }}
          onFocus={e => { (e.target as HTMLInputElement).style.borderColor = 'color-mix(in srgb, var(--accent) 40%, transparent)' }}
          onBlur={e => { (e.target as HTMLInputElement).style.borderColor = 'color-mix(in srgb, var(--text-primary) 8%, transparent)' }}
        />
        {searchValue && (
          <button
            onClick={() => setSearchValue('')}
            aria-label="Clear search"
            style={{
              position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
              background: 'none', border: 'none', color: 'var(--text-faint)', cursor: 'pointer',
              fontSize: 14, lineHeight: 1, padding: 2,
            }}
          >
            ✕
          </button>
        )}
      </div>

      {/* Icon buttons */}
      <IconButton onClick={onToggleDark} title={darkMode ? 'Switch to light theme' : 'Switch to dark theme'} aria-label="Toggle light/dark theme">
        {darkMode ? (
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
          </svg>
        ) : (
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
            <circle cx="12" cy="12" r="4.5" />
            <path d="M12 2v2.5M12 19.5V22M4.2 4.2l1.8 1.8M18 18l1.8 1.8M2 12h2.5M19.5 12H22M4.2 19.8L6 18M18 6l1.8-1.8" strokeLinecap="round" />
          </svg>
        )}
      </IconButton>

      <IconButton
        onClick={() => onNavigate('notifications')}
        title="Notifications"
        aria-label={`Notifications — ${notifCount} unread`}
        badge={notifCount}
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
          <path d="M13.73 21a2 2 0 0 1-3.46 0" />
        </svg>
      </IconButton>

      {/* Scan cadence */}
      <div style={{
        padding: '0 12px',
        height: 30,
        borderLeft: '1px solid color-mix(in srgb, var(--text-primary) 6%, transparent)',
        display: 'flex', alignItems: 'center',
      }}>
        <span style={{ fontSize: 10, color: 'var(--text-faint)', fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>
          last scan <span style={{ color: 'var(--text-tertiary)' }}>2m ago</span>
        </span>
      </div>

      {user && (
        <div style={{
          padding: '0 4px 0 12px',
          height: 30,
          borderLeft: '1px solid color-mix(in srgb, var(--text-primary) 6%, transparent)',
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <div style={{
            width: 24, height: 24, borderRadius: '50%',
            background: 'color-mix(in srgb, var(--accent) 15%, transparent)', color: 'var(--accent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 11, fontWeight: 700, flexShrink: 0,
          }}>
            {user.name.charAt(0).toUpperCase()}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 600, maxWidth: 110, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {user.name}
          </span>
          {onLogout && (
            <button
              onClick={onLogout}
              title="Sign out"
              aria-label="Sign out"
              style={{
                background: 'none', border: 'none', color: 'var(--text-faint)',
                cursor: 'pointer', fontSize: 11, padding: '4px 6px',
              }}
            >
              Sign out
            </button>
          )}
        </div>
      )}
    </header>
  )
}

interface IconButtonProps {
  onClick: () => void
  title: string
  'aria-label': string
  badge?: number
  children: React.ReactNode
}

function IconButton({ onClick, title, children, badge, ...rest }: IconButtonProps & { [key: string]: unknown }) {
  const [hovered, setHovered] = useState(false)
  return (
    <button
      onClick={onClick}
      title={title}
      aria-label={rest['aria-label'] as string}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        position: 'relative',
        width: 32, height: 32,
        background: hovered ? 'color-mix(in srgb, var(--text-primary) 8%, transparent)' : 'color-mix(in srgb, var(--text-primary) 4%, transparent)',
        border: '1px solid color-mix(in srgb, var(--text-primary) 8%, transparent)',
        borderRadius: 8,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        cursor: 'pointer',
        color: hovered ? 'var(--text-secondary)' : 'var(--text-tertiary)',
        transition: 'all 0.12s',
        flexShrink: 0,
      }}
    >
      {children}
      {badge != null && badge > 0 && (
        <span style={{
          position: 'absolute', top: 5, right: 5,
          width: 7, height: 7, borderRadius: '50%',
          background: 'var(--critical)',
          boxShadow: '0 0 5px color-mix(in srgb, var(--critical) 70%, transparent)',
        }} />
      )}
    </button>
  )
}