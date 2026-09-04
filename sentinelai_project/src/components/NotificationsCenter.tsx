import { useEffect, useState } from 'react'
import type { NavPage } from '../App'
import { api } from '../lib/api'

interface Props {
  onNavigate: (page: NavPage) => void
}

interface ApiNotification {
  id: string
  title: string
  body: string | null
  severity: string | null
  read: number
  created_at: string
}

const TYPE_CONFIG: Record<string, { color: string; bg: string; border: string; icon: string }> = {
  Critical: { color: '#FF3B3B', bg: 'rgba(255,59,59,0.07)', border: 'rgba(255,59,59,0.18)', icon: '⊗' },
  High: { color: '#FF8C00', bg: 'rgba(255,140,0,0.07)', border: 'rgba(255,140,0,0.18)', icon: '▲' },
  Medium: { color: '#FFB800', bg: 'rgba(255,184,0,0.06)', border: 'rgba(255,184,0,0.18)', icon: '▲' },
  Low: { color: '#22C55E', bg: 'rgba(34,197,94,0.06)', border: 'rgba(34,197,94,0.15)', icon: '✓' },
  Info: { color: '#00D4FF', bg: 'rgba(0,212,255,0.05)', border: 'rgba(0,212,255,0.13)', icon: '◆' },
}

function relativeTime(iso: string) {
  const then = new Date(iso.replace(' ', 'T') + 'Z').getTime()
  const diffMs = Date.now() - then
  const mins = Math.floor(diffMs / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs} hr ago`
  return `${Math.floor(hrs / 24)} day(s) ago`
}

export default function NotificationsCenter({ onNavigate }: Props) {
  const [items, setItems] = useState<ApiNotification[]>([])
  const [filter, setFilter] = useState<'all' | 'unread'>('all')
  const [loading, setLoading] = useState(true)

  const load = () => {
    setLoading(true)
    api.notifications
      .list()
      .then(({ notifications }) => setItems(notifications))
      .finally(() => setLoading(false))
  }

  useEffect(load, [])

  const unreadCount = items.filter(n => !n.read).length

  const markAllRead = async () => {
    setItems(prev => prev.map(n => ({ ...n, read: 1 })))
    await api.notifications.markAllRead().catch(() => {})
  }
  const markRead = async (id: string) => {
    setItems(prev => prev.map(n => (n.id === id ? { ...n, read: 1 } : n)))
    await api.notifications.markRead(id).catch(() => {})
  }

  const visible = filter === 'unread' ? items.filter(n => !n.read) : items

  return (
    <div className="animate-fade-in-up" style={{ maxWidth: 680 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
        <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700, color: '#E8EFF7' }}>Alerts</h2>
        {unreadCount > 0 && (
          <span style={{
            padding: '2px 9px', borderRadius: 10,
            background: 'rgba(255,59,59,0.1)',
            border: '1px solid rgba(255,59,59,0.25)',
            fontSize: 11, color: '#FF3B3B', fontWeight: 700,
          }}>
            {unreadCount} unread
          </span>
        )}

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
          {(['all', 'unread'] as const).map(f => (
            <FilterBtn key={f} active={filter === f} onClick={() => setFilter(f)} label={f === 'all' ? 'All' : 'Unread only'} />
          ))}
          {unreadCount > 0 && (
            <button
              onClick={markAllRead}
              style={{
                padding: '5px 12px', borderRadius: 7,
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid rgba(255,255,255,0.08)',
                color: '#8A9BB0', fontSize: 12, fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Mark all read
            </button>
          )}
        </div>
      </div>

      {/* Notifications list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {loading && (
          <div style={{ padding: '48px 0', textAlign: 'center', color: '#4A5D70', fontSize: 14 }}>Loading…</div>
        )}
        {!loading && visible.length === 0 && (
          <div style={{ padding: '48px 0', textAlign: 'center', color: '#4A5D70', fontSize: 14 }}>
            {items.length === 0
              ? 'No notifications yet — add an asset and run a scan to get started.'
              : 'No unread notifications.'}
          </div>
        )}
        {visible.map(n => (
          <NotifCard
            key={n.id}
            notif={n}
            onNavigate={(page) => { markRead(n.id); onNavigate(page) }}
            onMarkRead={() => markRead(n.id)}
          />
        ))}
      </div>
    </div>
  )
}

function NotifCard({ notif, onNavigate, onMarkRead }: {
  notif: ApiNotification
  onNavigate: (page: NavPage) => void
  onMarkRead: () => void
}) {
  const [hovered, setHovered] = useState(false)
  const cfg = TYPE_CONFIG[notif.severity || 'Info'] ?? TYPE_CONFIG.Info
  const read = Boolean(notif.read)

  // Route to a sensible page based on notification content.
  const target: NavPage = notif.title.toLowerCase().includes('asset') ? 'vulnerabilities' : 'vulnerabilities'

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: read
          ? hovered ? '#161F2C' : '#131A22'
          : hovered ? '#162230' : '#131A22',
        border: `1px solid ${read ? 'rgba(255,255,255,0.06)' : cfg.border}`,
        borderLeft: `3px solid ${read ? 'rgba(255,255,255,0.05)' : cfg.color}`,
        borderRadius: 10,
        padding: '16px 18px',
        display: 'flex', gap: 14, alignItems: 'flex-start',
        transition: 'all 0.15s',
      }}
    >
      {/* Icon */}
      <div style={{
        width: 32, height: 32, borderRadius: '50%', flexShrink: 0,
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        color: cfg.color, fontSize: 13, fontWeight: 700,
      }}>
        {cfg.icon}
      </div>

      {/* Content */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 5 }}>
          <div style={{
            flex: 1, fontSize: 13, fontWeight: read ? 600 : 700,
            color: read ? '#8A9BB0' : '#E8EFF7', lineHeight: 1.35,
          }}>
            {notif.title}
          </div>
          <div style={{
            fontSize: 10, color: '#4A5D70',
            fontFamily: "'JetBrains Mono', monospace",
            flexShrink: 0, paddingTop: 1,
          }}>
            {relativeTime(notif.created_at)}
          </div>
        </div>

        {notif.body && (
          <div style={{ fontSize: 12.5, color: '#8A9BB0', lineHeight: 1.6, marginBottom: 12 }}>
            {notif.body}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button
            onClick={() => onNavigate(target)}
            style={{
              padding: '5px 13px', borderRadius: 6,
              background: 'rgba(0,212,255,0.08)',
              border: '1px solid rgba(0,212,255,0.2)',
              color: '#00D4FF', fontSize: 12, fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 0.12s',
            }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(0,212,255,0.14)' }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = 'rgba(0,212,255,0.08)' }}
          >
            View details →
          </button>
          {!read && (
            <button
              onClick={onMarkRead}
              style={{
                padding: '5px 10px', borderRadius: 6,
                background: 'transparent', border: 'none',
                color: '#4A5D70', fontSize: 11, fontWeight: 600,
                cursor: 'pointer',
                transition: 'color 0.12s',
              }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = '#8A9BB0' }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#4A5D70' }}
            >
              Mark read
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function FilterBtn({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  const [hovered, setHovered] = useState(false)
  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        padding: '5px 12px', borderRadius: 7,
        background: active ? 'rgba(0,212,255,0.1)' : hovered ? 'rgba(255,255,255,0.05)' : 'rgba(255,255,255,0.03)',
        border: active ? '1px solid rgba(0,212,255,0.25)' : '1px solid rgba(255,255,255,0.07)',
        color: active ? '#00D4FF' : hovered ? '#C8D5E3' : '#8A9BB0',
        fontSize: 12, fontWeight: active ? 700 : 500,
        cursor: 'pointer', transition: 'all 0.12s',
      }}
    >
      {label}
    </button>
  )
}
