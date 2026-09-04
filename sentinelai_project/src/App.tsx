import { useEffect, useState } from 'react'
import Sidebar from './components/Sidebar'
import TopBar from './components/TopBar'
import Dashboard from './components/Dashboard'
import VulnerabilityTable from './components/VulnerabilityTable'
import AttackPathMapper from './components/AttackPathMapper'
import Reports from './components/Reports'
import NotificationsCenter from './components/NotificationsCenter'
import Settings from './components/Settings'
import LoginPage from './components/LoginPage'
import { api, getStoredUser, getToken, type AuthUser } from './lib/api'
import { useTheme } from './lib/theme'

export type NavPage =
  | 'dashboard'
  | 'vulnerabilities'
  | 'attack-paths'
  | 'reports'
  | 'notifications'
  | 'settings'

// Pages that manage their own height and scrolling (no outer scroll)
const FIXED_HEIGHT_PAGES: NavPage[] = ['vulnerabilities', 'attack-paths']

export default function App() {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [checkingSession, setCheckingSession] = useState(true)
  const [page, setPage] = useState<NavPage>('dashboard')
  const { theme, toggleTheme } = useTheme()
  const [notifCount, setNotifCount] = useState(0)

  // Restore session on load if a token is already stored.
  useEffect(() => {
    const stored = getStoredUser()
    const token = getToken()
    if (stored && token) setUser(stored)
    setCheckingSession(false)
  }, [])

  useEffect(() => {
    if (!user) return
    api.notifications
      .list()
      .then(({ notifications }) => setNotifCount(notifications.filter((n: any) => !n.read).length))
      .catch(() => {})
  }, [user, page])

  if (checkingSession) {
    return (
      <div style={{ height: '100vh', background: 'var(--bg-app)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-tertiary)' }}>
        Loading…
      </div>
    )
  }

  if (!user) {
    return <LoginPage onLogin={setUser} />
  }

  const fixedHeight = FIXED_HEIGHT_PAGES.includes(page)

  const handleLogout = () => {
    api.logout()
    setUser(null)
    setPage('dashboard')
  }

  return (
    <div
      style={{
        display: 'flex',
        height: '100vh',
        overflow: 'hidden',
        background: 'var(--bg-app)',
      }}
    >
      <Sidebar currentPage={page} onNavigate={setPage} user={user} onLogout={handleLogout} />

      <div
        style={{
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          minWidth: 0,
        }}
      >
        <TopBar
          page={page}
          darkMode={theme === 'dark'}
          onToggleDark={toggleTheme}
          notifCount={notifCount}
          onNavigate={setPage}
          user={user}
          onLogout={handleLogout}
        />

        <main
          style={{
            flex: 1,
            overflowY: fixedHeight ? 'hidden' : 'auto',
            padding: '22px 24px',
            minHeight: 0,
          }}
        >
          {page === 'dashboard' && <Dashboard onNavigate={setPage} />}
          {page === 'vulnerabilities' && <VulnerabilityTable />}
          {page === 'attack-paths' && <AttackPathMapper />}
          {page === 'reports' && <Reports />}
          {page === 'notifications' && <NotificationsCenter onNavigate={setPage} />}
          {page === 'settings' && <Settings user={user} />}
        </main>
      </div>
    </div>
  )
}