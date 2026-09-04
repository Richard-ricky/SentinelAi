import { useState } from 'react'
import ShieldIcon from './icons/ShieldIcon'
import { api, ApiError, type AuthUser } from '../lib/api'

interface Props {
  onLogin: (user: AuthUser) => void
}

type Mode = 'login' | 'register'

export default function LoginPage({ onLogin }: Props) {
  const [mode, setMode] = useState<Mode>('login')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [workspaceName, setWorkspaceName] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    if (!email.trim() || !password.trim() || (mode === 'register' && !name.trim())) {
      setError('Please fill in all required fields.')
      return
    }

    setLoading(true)
    try {
      const user =
        mode === 'login'
          ? await api.login(email.trim(), password)
          : await api.register(name.trim(), email.trim(), password, workspaceName.trim() || undefined)
      onLogin(user)
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError(
          'Could not reach the SentinelAI API. Make sure the backend server is running (see server/README).'
        )
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: '#0B0F14',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Grid background */}
      <div style={{
        position: 'absolute', inset: 0, pointerEvents: 'none',
        backgroundImage: [
          'linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px)',
          'linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px)',
        ].join(', '),
        backgroundSize: '44px 44px',
      }} />
      {/* Radial highlight */}
      <div style={{
        position: 'absolute', top: '38%', left: '50%',
        transform: 'translate(-50%, -50%)',
        width: 700, height: 700,
        background: 'radial-gradient(circle, rgba(0,212,255,0.05) 0%, transparent 65%)',
        pointerEvents: 'none',
      }} />

      {/* Card */}
      <div className="animate-fade-in-up" style={{
        position: 'relative',
        width: 400,
        background: '#131A22',
        border: '1px solid rgba(255,255,255,0.09)',
        borderRadius: 16,
        padding: '36px 34px',
        boxShadow: '0 32px 80px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.04) inset',
      }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 11, marginBottom: 28 }}>
          <div style={{
            width: 38, height: 38, flexShrink: 0,
            background: 'rgba(0,212,255,0.1)',
            border: '1px solid rgba(0,212,255,0.25)',
            borderRadius: 10,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <ShieldIcon size={20} color="#00D4FF" />
          </div>
          <div>
            <div style={{ fontSize: 17, fontWeight: 800, letterSpacing: '-0.3px', color: '#E8EFF7', lineHeight: 1 }}>
              SentinelAI
            </div>
            <div style={{ fontSize: 10, color: '#4A5D70', fontFamily: "'JetBrains Mono', monospace", marginTop: 3 }}>
              Security Operations Platform
            </div>
          </div>
        </div>

        {/* Header */}
        <div style={{ marginBottom: 24 }}>
          <h1 style={{ margin: '0 0 6px', fontSize: 20, fontWeight: 800, color: '#E8EFF7', letterSpacing: '-0.3px' }}>
            {mode === 'login' ? 'Sign in to your workspace' : 'Create your workspace'}
          </h1>
          <p style={{ margin: 0, fontSize: 13, color: '#8A9BB0', lineHeight: 1.5 }}>
            Monitoring your security perimeter 24/7.
          </p>
        </div>

        {/* Error */}
        {error && (
          <div style={{
            padding: '10px 14px', marginBottom: 16,
            background: 'rgba(255,59,59,0.08)',
            border: '1px solid rgba(255,59,59,0.2)',
            borderRadius: 8, fontSize: 12, color: '#FF7070',
            lineHeight: 1.5,
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} noValidate>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {mode === 'register' && (
              <Field label="Full name">
                <input
                  type="text"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  autoComplete="name"
                  autoFocus
                  required
                  style={inputStyle}
                  onFocus={focusInput}
                  onBlur={blurInput}
                />
              </Field>
            )}
            <Field label="Email address">
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                autoComplete="email"
                autoFocus={mode === 'login'}
                required
                style={inputStyle}
                onFocus={focusInput}
                onBlur={blurInput}
              />
            </Field>
            <Field label="Password">
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                required
                placeholder={mode === 'register' ? 'At least 8 characters' : 'Enter your password'}
                style={inputStyle}
                onFocus={focusInput}
                onBlur={blurInput}
              />
            </Field>
            {mode === 'register' && (
              <Field label="Workspace name (optional)">
                <input
                  type="text"
                  value={workspaceName}
                  onChange={e => setWorkspaceName(e.target.value)}
                  placeholder="e.g. Acme Corp"
                  style={inputStyle}
                  onFocus={focusInput}
                  onBlur={blurInput}
                />
              </Field>
            )}

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12 }}>
              <button
                type="button"
                onClick={() => { setMode(mode === 'login' ? 'register' : 'login'); setError(null) }}
                style={{ background: 'none', border: 'none', color: '#00D4FF', fontSize: 12, cursor: 'pointer', fontFamily: "'Manrope', sans-serif" }}
              >
                {mode === 'login' ? "New here? Create a workspace" : 'Already have an account? Sign in'}
              </button>
            </div>

            <PrimaryButton type="submit" label={loading ? 'Please wait…' : mode === 'login' ? 'Sign in →' : 'Create workspace →'} disabled={loading} />
          </div>
        </form>

        {/* Footer */}
        <div style={{
          marginTop: 28, paddingTop: 18,
          borderTop: '1px solid rgba(255,255,255,0.06)',
          fontSize: 11, color: '#2A3A4A',
          textAlign: 'center', lineHeight: 1.6,
        }}>
          Your data is isolated from other workspaces.
          <br />Each new account gets its own private workspace.
        </div>
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label style={{
        display: 'block', fontSize: 11, color: '#8A9BB0',
        fontWeight: 700, letterSpacing: '0.5px',
        textTransform: 'uppercase', marginBottom: 6,
      }}>
        {label}
      </label>
      {children}
    </div>
  )
}

function PrimaryButton({ type, label, disabled }: { type: 'submit' | 'button'; label: string; disabled?: boolean }) {
  const [hovered, setHovered] = useState(false)
  return (
    <button
      type={type}
      disabled={disabled}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        width: '100%', padding: '13px 0',
        background: disabled ? '#4A5D70' : hovered ? '#00BFEA' : '#00D4FF',
        color: '#0B0F14',
        border: 'none', borderRadius: 9,
        fontSize: 14, fontWeight: 800,
        cursor: disabled ? 'default' : 'pointer',
        transition: 'background 0.12s',
        letterSpacing: '0.1px',
      }}
    >
      {label}
    </button>
  )
}

const inputStyle: React.CSSProperties = {
  display: 'block',
  width: '100%',
  padding: '11px 14px',
  background: '#0B0F14',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: 8,
  color: '#E8EFF7',
  fontSize: 14,
  outline: 'none',
  transition: 'border-color 0.15s',
  boxSizing: 'border-box',
}

function focusInput(e: React.FocusEvent<HTMLInputElement>) {
  e.currentTarget.style.borderColor = 'rgba(0,212,255,0.45)'
}

function blurInput(e: React.FocusEvent<HTMLInputElement>) {
  e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)'
}
