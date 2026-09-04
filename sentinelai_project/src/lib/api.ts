// Central API client for the SentinelAI backend.
// The backend URL defaults to localhost:4000 for local dev; override with
// VITE_API_URL when deploying the frontend separately from the backend.

const BASE_URL = (import.meta as any).env?.VITE_API_URL || 'http://localhost:4000'

const TOKEN_KEY = 'sentinelai_token'
const USER_KEY = 'sentinelai_user'

export interface AuthUser {
  id: string
  workspace_id: string
  name: string
  email: string
  role: 'admin' | 'analyst' | 'viewer'
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function getStoredUser(): AuthUser | null {
  const raw = localStorage.getItem(USER_KEY)
  return raw ? JSON.parse(raw) : null
}

function setSession(token: string, user: AuthUser) {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken()
  const res = await fetch(`${BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  })

  if (!res.ok) {
    let message = `Request failed (${res.status})`
    try {
      const body = await res.json()
      message = body.error || message
    } catch {
      // ignore parse failure
    }
    throw new ApiError(message, res.status)
  }

  const contentType = res.headers.get('content-type') || ''
  if (contentType.includes('application/json')) return res.json()
  return res as unknown as T
}

export const api = {
  async register(name: string, email: string, password: string, workspaceName?: string) {
    const data = await request<{ token: string; user: AuthUser }>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ name, email, password, workspaceName }),
    })
    setSession(data.token, data.user)
    return data.user
  },

  async login(email: string, password: string) {
    const data = await request<{ token: string; user: AuthUser }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })
    setSession(data.token, data.user)
    return data.user
  },

  logout() {
    clearSession()
  },

  assets: {
    list: () => request<{ assets: any[] }>('/api/assets'),
    create: (payload: { name: string; type: string; target: string }) =>
      request<{ asset: any }>('/api/assets', { method: 'POST', body: JSON.stringify(payload) }),
    remove: (id: string) => request<{ ok: boolean }>(`/api/assets/${id}`, { method: 'DELETE' }),
    discover: (domain: string) =>
      request<{ candidates: { host: string; addresses: string[] }[] }>('/api/assets/discover', {
        method: 'POST',
        body: JSON.stringify({ domain }),
      }),
    setAutoScan: (id: string, enabled: boolean) =>
      request<{ asset: any }>(`/api/assets/${id}/auto-scan`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled }),
      }),
  },

  monitoring: {
    status: () => request<{ intervalMinutes: number; running: boolean }>('/api/monitoring/status'),
    runNow: () => request<{ ok: boolean; message: string }>('/api/monitoring/run-now', { method: 'POST' }),
  },

  scans: {
    run: (assetId: string) =>
      request<{ scan: any; vulnerabilities: any[] }>(`/api/scans/assets/${assetId}`, { method: 'POST' }),
    list: () => request<{ scans: any[] }>('/api/scans'),
  },

  vulnerabilities: {
    list: () => request<{ vulnerabilities: any[] }>('/api/vulnerabilities'),
    get: (id: string) => request<{ vulnerability: any }>(`/api/vulnerabilities/${id}`),
    explain: (id: string) =>
      request<{ explanation: string }>(`/api/vulnerabilities/${id}/explain`, { method: 'POST' }),
    chat: (id: string, message: string, history: { role: string; content: string }[]) =>
      request<{ reply: string }>(`/api/vulnerabilities/${id}/chat`, {
        method: 'POST',
        body: JSON.stringify({ message, history }),
      }),
    patch: (id: string, decision: 'approved' | 'rejected') =>
      request<{ vulnerability: any }>(`/api/vulnerabilities/${id}/patch`, {
        method: 'POST',
        body: JSON.stringify({ decision }),
      }),
    setStatus: (id: string, status: string) =>
      request<{ vulnerability: any }>(`/api/vulnerabilities/${id}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      }),
  },

  notifications: {
    list: () => request<{ notifications: any[] }>('/api/notifications'),
    markRead: (id: string) => request<{ ok: boolean }>(`/api/notifications/${id}/read`, { method: 'PATCH' }),
    markAllRead: () => request<{ ok: boolean }>('/api/notifications/read-all', { method: 'POST' }),
  },

  reports: {
    summary: () => request<any>('/api/reports/summary'),
    pdfUrl: () => `${BASE_URL}/api/reports/pdf`,
    compliance: () => request<any>('/api/reports/compliance'),
  },

  apiKeys: {
    list: () => request<{ apiKeys: any[] }>('/api/settings/api-keys'),
    create: (name: string) =>
      request<{ apiKey: any; rawKey: string }>('/api/settings/api-keys', {
        method: 'POST',
        body: JSON.stringify({ name }),
      }),
    revoke: (id: string) => request<{ ok: boolean }>(`/api/settings/api-keys/${id}`, { method: 'DELETE' }),
  },

  webhooks: {
    list: () => request<{ webhooks: any[] }>('/api/settings/webhooks'),
    create: (url: string, events?: string[]) =>
      request<{ webhook: any; secret: string }>('/api/settings/webhooks', {
        method: 'POST',
        body: JSON.stringify({ url, events }),
      }),
    test: (id: string) => request<{ webhook: any }>(`/api/settings/webhooks/${id}/test`, { method: 'POST' }),
    remove: (id: string) => request<{ ok: boolean }>(`/api/settings/webhooks/${id}`, { method: 'DELETE' }),
  },

  team: {
    list: () => request<{ members: any[] }>('/api/team'),
    invite: (name: string, email: string, role: string) =>
      request<{ member: any; tempPassword: string }>('/api/team/invite', {
        method: 'POST',
        body: JSON.stringify({ name, email, role }),
      }),
    setRole: (userId: string, role: string) =>
      request<{ member: any }>(`/api/team/${userId}/role`, { method: 'PATCH', body: JSON.stringify({ role }) }),
    remove: (userId: string) => request<{ ok: boolean }>(`/api/team/${userId}`, { method: 'DELETE' }),
  },

  cloud: {
    list: () => request<{ connections: any[] }>('/api/cloud'),
    connectAws: (accessKeyId: string, secretAccessKey: string, region: string, label?: string) =>
      request<{ connection: any }>('/api/cloud/aws/connect', {
        method: 'POST',
        body: JSON.stringify({ accessKeyId, secretAccessKey, region, label }),
      }),
    disconnectAws: () => request<{ ok: boolean }>('/api/cloud/aws', { method: 'DELETE' }),
    scanAws: () => request<{ findingCount: number; vulnerabilities: any[] }>('/api/cloud/aws/scan', { method: 'POST' }),
  },
}

export { ApiError }