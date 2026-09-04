import { useEffect, useState } from 'react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, Legend } from 'recharts'
import { scoreHistory } from '../data/mockData'
import { api, getToken } from '../lib/api'

const CATEGORY_COLORS = ['#FF3B3B', '#FF8C00', '#FFB800', '#00D4FF', '#22C55E', '#A78BFA']

const monthlyData = [
  { month: 'Jan', critical: 4, high: 6, medium: 8, patched: 12 },
  { month: 'Feb', critical: 5, high: 7, medium: 9, patched: 15 },
  { month: 'Mar', critical: 3, high: 5, medium: 7, patched: 18 },
  { month: 'Apr', critical: 4, high: 4, medium: 6, patched: 20 },
  { month: 'May', critical: 6, high: 5, medium: 8, patched: 16 },
  { month: 'Jun', critical: 3, high: 3, medium: 5, patched: 22 },
  { month: 'Jul', critical: 3, high: 2, medium: 2, patched: 1 },
]

export default function Reports() {
  const [showReportModal, setShowReportModal] = useState(false)
  const [summary, setSummary] = useState<any | null>(null)
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([])
  const [downloading, setDownloading] = useState(false)
  const [downloadError, setDownloadError] = useState<string | null>(null)

  useEffect(() => {
    api.reports.summary().then(setSummary).catch(() => {})
    api.vulnerabilities.list().then(({ vulnerabilities }) => setVulnerabilities(vulnerabilities)).catch(() => {})
  }, [])

  const categoryData = (() => {
    const counts: Record<string, number> = {}
    for (const v of vulnerabilities) {
      if (v.status === 'Patched') continue
      counts[v.category] = (counts[v.category] || 0) + 1
    }
    const entries = Object.entries(counts)
    if (entries.length === 0) return [{ name: 'No open findings yet', value: 1, color: '#2A3A4A' }]
    return entries.map(([name, value], i) => ({ name, value, color: CATEGORY_COLORS[i % CATEGORY_COLORS.length] }))
  })()

  const downloadPdf = async () => {
    setDownloading(true)
    setDownloadError(null)
    try {
      const token = getToken()
      const res = await fetch(api.reports.pdfUrl(), {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) throw new Error('Report generation failed')
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'sentinelai-executive-report.pdf'
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch {
      setDownloadError('Could not generate the report. Make sure the backend server is running.')
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20, animation: 'fade-in 0.3s ease-out' }}>
      {/* Row 1: Score trend + Donut */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16 }}>
        {/* Score trend */}
        <Card title="Security Score Trend" subtitle="Sample trend — historical tracking coming soon">
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={scoreHistory}>
              <CartesianGrid stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />
              <XAxis dataKey="date" tick={{ fill: '#4A5D70', fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
              <YAxis domain={[30, 100]} tick={{ fill: '#4A5D70', fontSize: 11 }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: '#1A2332', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12, color: '#E8EFF7' }}
                cursor={{ stroke: 'rgba(255,255,255,0.1)' }}
              />
              <Line
                type="monotone" dataKey="score" stroke="#00D4FF" strokeWidth={2.5}
                dot={{ fill: '#00D4FF', r: 4, strokeWidth: 0 }}
                activeDot={{ r: 6, fill: '#00D4FF', strokeWidth: 0 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </Card>

        {/* Category breakdown */}
        <Card title="By Category" subtitle="Live — from your open findings">
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <PieChart width={130} height={130}>
              <Pie data={categoryData} cx={65} cy={65} innerRadius={38} outerRadius={58} dataKey="value" strokeWidth={0}>
                {categoryData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
              </Pie>
            </PieChart>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
              {categoryData.map(item => (
                <div key={item.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ width: 6, height: 6, borderRadius: '50%', background: item.color, flexShrink: 0 }} />
                    <span style={{ fontSize: 11, color: '#8A9BB0' }}>{item.name}</span>
                  </div>
                  <span style={{ fontSize: 11, fontWeight: 700, color: item.color, fontFamily: "'JetBrains Mono', monospace" }}>{item.value}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>

      {/* Row 2: Monthly breakdown */}
      <Card title="Monthly Vulnerability Activity" subtitle="Sample data — discovered vs patched over time">
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={monthlyData} barSize={14} barGap={4}>
            <CartesianGrid stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" vertical={false} />
            <XAxis dataKey="month" tick={{ fill: '#4A5D70', fontSize: 11 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: '#4A5D70', fontSize: 11 }} axisLine={false} tickLine={false} />
            <Tooltip contentStyle={{ background: '#1A2332', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 12, color: '#E8EFF7' }} />
            <Legend wrapperStyle={{ fontSize: 11, color: '#8A9BB0', paddingTop: 10 }} />
            <Bar dataKey="critical" name="Critical" fill="#FF3B3B" radius={[2,2,0,0]} />
            <Bar dataKey="high" name="High" fill="#FF8C00" radius={[2,2,0,0]} />
            <Bar dataKey="patched" name="Patched" fill="#22C55E" radius={[2,2,0,0]} />
          </BarChart>
        </ResponsiveContainer>
      </Card>

      {/* Row 3: Compliance + Report button */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16 }}>
        <ComplianceCard />

        {/* Executive report */}
        <Card title="Executive Report">
          <div style={{ textAlign: 'center', padding: '10px 0' }}>
            <div style={{ fontSize: 40, marginBottom: 12 }}>📄</div>
            <div style={{ fontSize: 13, color: '#8A9BB0', lineHeight: 1.6, marginBottom: 20 }}>
              Generate a PDF summary of your security posture, top vulnerabilities, and remediation progress — ready to share with your board or clients.
            </div>
            {downloadError && (
              <div style={{ marginBottom: 12, fontSize: 11, color: '#FF7070' }}>{downloadError}</div>
            )}
            <button
              onClick={() => setShowReportModal(true)}
              style={{
                width: '100%', padding: '12px 0',
                background: '#00D4FF', color: '#0B0F14',
                border: 'none', borderRadius: 8,
                fontSize: 14, fontWeight: 700,
                cursor: 'pointer', fontFamily: "'Manrope', sans-serif",
              }}>
              Preview Executive PDF Report
            </button>
            <button
              onClick={downloadPdf}
              disabled={downloading}
              style={{
                width: '100%', marginTop: 8, padding: '10px 0',
                background: 'rgba(0,212,255,0.08)', color: '#00D4FF',
                border: '1px solid rgba(0,212,255,0.2)', borderRadius: 8,
                fontSize: 13, fontWeight: 700,
                cursor: downloading ? 'default' : 'pointer', fontFamily: "'Manrope', sans-serif",
              }}>
              {downloading ? 'Generating…' : 'Download PDF now'}
            </button>
            <div style={{ marginTop: 12, fontSize: 11, color: '#4A5D70' }}>
              {summary ? `Security score: ${summary.securityScore}/100` : 'Loading current score…'}
            </div>
          </div>
        </Card>
      </div>

      {/* Modal */}
      {showReportModal && (
        <div style={{
          position: 'fixed', inset: 0,
          background: 'rgba(0,0,0,0.7)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          zIndex: 100,
        }} onClick={() => setShowReportModal(false)}>
          <div style={{
            background: '#131A22', border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: 14, padding: '28px 32px', width: 480,
          }} onClick={e => e.stopPropagation()}>
            <h3 style={{ margin: '0 0 6px', fontSize: 18, fontWeight: 700 }}>Executive Security Report</h3>
            <p style={{ margin: '0 0 20px', fontSize: 13, color: '#8A9BB0' }}>Live preview · generated from your current data</p>
            <div style={{ background: '#0B0F14', borderRadius: 8, padding: '20px', marginBottom: 20, fontSize: 12, color: '#8A9BB0', lineHeight: 1.8 }}>
              <div style={{ fontWeight: 700, color: '#E8EFF7', marginBottom: 8 }}>SentinelAI Security Report</div>
              {summary ? (
                <>
                  <div>Overall Score: <strong style={{ color: summary.securityScore >= 80 ? '#22C55E' : summary.securityScore >= 50 ? '#FFB800' : '#FF3B3B' }}>{summary.securityScore}/100</strong></div>
                  <div>Open vulnerabilities: <strong style={{ color: '#FF3B3B' }}>{summary.bySeverity?.Critical ?? 0} Critical</strong>, {summary.bySeverity?.High ?? 0} High, {summary.bySeverity?.Medium ?? 0} Medium, {summary.bySeverity?.Low ?? 0} Low</div>
                  <div>Assets monitored: {summary.totalAssets}</div>
                  <div>Patched vulnerabilities: {summary.patchedVulnerabilities}</div>
                </>
              ) : (
                <div>Loading current data…</div>
              )}
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button onClick={downloadPdf} disabled={downloading} style={{
                flex: 1, padding: '11px 0',
                background: '#00D4FF', color: '#0B0F14',
                border: 'none', borderRadius: 8, fontSize: 13, fontWeight: 700,
                cursor: downloading ? 'default' : 'pointer', fontFamily: "'Manrope', sans-serif",
              }}>{downloading ? 'Generating…' : 'Download PDF'}</button>
              <button onClick={() => setShowReportModal(false)} style={{
                padding: '11px 16px',
                background: 'rgba(255,255,255,0.05)',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 8, fontSize: 13, color: '#8A9BB0',
                cursor: 'pointer', fontFamily: "'Manrope', sans-serif",
              }}>Close</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

const FRAMEWORK_LABELS: Record<string, string> = { soc2: 'SOC 2', iso27001: 'ISO 27001', gdpr: 'GDPR' }

function ComplianceCard() {
  const [data, setData] = useState<any | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    api.reports.compliance().then(setData).catch(() => setError(true))
  }, [])

  return (
    <Card title="Compliance Readiness" subtitle="Maps open findings to real audit control families — not a certification">
      {error && <div style={{ fontSize: 12, color: '#4A5D70' }}>Could not load compliance data.</div>}
      {!error && !data && <div style={{ fontSize: 12, color: '#4A5D70' }}>Loading…</div>}
      {data && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {Object.entries(FRAMEWORK_LABELS).map(([key, label]) => {
            const fw = data.frameworks[key]
            const clear = fw.gapCount === 0
            return (
              <div key={key}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                  <span style={{ fontSize: 13, color: '#E8EFF7', fontWeight: 600 }}>{label}</span>
                  <span style={{
                    fontSize: 11, fontWeight: 700,
                    color: clear ? '#22C55E' : '#FF8C00',
                  }}>
                    {clear ? '✓ No open gaps' : `${fw.gapCount} control area(s) affected`}
                  </span>
                </div>
                {!clear && (
                  <div style={{ fontSize: 11, color: '#8A9BB0', lineHeight: 1.6 }}>
                    {fw.controlsWithGaps.slice(0, 2).map((c: any) => c.control).join('; ')}
                    {fw.controlsWithGaps.length > 2 ? `, +${fw.controlsWithGaps.length - 2} more` : ''}
                  </div>
                )}
              </div>
            )
          })}
          <div style={{
            marginTop: 4, padding: '10px 12px', background: 'rgba(0,212,255,0.05)',
            border: '1px dashed rgba(0,212,255,0.2)', borderRadius: 8, fontSize: 11, color: '#4A5D70', lineHeight: 1.5,
          }}>
            {data.disclaimer}
          </div>
        </div>
      )}
    </Card>
  )
}

function Card({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <div style={{
      background: '#131A22',
      border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 12, padding: '20px 22px',
    }}>
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#E8EFF7' }}>{title}</div>
        {subtitle && <div style={{ fontSize: 11, color: '#4A5D70', marginTop: 2 }}>{subtitle}</div>}
      </div>
      {children}
    </div>
  )
}
