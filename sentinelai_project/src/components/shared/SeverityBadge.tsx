export type Severity = 'Critical' | 'High' | 'Medium' | 'Low'

const config: Record<Severity, { color: string; bg: string; icon: string }> = {
  Critical: { color: '#FF3B3B', bg: 'rgba(255,59,59,0.12)', icon: '⊗' },
  High:     { color: '#FF8C00', bg: 'rgba(255,140,0,0.12)', icon: '▲' },
  Medium:   { color: '#FFB800', bg: 'rgba(255,184,0,0.12)', icon: '◆' },
  Low:      { color: '#22C55E', bg: 'rgba(34,197,94,0.12)', icon: '●' },
}

interface Props {
  severity: Severity
  size?: 'sm' | 'md'
}

export default function SeverityBadge({ severity, size = 'md' }: Props) {
  const c = config[severity]
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: size === 'sm' ? '2px 7px' : '4px 10px',
      background: c.bg,
      border: `1px solid ${c.color}33`,
      borderRadius: 6,
      color: c.color,
      fontSize: size === 'sm' ? 11 : 12,
      fontWeight: 600,
      fontFamily: "'Manrope', sans-serif",
      letterSpacing: '0.3px',
      whiteSpace: 'nowrap',
    }}>
      <span style={{ fontSize: size === 'sm' ? 8 : 9 }}>{c.icon}</span>
      {severity}
    </span>
  )
}
