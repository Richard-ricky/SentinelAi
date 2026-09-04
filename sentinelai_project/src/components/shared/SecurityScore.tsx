interface Props {
  score: number
  size?: number
}

export default function SecurityScore({ score, size = 120 }: Props) {
  const radius = (size - 16) / 2
  const circumference = 2 * Math.PI * radius
  const strokeDash = (score / 100) * circumference
  const color = score >= 80 ? '#22C55E' : score >= 60 ? '#FFB800' : score >= 40 ? '#FF8C00' : '#FF3B3B'

  return (
    <div style={{ position: 'relative', width: size, height: size }}>
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8"
        />
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          fill="none" stroke={color} strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={`${strokeDash} ${circumference}`}
          style={{ filter: `drop-shadow(0 0 6px ${color}80)`, transition: 'stroke-dasharray 1s ease' }}
        />
      </svg>
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
      }}>
        <span style={{ fontSize: size * 0.25, fontWeight: 800, color, letterSpacing: '-1px', lineHeight: 1 }}>{score}</span>
        <span style={{ fontSize: size * 0.085, color: '#4A5D70', fontWeight: 600, letterSpacing: '0.5px', textTransform: 'uppercase' }}>Score</span>
      </div>
    </div>
  )
}
