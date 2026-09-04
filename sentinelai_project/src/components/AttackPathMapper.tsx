import { useState, useRef, useCallback, useEffect, useMemo } from 'react'
import { api } from '../lib/api'

// NOTE ON SCOPE: this view shows your real registered assets and their
// real current risk severity from actual scans — every node and edge here
// is backed by data from the API, not a scripted demo. What it does NOT
// do is invent multi-hop internal attack chains ("pivot from server A to
// database B") — SentinelAI doesn't have real network topology data (which
// devices can actually reach which others internally), so fabricating that
// would be misleading. This view honestly shows external exposure: what's
// reachable from the internet, and how risky each thing currently is.
// Real lateral-movement mapping is future work that needs either an
// on-prem network agent or manually-declared topology.

type Risk = 'critical' | 'high' | 'medium' | 'low' | 'safe'
type NodeType = 'external' | 'website' | 'server' | 'endpoint' | 'database' | 'cloud'

interface GraphNode {
  id: string
  label: string
  type: NodeType
  risk: Risk
  x: number
  y: number
  target?: string
  vulnCount: number
  vulns: { name: string; severity: string; category: string }[]
}

interface Edge {
  from: string
  to: string
  path: 'critical' | 'high' | 'normal'
}

const SVG_W = 900
const SVG_H = 480

const RISK_COLOR: Record<Risk, string> = {
  critical: '#FF3B3B',
  high: '#FF8C00',
  medium: '#FFB800',
  low: '#22C55E',
  safe: '#4A5D70',
}

const EDGE_COLOR: Record<string, string> = {
  critical: '#FF3B3B',
  high: '#FF8C00',
  normal: '#3A4D60',
}

const NODE_RADIUS: Record<NodeType, number> = {
  database: 20,
  external: 16,
  cloud: 17,
  website: 14,
  server: 14,
  endpoint: 13,
}

const SEVERITY_RANK: Record<string, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 }

function nodeIcon(type: NodeType): string {
  switch (type) {
    case 'database': return 'DB'
    case 'cloud': return 'S3'
    case 'external': return 'NET'
    case 'endpoint': return 'PC'
    case 'website': return 'WEB'
    default: return 'SRV'
  }
}

function riskFromVulns(vulns: { severity: string }[]): Risk {
  if (vulns.some(v => v.severity === 'Critical')) return 'critical'
  if (vulns.some(v => v.severity === 'High')) return 'high'
  if (vulns.some(v => v.severity === 'Medium')) return 'medium'
  if (vulns.length > 0) return 'low'
  return 'safe'
}

export default function AttackPathMapper() {
  const [assets, setAssets] = useState<any[]>([])
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [hoveredId, setHoveredId] = useState<string | null>(null)
  const [filterPath, setFilterPath] = useState<'all' | 'critical' | 'high'>('all')
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [isDragging, setIsDragging] = useState(false)
  const dragStart = useRef<{ mouseX: number; mouseY: number; panX: number; panY: number } | null>(null)

  useEffect(() => {
    Promise.all([api.assets.list(), api.vulnerabilities.list()])
      .then(([a, v]) => {
        setAssets(a.assets)
        setVulnerabilities(v.vulnerabilities)
        setError(null)
      })
      .catch(() => setError('Could not reach the SentinelAI API.'))
      .finally(() => setLoading(false))
  }, [])

  // Real node/edge computation from real data. Only asset-derived data
  // reaches this — nothing here is scripted.
  const { nodes, edges } = useMemo(() => {
    const openVulnsByAsset = new Map<string, any[]>()
    for (const v of vulnerabilities) {
      if (v.status === 'Patched') continue
      const list = openVulnsByAsset.get(v.asset_id) ?? []
      list.push(v)
      openVulnsByAsset.set(v.asset_id, list)
    }

    const internetNode: GraphNode = {
      id: 'internet',
      label: 'Public Internet',
      type: 'external',
      risk: 'safe',
      x: 90, y: SVG_H / 2,
      vulnCount: 0,
      vulns: [],
    }

    const assetNodes: GraphNode[] = assets.map((asset, i) => {
      const vulns = (openVulnsByAsset.get(asset.id) ?? [])
        .slice()
        .sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
      const t = assets.length <= 1 ? 0.5 : i / (assets.length - 1)
      const x = 300 + t * (SVG_W - 380)
      const y = SVG_H / 2 + Math.sin(i * 2.3) * (SVG_H / 2 - 70)
      const type: NodeType = ['website', 'server', 'endpoint', 'database', 'cloud'].includes(asset.type)
        ? asset.type
        : 'server'

      return {
        id: asset.id,
        label: asset.name,
        type,
        risk: riskFromVulns(vulns),
        x, y,
        target: asset.target,
        vulnCount: vulns.length,
        vulns: vulns.map(v => ({ name: v.name, severity: v.severity, category: v.category })),
      }
    })

    const allNodes = [internetNode, ...assetNodes]

    // Honest edges: internet → each monitored asset only. No fabricated
    // internal pivoting — we don't have real topology data to back that.
    const allEdges: Edge[] = assetNodes.map(n => ({
      from: 'internet',
      to: n.id,
      path: n.risk === 'critical' ? 'critical' : n.risk === 'high' ? 'high' : 'normal',
    }))

    return { nodes: allNodes, edges: allEdges }
  }, [assets, vulnerabilities])

  const getNode = useCallback((id: string) => nodes.find(n => n.id === id)!, [nodes])
  const selectedNode = selectedId ? getNode(selectedId) : null

  const visibleEdges = edges.filter(e => filterPath === 'all' || e.path === filterPath)
  const connectedEdges = selectedId ? edges.filter(e => e.from === selectedId || e.to === selectedId) : []

  const rankedRisky = useMemo(
    () => nodes.filter(n => n.id !== 'internet' && n.risk !== 'safe')
      .sort((a, b) => SEVERITY_RANK[a.vulns[0]?.severity ?? 'Low'] - SEVERITY_RANK[b.vulns[0]?.severity ?? 'Low']),
    [nodes]
  )

  const transformStr = `translate(${SVG_W / 2 + pan.x} ${SVG_H / 2 + pan.y}) scale(${zoom}) translate(${-SVG_W / 2} ${-SVG_H / 2})`

  const onMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    dragStart.current = { mouseX: e.clientX, mouseY: e.clientY, panX: pan.x, panY: pan.y }
    setIsDragging(true)
  }, [pan])

  const onMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragStart.current) return
    const dx = e.clientX - dragStart.current.mouseX
    const dy = e.clientY - dragStart.current.mouseY
    setPan({ x: dragStart.current.panX + dx, y: dragStart.current.panY + dy })
  }, [])

  const onMouseUp = useCallback(() => {
    dragStart.current = null
    setIsDragging(false)
  }, [])

  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault()
    const delta = -e.deltaY * 0.001
    setZoom(z => Math.max(0.4, Math.min(2.5, z + delta)))
  }, [])

  useEffect(() => {
    const up = () => { dragStart.current = null; setIsDragging(false) }
    window.addEventListener('mouseup', up)
    return () => window.removeEventListener('mouseup', up)
  }, [])

  if (loading) {
    return <div style={{ color: '#8A9BB0', fontSize: 13 }}>Loading attack surface map…</div>
  }

  if (error) {
    return (
      <div style={{ background: 'rgba(255,59,59,0.08)', border: '1px solid rgba(255,59,59,0.2)', borderRadius: 12, padding: 20, color: '#FF7070', fontSize: 13 }}>
        {error}
      </div>
    )
  }

  if (assets.length === 0) {
    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        height: '60vh', color: '#4A5D70', textAlign: 'center', gap: 8,
      }}>
        <div style={{ fontSize: 28, opacity: 0.3 }}>◉</div>
        <div style={{ fontSize: 13, maxWidth: 340, lineHeight: 1.6 }}>
          No assets registered yet. Add an asset and run a scan from the Vulnerabilities tab —
          this map will populate with your real external attack surface.
        </div>
      </div>
    )
  }

  return (
    <div className="animate-fade-in-up" style={{ display: 'flex', gap: 20, height: 'calc(100vh - 112px)' }}>
      {/* Graph panel */}
      <div style={{
        flex: 1, minWidth: 0,
        background: '#0E1520',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: 12,
        display: 'flex', flexDirection: 'column',
        overflow: 'hidden',
      }}>
        {/* Toolbar */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '12px 18px',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          flexShrink: 0,
          background: '#0B0F14',
        }}>
          <span style={{ fontSize: 11, color: '#4A5D70', fontWeight: 700, letterSpacing: '0.5px', textTransform: 'uppercase', marginRight: 4 }}>Show:</span>
          {(['all', 'critical', 'high'] as const).map(f => {
            const active = filterPath === f
            const col = f === 'critical' ? '#FF3B3B' : f === 'high' ? '#FF8C00' : '#00D4FF'
            return (
              <button
                key={f}
                onClick={() => setFilterPath(f)}
                style={{
                  padding: '5px 13px', borderRadius: 6,
                  background: active ? `${col}18` : 'rgba(255,255,255,0.03)',
                  border: `1px solid ${active ? `${col}50` : 'rgba(255,255,255,0.07)'}`,
                  color: active ? col : '#8A9BB0',
                  fontSize: 12, fontWeight: 600, cursor: 'pointer',
                  transition: 'all 0.15s',
                }}
              >
                {f === 'all' ? 'All' : `${f.charAt(0).toUpperCase() + f.slice(1)} risk`}
              </button>
            )
          })}

          <div style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: '#4A5D70', fontFamily: "'JetBrains Mono', monospace" }}>
              {Math.round(zoom * 100)}%
            </span>
            <ToolBtn onClick={() => setZoom(z => Math.min(2.5, +(z + 0.2).toFixed(1)))} label="+" title="Zoom in" />
            <ToolBtn onClick={() => setZoom(z => Math.max(0.4, +(z - 0.2).toFixed(1)))} label="−" title="Zoom out" />
            <ToolBtn onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }) }} label="Reset" title="Reset view" />
          </div>
        </div>

        {/* Legend + honesty note */}
        <div style={{
          display: 'flex', flexDirection: 'column', gap: 4,
          padding: '7px 18px',
          borderBottom: '1px solid rgba(255,255,255,0.04)',
          flexShrink: 0,
        }}>
          <div style={{ display: 'flex', gap: 20, alignItems: 'center' }}>
            {(['critical', 'high', 'medium', 'low'] as const).map(r => (
              <div key={r} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ width: 7, height: 7, borderRadius: '50%', background: RISK_COLOR[r], boxShadow: `0 0 5px ${RISK_COLOR[r]}80` }} />
                <span style={{ fontSize: 11, color: '#4A5D70', textTransform: 'capitalize' }}>{r}</span>
              </div>
            ))}
            <span style={{ marginLeft: 'auto', fontSize: 10, color: '#3A4A58', fontStyle: 'italic' }}>
              real data from your last scans
            </span>
          </div>
        </div>

        {/* SVG graph */}
        <div
          className="no-select"
          onMouseDown={onMouseDown}
          onMouseMove={onMouseMove}
          onMouseUp={onMouseUp}
          onMouseLeave={onMouseUp}
          onWheel={onWheel}
          style={{ flex: 1, cursor: isDragging ? 'grabbing' : 'grab', overflow: 'hidden', position: 'relative' }}
        >
          <svg width="100%" height="100%" viewBox={`0 0 ${SVG_W} ${SVG_H}`} style={{ display: 'block' }}>
            <defs>
              {(['critical', 'high', 'normal', 'low', 'medium', 'safe'] as const).map(k => (
                <filter key={k} id={`sentinel-glow-${k}`} x="-50%" y="-50%" width="200%" height="200%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                </filter>
              ))}
              {(['critical', 'high', 'normal'] as const).map(p => (
                <marker key={p} id={`sentinel-arrow-${p}`} markerWidth="7" markerHeight="7" refX="5" refY="3.5" orient="auto">
                  <polygon points="0 0, 7 3.5, 0 7" fill={EDGE_COLOR[p]} opacity={p === 'normal' ? 0.5 : 0.9} />
                </marker>
              ))}
              <pattern id="sentinel-grid" width="40" height="40" patternUnits="userSpaceOnUse">
                <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.025)" strokeWidth="0.5" />
              </pattern>
            </defs>

            <rect width={SVG_W} height={SVG_H} fill="url(#sentinel-grid)" />

            <g transform={transformStr}>
              {visibleEdges.map((edge, i) => {
                const from = getNode(edge.from)
                const to = getNode(edge.to)
                const mx = (from.x + to.x) / 2
                const my = (from.y + to.y) / 2 - 28
                const col = EDGE_COLOR[edge.path]
                const isHighlighted = selectedId ? edge.from === selectedId || edge.to === selectedId : true
                const opacity = selectedId ? (isHighlighted ? 1 : 0.12) : 0.85

                return (
                  <g key={i} style={{ opacity, transition: 'opacity 0.2s' }}>
                    <path
                      d={`M ${from.x} ${from.y} Q ${mx} ${my} ${to.x} ${to.y}`}
                      stroke={col}
                      strokeWidth={edge.path === 'critical' ? 2.2 : edge.path === 'high' ? 1.6 : 1}
                      fill="none"
                      strokeDasharray={edge.path === 'critical' ? '7 4' : edge.path === 'high' ? '4 3' : undefined}
                      filter={`url(#sentinel-glow-${edge.path})`}
                      markerEnd={`url(#sentinel-arrow-${edge.path})`}
                      style={edge.path === 'critical' ? { animation: 'dash-flow 1.8s linear infinite' } : undefined}
                    />
                  </g>
                )
              })}

              {nodes.map(node => {
                const col = RISK_COLOR[node.risk]
                const r = NODE_RADIUS[node.type] ?? 14
                const isSelected = selectedId === node.id
                const isHovered = hoveredId === node.id
                const isDimmed = !!(selectedId && !isSelected && !connectedEdges.some(e => e.from === node.id || e.to === node.id))
                const opacity = isDimmed ? 0.2 : 1

                return (
                  <g
                    key={node.id}
                    onClick={(e) => { e.stopPropagation(); setSelectedId(node.id === selectedId ? null : node.id) }}
                    onMouseEnter={() => setHoveredId(node.id)}
                    onMouseLeave={() => setHoveredId(null)}
                    style={{ cursor: 'pointer', opacity, transition: 'opacity 0.2s' }}
                  >
                    {node.risk === 'critical' && (
                      <circle cx={node.x} cy={node.y} r={r + 10} fill="none" stroke={col} strokeWidth="1" opacity="0.2"
                        style={{ animation: 'pulse-live 2.2s ease-in-out infinite' }} />
                    )}
                    {isSelected && (
                      <circle cx={node.x} cy={node.y} r={r + 7} fill="none" stroke={col} strokeWidth="1.5" opacity="0.5" strokeDasharray="3 2" />
                    )}
                    <circle
                      cx={node.x} cy={node.y}
                      r={isHovered ? r + 2 : r}
                      fill={isSelected ? `${col}30` : `${col}18`}
                      stroke={col}
                      strokeWidth={isSelected ? 2 : isHovered ? 2 : 1.5}
                      filter={`url(#sentinel-glow-${node.risk})`}
                    />
                    <text x={node.x} y={node.y + 1} textAnchor="middle" dominantBaseline="middle"
                      fill={col} fontSize={7} fontFamily="'JetBrains Mono', monospace" fontWeight="600" style={{ pointerEvents: 'none' }}>
                      {nodeIcon(node.type)}
                    </text>
                    <text x={node.x} y={node.y + r + 13} textAnchor="middle"
                      fill={isSelected ? '#E8EFF7' : '#9AABB8'} fontSize="9.5" fontFamily="'Manrope', sans-serif" fontWeight="600"
                      style={{ pointerEvents: 'none' }}>
                      {node.label}
                    </text>
                    {node.vulnCount > 0 && (
                      <>
                        <circle cx={node.x + r - 2} cy={node.y - r + 2} r="6" fill={col} />
                        <text x={node.x + r - 2} y={node.y - r + 2} textAnchor="middle" dominantBaseline="middle"
                          fill="#0B0F14" fontSize="7" fontWeight="800" style={{ pointerEvents: 'none' }}>
                          {node.vulnCount}
                        </text>
                      </>
                    )}
                  </g>
                )
              })}
            </g>

            {!selectedId && (
              <text x={SVG_W - 12} y={SVG_H - 10} textAnchor="end" fill="rgba(255,255,255,0.15)" fontSize="10" fontFamily="'JetBrains Mono', monospace">
                scroll to zoom · drag to pan · click node to inspect
              </text>
            )}
          </svg>
        </div>
      </div>

      {/* Right panel */}
      <div style={{ width: 310, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 14, overflowY: 'auto' }}>
        {/* Node detail */}
        <div style={{
          background: '#131A22',
          border: `1px solid ${selectedNode ? RISK_COLOR[selectedNode.risk] + '35' : 'rgba(255,255,255,0.07)'}`,
          borderRadius: 12, padding: '18px 18px', transition: 'border-color 0.2s', flexShrink: 0,
        }}>
          {selectedNode ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: RISK_COLOR[selectedNode.risk], boxShadow: `0 0 6px ${RISK_COLOR[selectedNode.risk]}` }} />
                  <span style={{ fontSize: 11, color: RISK_COLOR[selectedNode.risk], fontWeight: 700, textTransform: 'capitalize' }}>
                    {selectedNode.risk === 'safe' ? 'No open findings' : `${selectedNode.risk} risk`}
                  </span>
                </div>
                <button onClick={() => setSelectedId(null)} style={{ background: 'none', border: 'none', color: '#4A5D70', cursor: 'pointer', fontSize: 16, lineHeight: 1, padding: 2 }} aria-label="Close detail">✕</button>
              </div>

              <div style={{ fontSize: 15, fontWeight: 700, color: '#E8EFF7', marginBottom: 4, lineHeight: 1.3 }}>{selectedNode.label}</div>
              {selectedNode.target && (
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10, color: '#4A5D70', marginBottom: 10 }}>
                  {selectedNode.target} · {selectedNode.type}
                </div>
              )}

              {selectedNode.vulns.length > 0 ? (
                <div style={{ borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 12 }}>
                  <div style={{ fontSize: 10, color: '#4A5D70', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>
                    Open findings ({selectedNode.vulns.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {selectedNode.vulns.map((v, i) => (
                      <div key={i} style={{
                        padding: '7px 10px', borderRadius: 6,
                        background: 'rgba(255,255,255,0.03)',
                        border: `1px solid ${(EDGE_COLOR as any)[v.severity] || 'rgba(255,255,255,0.07)'}25`,
                      }}>
                        <div style={{ fontSize: 11.5, color: '#C8D5E3', fontWeight: 600 }}>{v.name}</div>
                        <div style={{ fontSize: 10, color: '#4A5D70', marginTop: 2 }}>{v.severity} · {v.category}</div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : selectedNode.id !== 'internet' && (
                <div style={{ fontSize: 12, color: '#4A5D70', lineHeight: 1.6 }}>
                  No open findings for this asset right now.
                </div>
              )}
            </>
          ) : (
            <div style={{ textAlign: 'center', padding: '14px 0' }}>
              <div style={{ fontSize: 24, marginBottom: 8, opacity: 0.25 }}>◉</div>
              <div style={{ fontSize: 12, color: '#4A5D70', lineHeight: 1.6 }}>
                Click any node to see its real open findings.
              </div>
            </div>
          )}
        </div>

        {/* Honest scope note */}
        <div style={{
          background: '#131A22', border: '1px solid rgba(0,212,255,0.15)', borderRadius: 12,
          padding: '14px 16px', flexShrink: 0, fontSize: 11, color: '#8A9BB0', lineHeight: 1.6,
        }}>
          <strong style={{ color: '#00D4FF' }}>Scope note:</strong> this map shows your real external
          attack surface — actual assets and actual open findings. It does not yet infer multi-hop
          internal attack chains (e.g. "server A can pivot to database B"), since that requires real
          network topology data SentinelAI doesn't collect yet. Treat each node's risk as independent
          until that's built.
        </div>

        {/* Highest-risk assets, ranked by real severity */}
        <div style={{ background: '#131A22', border: '1px solid rgba(255,59,59,0.18)', borderRadius: 12, padding: '16px 18px', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 14 }}>
            <div className="animate-pulse-live" style={{ width: 7, height: 7, borderRadius: '50%', background: '#FF3B3B', boxShadow: '0 0 6px #FF3B3B' }} />
            <span style={{ fontSize: 11, color: '#FF3B3B', fontWeight: 700, letterSpacing: '0.4px', textTransform: 'uppercase' }}>
              Highest-risk assets
            </span>
          </div>
          {rankedRisky.length === 0 ? (
            <div style={{ fontSize: 12, color: '#4A5D70' }}>No open findings on any asset right now.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {rankedRisky.slice(0, 5).map(n => (
                <button
                  key={n.id}
                  onClick={() => setSelectedId(n.id)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8, textAlign: 'left',
                    padding: '7px 10px', borderRadius: 6,
                    background: 'rgba(255,255,255,0.03)', border: `1px solid ${RISK_COLOR[n.risk]}25`,
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: RISK_COLOR[n.risk], flexShrink: 0 }} />
                  <span style={{ fontSize: 12, color: '#C8D5E3', fontWeight: 600, flex: 1 }}>{n.label}</span>
                  <span style={{ fontSize: 10, color: RISK_COLOR[n.risk], fontFamily: "'JetBrains Mono', monospace" }}>{n.vulnCount} finding{n.vulnCount !== 1 ? 's' : ''}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Asset summary */}
        <div style={{ background: '#131A22', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 12, padding: '14px 18px', flexShrink: 0 }}>
          <div style={{ fontSize: 10, color: '#4A5D70', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
            Asset summary
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {[
              { label: 'Assets monitored', value: String(assets.length), color: '#8A9BB0' },
              { label: 'Total open findings', value: String(vulnerabilities.filter(v => v.status !== 'Patched').length), color: '#8A9BB0' },
              { label: 'Critical assets', value: String(nodes.filter(n => n.risk === 'critical').length), color: '#FF3B3B' },
              { label: 'High risk assets', value: String(nodes.filter(n => n.risk === 'high').length), color: '#FF8C00' },
            ].map(item => (
              <div key={item.label} style={{ padding: '8px 10px', background: 'rgba(255,255,255,0.03)', borderRadius: 7, border: '1px solid rgba(255,255,255,0.05)' }}>
                <div style={{ fontSize: 18, fontWeight: 800, color: item.color, letterSpacing: '-0.5px', lineHeight: 1 }}>{item.value}</div>
                <div style={{ fontSize: 10, color: '#4A5D70', marginTop: 3 }}>{item.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function ToolBtn({ onClick, label, title }: { onClick: () => void; label: string; title: string }) {
  const [hovered, setHovered] = useState(false)
  return (
    <button
      onClick={onClick}
      title={title}
      aria-label={title}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        padding: '5px 10px', borderRadius: 6,
        background: hovered ? 'rgba(255,255,255,0.08)' : 'rgba(255,255,255,0.04)',
        border: '1px solid rgba(255,255,255,0.08)',
        color: hovered ? '#E8EFF7' : '#8A9BB0',
        fontSize: 13, fontWeight: 600, cursor: 'pointer',
        transition: 'all 0.12s',
        lineHeight: 1,
      }}
    >
      {label}
    </button>
  )
}
