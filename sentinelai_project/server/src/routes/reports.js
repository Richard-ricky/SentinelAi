import { Router } from 'express'
import PDFDocument from 'pdfkit'
import { db } from '../db/index.js'
import { requireAuth } from '../middleware/auth.js'
import { buildComplianceReport } from '../lib/compliance.js'

const router = Router()
router.use(requireAuth)

const SEVERITY_WEIGHT = { Critical: 25, High: 12, Medium: 5, Low: 2 }

function computeScore(vulns) {
  const open = vulns.filter((v) => v.status !== 'Patched')
  const penalty = open.reduce((sum, v) => sum + (SEVERITY_WEIGHT[v.severity] || 0), 0)
  return Math.max(0, 100 - penalty)
}

router.get('/summary', (req, res) => {
  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE workspace_id = ?').all(req.user.workspace_id)
  const assets = db.prepare('SELECT * FROM assets WHERE workspace_id = ?').all(req.user.workspace_id)

  const bySeverity = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  for (const v of vulns) if (v.status !== 'Patched') bySeverity[v.severity] = (bySeverity[v.severity] || 0) + 1

  res.json({
    securityScore: computeScore(vulns),
    totalAssets: assets.length,
    openVulnerabilities: vulns.filter((v) => v.status !== 'Patched').length,
    patchedVulnerabilities: vulns.filter((v) => v.status === 'Patched').length,
    bySeverity,
  })
})

router.get('/compliance', (req, res) => {
  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE workspace_id = ?').all(req.user.workspace_id)
  res.json({
    frameworks: buildComplianceReport(vulns),
    disclaimer:
      'This is a readiness aid based on automated technical scanning, not a certification. A real audit also covers policy, process, and organizational controls this tool cannot assess.',
  })
})

router.get('/pdf', (req, res) => {
  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE workspace_id = ?').all(req.user.workspace_id)
  const assets = db.prepare('SELECT * FROM assets WHERE workspace_id = ?').all(req.user.workspace_id)
  const score = computeScore(vulns)

  res.setHeader('Content-Type', 'application/pdf')
  res.setHeader('Content-Disposition', 'attachment; filename="sentinelai-executive-report.pdf"')

  const doc = new PDFDocument({ margin: 50 })
  doc.pipe(res)

  doc.fontSize(22).fillColor('#0B0F14').text('SentinelAI — Executive Security Report', { align: 'left' })
  doc.moveDown(0.3)
  doc.fontSize(10).fillColor('#555').text(`Generated ${new Date().toLocaleString()} for ${req.user.name}`)
  doc.moveDown(1.2)

  doc.fontSize(14).fillColor('#0B0F14').text('Overview')
  doc.fontSize(11).fillColor('#333')
  doc.text(`Security Score: ${score} / 100`)
  doc.text(`Monitored Assets: ${assets.length}`)
  doc.text(`Open Vulnerabilities: ${vulns.filter((v) => v.status !== 'Patched').length}`)
  doc.text(`Patched Vulnerabilities: ${vulns.filter((v) => v.status === 'Patched').length}`)
  doc.moveDown(1)

  doc.fontSize(14).fillColor('#0B0F14').text('Findings by Severity')
  doc.fontSize(11).fillColor('#333')
  for (const sev of ['Critical', 'High', 'Medium', 'Low']) {
    const count = vulns.filter((v) => v.severity === sev && v.status !== 'Patched').length
    doc.text(`${sev}: ${count}`)
  }
  doc.moveDown(1)

  doc.fontSize(14).fillColor('#0B0F14').text('Open Findings — Detail')
  doc.moveDown(0.3)
  const open = vulns.filter((v) => v.status !== 'Patched').sort((a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0))

  if (open.length === 0) {
    doc.fontSize(11).fillColor('#333').text('No open findings — great work.')
  }

  for (const v of open) {
    const asset = assets.find((a) => a.id === v.asset_id)
    doc.fontSize(12).fillColor('#0B0F14').text(`${v.severity} — ${v.name}`)
    doc.fontSize(10).fillColor('#555').text(`Asset: ${asset?.name || 'unknown'}  |  Category: ${v.category}${v.cve ? `  |  ${v.cve}` : ''}`)
    doc.fontSize(10).fillColor('#333').text(v.description || '')
    if (v.fix) {
      doc.fontSize(10).fillColor('#046a38').text(`Recommended fix: ${v.fix}`)
    }
    doc.moveDown(0.7)
  }

  doc.addPage()
  doc.fontSize(16).fillColor('#0B0F14').text('Compliance Readiness Snapshot')
  doc.fontSize(9).fillColor('#888').text(
    'This section is a readiness aid based on automated technical scanning, not a certification. ' +
    'A real audit also covers policy, process, and organizational controls no scanner can assess.'
  )
  doc.moveDown(0.8)

  const compliance = buildComplianceReport(vulns)
  const FRAMEWORK_LABEL = { soc2: 'SOC 2', iso27001: 'ISO 27001', gdpr: 'GDPR' }
  for (const [key, label] of Object.entries(FRAMEWORK_LABEL)) {
    const fw = compliance[key]
    doc.fontSize(13).fillColor('#0B0F14').text(label)
    doc.fontSize(10).fillColor('#333')
    if (fw.controlsWithGaps.length === 0) {
      doc.text('No open findings currently map to a control gap in this framework.')
    } else {
      for (const c of fw.controlsWithGaps) {
        doc.text(`• ${c.control} — ${c.findings.length} open finding(s)`)
      }
    }
    doc.fontSize(9).fillColor('#888').text(`Not covered by automated scanning: ${fw.notCovered.join('; ')}`)
    doc.moveDown(0.6)
  }

  doc.end()
})

export default router
