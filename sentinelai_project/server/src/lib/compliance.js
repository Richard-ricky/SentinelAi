// Compliance readiness mapping.
//
// IMPORTANT — this is explicitly a *readiness aid*, not a certification.
// It maps the categories of findings SentinelAI already detects to the
// control families a real auditor would ask about, so a team can walk
// into a SOC 2/ISO 27001 audit already knowing where their gaps are. It
// does not claim compliance, does not replace an auditor's judgment, and
// does not cover every control in any framework — only the slice that
// automated technical scanning can actually speak to (a huge portion of
// real compliance work is process/policy, which no scanner can assess).

const CATEGORY_CONTROL_MAP = {
  'Transport Security': {
    soc2: ['CC6.1 — Logical access & transmission security', 'CC6.7 — Data transmission controls'],
    iso27001: ['A.8.24 — Use of cryptography'],
    gdpr: ['Art. 32 — Security of processing (encryption in transit)'],
  },
  'Web Application Security': {
    soc2: ['CC6.6 — Protection against external threats'],
    iso27001: ['A.8.26 — Application security requirements'],
    gdpr: ['Art. 32 — Security of processing'],
  },
  'Secret Exposure': {
    soc2: ['CC6.1 — Logical access controls', 'CC6.3 — Credential management'],
    iso27001: ['A.8.24 — Use of cryptography', 'A.5.17 — Authentication information'],
    gdpr: ['Art. 32 — Security of processing', 'Art. 33 — Breach notification readiness'],
  },
  'Source Exposure': {
    soc2: ['CC6.1 — Logical access controls'],
    iso27001: ['A.8.4 — Access to source code'],
    gdpr: ['Art. 32 — Security of processing'],
  },
  'Information Disclosure': {
    soc2: ['CC6.1 — Logical access controls'],
    iso27001: ['A.5.10 — Acceptable use of information'],
    gdpr: ['Art. 5(1)(f) — Integrity and confidentiality'],
  },
  'Software Vulnerability': {
    soc2: ['CC7.1 — Vulnerability management'],
    iso27001: ['A.8.8 — Management of technical vulnerabilities'],
    gdpr: ['Art. 32 — Security of processing'],
  },
  Availability: {
    soc2: ['A1.2 — Availability monitoring'],
    iso27001: ['A.8.14 — Redundancy of information processing facilities'],
    gdpr: ['Art. 32(1)(b) — Ability to ensure ongoing availability'],
  },
}

// Every control family with at least one automated check, so the report
// can also show what SentinelAI does NOT cover — necessary honesty, since
// a huge portion of real compliance is policy/process work no scanner
// can assess (e.g. vendor risk management, employee training records).
const FRAMEWORK_NOT_COVERED = {
  soc2: ['Change management approval workflows', 'Vendor risk assessments', 'Employee security training records', 'Physical security controls'],
  iso27001: ['Risk assessment methodology (Clause 6)', 'Statement of Applicability', 'Business continuity planning (A.5.29-5.30)'],
  gdpr: ['Lawful basis documentation', 'Data subject rights process (Art. 15-22)', 'DPIA completion for high-risk processing'],
}

export function buildComplianceReport(vulnerabilities) {
  const openFindings = vulnerabilities.filter((v) => v.status !== 'Patched')
  const frameworks = { soc2: new Map(), iso27001: new Map(), gdpr: new Map() }

  for (const v of openFindings) {
    const mapping = CATEGORY_CONTROL_MAP[v.category]
    if (!mapping) continue
    for (const framework of Object.keys(frameworks)) {
      for (const control of mapping[framework] || []) {
        const entry = frameworks[framework].get(control) || { control, findings: [] }
        entry.findings.push({ id: v.id, name: v.name, severity: v.severity, asset_id: v.asset_id })
        frameworks[framework].set(control, entry)
      }
    }
  }

  const result = {}
  for (const framework of Object.keys(frameworks)) {
    const controlsWithGaps = [...frameworks[framework].values()].sort(
      (a, b) => b.findings.length - a.findings.length
    )
    result[framework] = {
      controlsWithGaps,
      gapCount: controlsWithGaps.length,
      findingCount: controlsWithGaps.reduce((sum, c) => sum + c.findings.length, 0),
      notCovered: FRAMEWORK_NOT_COVERED[framework],
    }
  }
  return result
}
