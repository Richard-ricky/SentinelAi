# Figma Make Prompt — SentinelAI Web App

Copy everything below into Figma Make as your build prompt.

---

## Product Context

Build a production-quality web application called **SentinelAI** — a continuous cybersecurity monitoring platform for SMEs, schools, startups, government agencies, and mid-tier enterprises. It replaces one-time annual security scans with 24/7 automated monitoring, translates technical vulnerabilities into plain-language explanations, visually maps multi-step attack paths, and lets users approve AI-generated "fix-it scripts" through a human-in-the-loop workflow (the system never patches anything without explicit user approval).

The product should feel like a **security operations command center** that a non-technical business owner can still understand — trustworthy, calm, precise, and modern. Not playful, not cluttered. Think "control tower" rather than "consumer app."

## Design Direction

- **Visual tone:** dark-mode-first security dashboard (with a light mode toggle), high contrast, generous whitespace around data-dense areas so it doesn't feel overwhelming.
- **Color system:** deep navy/charcoal background (#0B0F14 to #131A22 range), with a single accent color for primary actions (electric blue or teal), and a strict semantic color scale for risk severity: Critical = red, High = orange, Medium = yellow/amber, Low = green/gray. These four colors must be used consistently everywhere (badges, graph nodes, charts, notifications).
- **Typography:** clean geometric sans-serif for headings (e.g., Inter, Manrope), monospace accents for technical values (IP addresses, CVE codes, ports) so they're visually distinct from plain-language copy.
- **Iconography:** line icons, consistent stroke width, security-themed (shield, lock, network node, radar).
- **Motion:** subtle — pulsing "live" indicators for real-time monitoring, smooth transitions when expanding a vulnerability into its explanation panel, animated line-draw when the attack path graph renders.
- Follow modern SaaS dashboard conventions (persistent left sidebar nav, top bar with search/notifications/account, card-based content grids), but avoid generic "template" look — add one distinctive signature element: the interactive attack path graph should feel like the product's visual centerpiece.

## Information Architecture / Screens to Design

1. **Login / Auth**
   - Secure login, role-based access (Admin, IT Manager, Viewer), workspace/organization selector for multi-tenant users, MFA step.

2. **Onboarding / Asset Discovery**
   - First-run flow: "Scanning your network..." animated state, then a results screen showing discovered assets (servers, endpoints, websites, cloud storage buckets) as a list and as a network map.

3. **Main Dashboard (Home)**
   - Real-time overall Security Score (large, prominent, 0–100 with trend arrow).
   - Summary cards: total assets monitored, open vulnerabilities by severity (Critical/High/Medium/Low counts), last scan timestamp, "monitoring live" status indicator.
   - Recent activity feed (new vulnerability found, patch approved, scan completed).
   - Quick-access card promoting the Attack Path Mapper ("2 critical attack paths detected — review now").

4. **Vulnerability Assessment Center**
   - Filterable, sortable table/list of all discovered vulnerabilities.
   - Columns: asset, vulnerability name, severity badge, category, date discovered, status (Open/In Review/Patched).
   - Filters by severity, asset type, status, date range.
   - Clicking a row opens a detail panel (see #6).

5. **Interactive Visual Attack Path Mapper**
   - Node-and-edge graph visualization: nodes = assets (computers, servers, databases, external websites), edges = potential attack routes.
   - Critical/high-risk paths rendered as bold red lines connecting the outer network to sensitive internal assets (e.g., customer database).
   - Nodes color-coded by risk exposure; clicking a node or edge highlights the relevant vulnerabilities and shows a side panel with the "chain" explanation (e.g., "Server A → Server B → Customer DB").
   - Zoom/pan controls, legend for severity colors, toggle to isolate a single attack path.

6. **Vulnerability Detail / AI Assistant Panel**
   - Plain-language explanation panel with three clear sections: **What it is**, **Why it matters**, **How to fix it**.
   - Below that, a code/script preview block (monospace, syntax-highlighted) labeled "Suggested Fix — Draft."
   - Prominent **"Approve & Apply Patch"** button plus a **"Reject / Modify"** option — visually reinforce that nothing executes without this explicit approval (e.g., a small lock icon + "Human approval required" microcopy).
   - Chat-style AI assistant interface for follow-up questions about the vulnerability.

7. **Reports & Analytics**
   - Historical security score trend chart (line chart over time).
   - Vulnerability breakdown by category (bar/donut chart).
   - "Generate Executive PDF Report" button with a preview modal.
   - Compliance-readiness placeholder section (SOC2, ISO 27001, HIPAA, GDPR checklists) for future expansion — can be shown as a locked/upcoming feature.

8. **Notifications Center**
   - List of real-time alerts (new critical vulnerability, patch approved, scan completed), each actionable (jump straight to the relevant detail panel).

9. **Settings / Workspace Management**
   - User roles & permissions management.
   - Connected assets & cloud integrations (AWS, Azure, GCP icons).
   - Multi-tenant workspace switcher (for MSP/enterprise use case) with clear data-isolation messaging.
   - Billing/plan page reflecting the Freemium model: Free, Premium Monitoring, Enterprise tiers, with a comparison table.

10. **Mobile Companion View**
    - Responsive/mobile layout emphasizing: security score, push notification detail, and a simplified one-tap "Approve & Apply Patch" action for on-the-go emergency review.

## Key Components to Build as Reusable

- Severity badge (Critical/High/Medium/Low) with consistent color tokens.
- Security score gauge/ring component.
- Attack path graph component (nodes, edges, tooltips).
- "AI explanation card" (What/Why/How structure).
- Code/script preview block with Approve/Reject actions.
- Data table with filter/sort controls.
- Notification toast and notification-center list item.
- Pricing/plan comparison table.

## Content & Copy Guidelines

- All AI-generated explanations should read at a plain-language, non-technical level — write sample placeholder copy demonstrating this (avoid jargon like "CVSS" or "XSS" without a one-line plain explanation alongside it).
- Use realistic sample data: fictional company assets, fictional but plausible vulnerabilities, fictional attack path scenarios (e.g., "Marketing Website → Employee Laptop → Customer Database").
- Reinforce trust and control language throughout: "Nothing executes without your approval," "Your data is isolated from other workspaces."

## Non-Functional / Production Notes

- Design for accessibility: sufficient color contrast even with severity colors, and don't rely on color alone (pair with icons/labels) since severity communication is safety-critical.
- Design both dark and light themes.
- Design responsive breakpoints: desktop dashboard, tablet, and mobile companion view.
- Keep the attack path graph performant-looking even with many nodes — show a state for "50+ assets" to demonstrate it scales.