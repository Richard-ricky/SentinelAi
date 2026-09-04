import type { Severity } from '../components/shared/SeverityBadge'

export interface Vulnerability {
  id: string
  asset: string
  assetType: 'server' | 'endpoint' | 'website' | 'database' | 'cloud'
  name: string
  severity: Severity
  category: string
  discovered: string
  status: 'Open' | 'In Review' | 'Patched'
  cve?: string
  description: string
  impact: string
  fix: string
  script: string
}

export const vulnerabilities: Vulnerability[] = [
  {
    id: 'vuln-001',
    asset: 'marketing-web-01',
    assetType: 'website',
    name: 'Outdated web framework with known exploit',
    severity: 'Critical',
    category: 'Software Vulnerability',
    discovered: '2026-07-12',
    status: 'Open',
    cve: 'CVE-2024-38473',
    description: 'Your marketing website is running an old version of its web framework that has a publicly known security flaw. Attackers can use this flaw to take complete control of the server without needing a password.',
    impact: 'An attacker who finds this could read, modify, or delete everything on your marketing server — including contact form submissions and customer data.',
    fix: 'Update the web framework to the latest stable version. This can be done with a single command and takes less than 5 minutes. No downtime required.',
    script: `#!/bin/bash
# SentinelAI Auto-Fix — marketing-web-01
# CVE-2024-38473: Framework update

set -euo pipefail

echo "[SentinelAI] Backing up current config..."
cp -r /var/www/app /var/www/app.backup.$(date +%Y%m%d)

echo "[SentinelAI] Updating framework..."
cd /var/www/app && npm update express@4.19.2 --save

echo "[SentinelAI] Restarting service..."
systemctl restart sentinel-app

echo "[SentinelAI] ✓ Fix applied successfully"`,
  },
  {
    id: 'vuln-002',
    asset: 'employee-laptop-msmith',
    assetType: 'endpoint',
    name: 'Unencrypted sensitive files on employee device',
    severity: 'High',
    category: 'Data Exposure',
    discovered: '2026-07-11',
    status: 'In Review',
    description: "M. Smith's laptop contains financial spreadsheets and customer contact lists stored without encryption. If this device is lost or stolen, anyone who finds it can access that data.",
    impact: 'Potential breach of customer PII and financial records. Depending on your region, this could trigger GDPR or HIPAA notification requirements.',
    fix: 'Enable full-disk encryption on the device (BitLocker on Windows, FileVault on Mac). This protects all files automatically and is invisible to the user once set up.',
    script: `# SentinelAI Auto-Fix — employee-laptop-msmith
# Enable FileVault (macOS)

sudo fdesetup enable -user msmith -outputplist /var/sentinel/filevault-recovery.plist
echo "[SentinelAI] ✓ Encryption enabled. Recovery key stored securely."`,
  },
  {
    id: 'vuln-003',
    asset: 'customer-db-prod',
    assetType: 'database',
    name: 'Database accessible from public internet',
    severity: 'Critical',
    category: 'Network Exposure',
    discovered: '2026-07-13',
    status: 'Open',
    cve: undefined,
    description: 'Your customer database can be reached directly from the public internet. It should only be accessible from inside your private network. This is like leaving your filing cabinet on the sidewalk.',
    impact: 'Anyone on the internet could attempt to log in to your database. A successful attack could expose all customer records.',
    fix: 'Update the firewall rules to block all external access to the database port. Only your internal servers should be allowed to connect.',
    script: `#!/bin/bash
# SentinelAI Auto-Fix — customer-db-prod
# Block public database access

ufw deny from any to any port 5432
ufw allow from 10.0.0.0/8 to any port 5432
ufw reload

echo "[SentinelAI] ✓ Database port 5432 restricted to internal network only"`,
  },
  {
    id: 'vuln-004',
    asset: 'app-server-02',
    assetType: 'server',
    name: 'Default admin credentials still active',
    severity: 'High',
    category: 'Authentication',
    discovered: '2026-07-10',
    status: 'Open',
    description: 'Your application server still has the factory-default username and password enabled. This is one of the first things attackers try — it takes seconds to exploit.',
    impact: 'An attacker could gain full administrative access to this server without any technical skill.',
    fix: 'Disable the default admin account and create a new account with a strong unique password and multi-factor authentication.',
    script: `#!/bin/bash
# SentinelAI Auto-Fix — app-server-02
# Disable default credentials

passwd -l admin
useradd -m -G sudo sentinel-admin
echo "sentinel-admin ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/sentinel

echo "[SentinelAI] ✓ Default admin disabled. New account created."`,
  },
  {
    id: 'vuln-005',
    asset: 'aws-s3-backups',
    assetType: 'cloud',
    name: 'Cloud backup bucket set to public read',
    severity: 'Critical',
    category: 'Cloud Misconfiguration',
    discovered: '2026-07-13',
    status: 'Open',
    description: 'Your AWS backup storage bucket is configured so anyone on the internet can download its contents. This includes database backups that may contain customer information.',
    impact: 'All backup files — potentially years of customer data — are freely downloadable by anyone who knows the URL.',
    fix: 'Set the S3 bucket to private. Enable Block Public Access settings and review the bucket policy.',
    script: `#!/bin/bash
# SentinelAI Auto-Fix — aws-s3-backups
# Restrict public S3 bucket access

BUCKET="acme-prod-backups"
aws s3api put-public-access-block --bucket $BUCKET \\
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

echo "[SentinelAI] ✓ S3 bucket $BUCKET is now private"`,
  },
  {
    id: 'vuln-006',
    asset: 'hr-portal',
    assetType: 'website',
    name: 'Login page vulnerable to brute-force attacks',
    severity: 'Medium',
    category: 'Authentication',
    discovered: '2026-07-09',
    status: 'Patched',
    description: 'The HR employee portal has no limit on how many times someone can try to log in. An attacker could try thousands of passwords automatically until one works.',
    impact: 'Employee accounts could be compromised, exposing payroll data and personal information.',
    fix: 'Add rate limiting: after 5 failed login attempts, temporarily lock the account and send an alert email.',
    script: `# Already applied via SentinelAI on 2026-07-10\n# Rate limiting: nginx config updated`,
  },
  {
    id: 'vuln-007',
    asset: 'dev-server-01',
    assetType: 'server',
    name: 'SSL certificate expires in 6 days',
    severity: 'Medium',
    category: 'Certificate Management',
    discovered: '2026-07-08',
    status: 'In Review',
    description: 'The security certificate for your development server expires in 6 days. After it expires, browsers will show a "Not Secure" warning and refuse to connect.',
    impact: 'Development workflow disruption. If left unrenewed, could affect your team\'s ability to test features.',
    fix: 'Renew the SSL certificate. We recommend enabling auto-renewal to prevent this in the future.',
    script: `#!/bin/bash
certbot renew --cert-name dev-server-01.acmecorp.io
echo "[SentinelAI] ✓ Certificate renewed"`,
  },
  {
    id: 'vuln-008',
    asset: 'network-firewall',
    assetType: 'server',
    name: 'Firewall firmware 14 months out of date',
    severity: 'Low',
    category: 'Patch Management',
    discovered: '2026-07-07',
    status: 'Open',
    description: 'Your network firewall is running firmware from 14 months ago. Newer versions include security patches and improved threat detection.',
    impact: 'Low immediate risk, but outdated firmware may miss newer attack patterns.',
    fix: 'Schedule a maintenance window to update the firewall firmware. Takes approximately 15 minutes with brief network interruption.',
    script: `# Contact your network admin to schedule firmware update\n# Model: Fortinet FortiGate 60E\n# Current: v7.2.1 → Target: v7.4.3`,
  },
]

export const activityFeed = [
  { id: 1, type: 'critical', message: 'Critical vulnerability found on aws-s3-backups', time: '4 min ago', icon: '⊗' },
  { id: 2, type: 'critical', message: 'Database customer-db-prod exposed to public internet', time: '12 min ago', icon: '⊗' },
  { id: 3, type: 'info', message: 'Scheduled scan completed — 47 assets checked', time: '18 min ago', icon: '●' },
  { id: 4, type: 'success', message: 'Patch approved & applied on hr-portal', time: '1 hr ago', icon: '✓' },
  { id: 5, type: 'info', message: 'New asset discovered: dev-server-03.acmecorp.io', time: '2 hr ago', icon: '◆' },
]

export const scoreHistory = [
  { date: 'Jan', score: 52 },
  { date: 'Feb', score: 48 },
  { date: 'Mar', score: 55 },
  { date: 'Apr', score: 61 },
  { date: 'May', score: 58 },
  { date: 'Jun', score: 67 },
  { date: 'Jul', score: 63 },
]
