// AWS S3 public-bucket exposure scanner.
//
// Uses the official @aws-sdk/client-s3 to check every bucket in the
// connected account for public accessibility — the single most common,
// highest-impact AWS misconfiguration (this is what caused most of the
// well-known "S3 leak" breaches). Entirely read-only: ListBuckets,
// GetPublicAccessBlock, GetBucketAcl, GetBucketPolicyStatus. Nothing here
// modifies AWS resources or reads object contents/data — only bucket-level
// access configuration.
//
// IMPORTANT — this file accepts an S3Client as a parameter rather than
// constructing one internally, specifically so the detection logic can be
// unit-tested against a fake/mocked client without needing real AWS
// network access (see test/awsScanner.test.js). Live connectivity against
// a real AWS account still needs to be verified by whoever deploys this
// with real credentials — it cannot be exercised from a sandboxed dev
// environment with restricted network egress.
//
// IMPORTANT — inconclusive vs. safe: a bucket check that errors out
// (missing permission, cross-region redirect, throttling) is NEVER treated
// as "not public." Silently defaulting an unverifiable bucket to "safe" is
// the one failure mode a security scanner cannot afford — it would give a
// false sense of safety instead of an honest "we don't know." Every such
// case is instead surfaced as its own inconclusive finding so a human
// knows to check it manually or grant the missing permission.

import {
  S3Client,
  ListBucketsCommand,
  GetPublicAccessBlockCommand,
  GetBucketAclCommand,
  GetBucketPolicyStatusCommand,
  GetBucketLocationCommand,
} from '@aws-sdk/client-s3'

export function createS3Client({ accessKeyId, secretAccessKey, region }) {
  return new S3Client({
    region: region || 'us-east-1',
    credentials: { accessKeyId, secretAccessKey },
  })
}

// Throws if the credentials don't work at all — used to fail fast when the
// user connects an account, rather than silently storing bad credentials.
export async function verifyCredentials(client) {
  await client.send(new ListBucketsCommand({}))
}

const ALL_USERS_URI = 'http://acs.amazonaws.com/groups/global/AllUsers'
const AUTH_USERS_URI = 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'

// Error names/codes that mean "there is genuinely nothing here" — safe to
// treat as a normal not-public result. Anything else that fails is treated
// as inconclusive, never as safe.
const BENIGN_NOT_FOUND = new Set([
  'NoSuchPublicAccessBlockConfiguration',
  'NoSuchBucketPolicy',
])

function isBenignNotFound(err) {
  return BENIGN_NOT_FOUND.has(err.name) || BENIGN_NOT_FOUND.has(err.Code)
}

function aclGrantsPublicAccess(acl) {
  if (!acl?.Grants) return { readable: false, writable: false }
  let readable = false
  let writable = false
  for (const grant of acl.Grants) {
    const uri = grant.Grantee?.URI
    if (uri === ALL_USERS_URI || uri === AUTH_USERS_URI) {
      if (['READ', 'READ_ACP', 'FULL_CONTROL'].includes(grant.Permission)) readable = true
      if (['WRITE', 'WRITE_ACP', 'FULL_CONTROL'].includes(grant.Permission)) writable = true
    }
  }
  return { readable, writable }
}

// Builds a client pointed at the bucket's actual region. Buckets returned
// by ListBuckets can live in any region regardless of which region the
// client was constructed with — calling ACL/policy APIs against the wrong
// region commonly throws a redirect/auth error that, before this fix, was
// swallowed and silently treated as "not public." Falls back to the
// original client if location lookup itself fails (still surfaced as
// inconclusive by the caller if the follow-up calls then fail too).
async function getRegionalClient(baseClient, bucketName, credentials) {
  try {
    const loc = await baseClient.send(new GetBucketLocationCommand({ Bucket: bucketName }))
    // us-east-1 is returned as null/empty by this API for historical reasons.
    const region = loc.LocationConstraint || 'us-east-1'
    if (!credentials) return baseClient
    return new S3Client({ region, credentials })
  } catch {
    return baseClient
  }
}

async function checkBucket(baseClient, bucketName, credentials) {
  const client = await getRegionalClient(baseClient, bucketName, credentials)
  const inconclusiveReasons = []

  // Public Access Block is AWS's account/bucket-level "kill switch" for
  // public access — if it fully blocks public ACLs and policies, the
  // bucket is safe regardless of what its ACL/policy say underneath.
  let publicAccessBlocked = false
  try {
    const pab = await client.send(new GetPublicAccessBlockCommand({ Bucket: bucketName }))
    const cfg = pab.PublicAccessBlockConfiguration
    publicAccessBlocked = Boolean(
      cfg?.BlockPublicAcls && cfg?.IgnorePublicAcls && cfg?.BlockPublicPolicy && cfg?.RestrictPublicBuckets
    )
  } catch (err) {
    if (!isBenignNotFound(err)) {
      inconclusiveReasons.push(`Public Access Block status (${err.name || err.Code || err.message})`)
    }
    // NoSuchPublicAccessBlockConfiguration means none is set — treat as not blocked, continue checking.
  }

  if (publicAccessBlocked) {
    return { bucketName, exposed: false, inconclusiveReasons: [] }
  }

  // Check the bucket policy status (does a policy make it public?)
  let policyPublic = false
  try {
    const policyStatus = await client.send(new GetBucketPolicyStatusCommand({ Bucket: bucketName }))
    policyPublic = Boolean(policyStatus.PolicyStatus?.IsPublic)
  } catch (err) {
    if (!isBenignNotFound(err)) {
      inconclusiveReasons.push(`bucket policy status (${err.name || err.Code || err.message})`)
    }
    // No bucket policy at all is the common case — not an error worth surfacing.
  }

  // Check the ACL directly.
  let aclPublic = { readable: false, writable: false }
  try {
    const acl = await client.send(new GetBucketAclCommand({ Bucket: bucketName }))
    aclPublic = aclGrantsPublicAccess(acl)
  } catch (err) {
    // A missing GetBucketAcl permission on this specific bucket means we
    // genuinely cannot verify it — this must NOT silently resolve to "safe."
    inconclusiveReasons.push(`bucket ACL (${err.name || err.Code || err.message})`)
  }

  if (policyPublic || aclPublic.readable || aclPublic.writable) {
    return {
      bucketName,
      exposed: true,
      writable: aclPublic.writable,
      reason: policyPublic ? 'bucket policy' : aclPublic.writable ? 'ACL grants public write' : 'ACL grants public read',
      inconclusiveReasons,
    }
  }

  return { bucketName, exposed: false, inconclusiveReasons }
}

export async function scanS3Buckets(client, credentials) {
  const { Buckets = [] } = await client.send(new ListBucketsCommand({}))
  const findings = []

  for (const bucket of Buckets) {
    let result
    try {
      result = await checkBucket(client, bucket.Name, credentials)
    } catch (err) {
      // Total failure (e.g. couldn't even reach the bucket) shouldn't abort
      // the whole scan — record it as an inconclusive finding instead of
      // silently skipping.
      findings.push({
        name: `Could not fully assess bucket "${bucket.Name}"`,
        severity: 'Low',
        category: 'Cloud Configuration',
        description: `SentinelAI's AWS credentials don't have permission to check this bucket's public access settings (${err.name || err.message}).`,
        impact: 'This bucket could not be verified as safe — its access configuration is unknown to SentinelAI.',
        fix: 'Grant the connected IAM user s3:GetBucketAcl, s3:GetBucketPolicyStatus, s3:GetBucketLocation, and s3:GetPublicAccessBlock on this bucket to allow assessment.',
      })
      continue
    }

    if (result.exposed) {
      findings.push({
        name: `S3 bucket "${result.bucketName}" is publicly ${result.writable ? 'writable' : 'readable'}`,
        severity: result.writable ? 'Critical' : 'High',
        category: 'Cloud Configuration',
        description: `The bucket "${result.bucketName}" grants public access via ${result.reason}, with no S3 Block Public Access settings preventing it.`,
        impact: result.writable
          ? 'Anyone on the internet can upload, overwrite, or delete objects in this bucket.'
          : 'Anyone on the internet can list and download every object in this bucket.',
        fix: `Enable S3 Block Public Access on "${result.bucketName}" (all four settings), and review/remove the bucket policy or ACL grants causing this exposure.`,
      })
    }

    // Partial-failure case: the bucket wasn't found to be exposed, but part
    // of the check couldn't be completed — report it as its own inconclusive
    // finding rather than folding it silently into "safe."
    if (result.inconclusiveReasons && result.inconclusiveReasons.length > 0) {
      findings.push({
        name: `Could not fully verify bucket "${result.bucketName}"`,
        severity: 'Low',
        category: 'Cloud Configuration',
        description: `SentinelAI could not check the following on bucket "${result.bucketName}": ${result.inconclusiveReasons.join('; ')}. Other checks on this bucket did not find public access, but the picture is incomplete.`,
        impact: 'Part of this bucket\'s access configuration is unknown to SentinelAI — it may or may not be exposed in a way this scan could not detect.',
        fix: 'Grant the connected IAM user the missing S3 permission(s) listed above (commonly s3:GetBucketAcl or s3:GetBucketPolicyStatus), then re-scan to get a complete result.',
      })
    }
  }

  return findings
}