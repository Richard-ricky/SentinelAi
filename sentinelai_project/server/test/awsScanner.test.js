// Unit tests for the S3 public-bucket detection logic, using a fake S3
// client that implements just .send() and returns canned responses based
// on which command was sent. This lets us verify the branching logic
// (Block Public Access short-circuits everything; ACL grants; bucket
// policy status) without any real AWS network access — which isn't
// available in this sandbox anyway. Live connectivity against a real
// AWS account is NOT covered by these tests and must be verified by
// whoever deploys this with real credentials.

import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import {
  ListBucketsCommand,
  GetPublicAccessBlockCommand,
  GetBucketAclCommand,
  GetBucketPolicyStatusCommand,
} from '@aws-sdk/client-s3'
import { scanS3Buckets } from '../src/lib/awsScanner.js'

function fakeClient(responses) {
  return {
    send: async (command) => {
      if (command instanceof ListBucketsCommand) return responses.listBuckets
      if (command instanceof GetPublicAccessBlockCommand) {
        const r = responses.publicAccessBlock?.[command.input.Bucket]
        if (r === 'not-configured') {
          const err = new Error('not configured')
          err.name = 'NoSuchPublicAccessBlockConfiguration'
          throw err
        }
        return r
      }
      if (command instanceof GetBucketAclCommand) return responses.acl?.[command.input.Bucket] ?? { Grants: [] }
      if (command instanceof GetBucketPolicyStatusCommand) {
        if (!responses.policyStatus?.[command.input.Bucket]) {
          throw new Error('no policy')
        }
        return responses.policyStatus[command.input.Bucket]
      }
      throw new Error(`Unhandled command in fake client: ${command.constructor.name}`)
    },
  }
}

describe('AWS S3 exposure scanner', () => {
  test('a bucket with full Block Public Access enabled is never flagged, even with a public ACL', async () => {
    const client = fakeClient({
      listBuckets: { Buckets: [{ Name: 'safe-bucket' }] },
      publicAccessBlock: {
        'safe-bucket': {
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true,
          },
        },
      },
      acl: {
        'safe-bucket': { Grants: [{ Grantee: { URI: 'http://acs.amazonaws.com/groups/global/AllUsers' }, Permission: 'READ' }] },
      },
    })
    const findings = await scanS3Buckets(client)
    assert.equal(findings.length, 0)
  })

  test('a public-read ACL with no Block Public Access is flagged High', async () => {
    const client = fakeClient({
      listBuckets: { Buckets: [{ Name: 'leaky-bucket' }] },
      publicAccessBlock: { 'leaky-bucket': 'not-configured' },
      acl: {
        'leaky-bucket': { Grants: [{ Grantee: { URI: 'http://acs.amazonaws.com/groups/global/AllUsers' }, Permission: 'READ' }] },
      },
    })
    const findings = await scanS3Buckets(client)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].severity, 'High')
    assert.match(findings[0].name, /publicly readable/)
  })

  test('a public-write ACL is flagged Critical, not just High', async () => {
    const client = fakeClient({
      listBuckets: { Buckets: [{ Name: 'writable-bucket' }] },
      publicAccessBlock: { 'writable-bucket': 'not-configured' },
      acl: {
        'writable-bucket': { Grants: [{ Grantee: { URI: 'http://acs.amazonaws.com/groups/global/AllUsers' }, Permission: 'WRITE' }] },
      },
    })
    const findings = await scanS3Buckets(client)
    assert.equal(findings.length, 1)
    assert.equal(findings[0].severity, 'Critical')
    assert.match(findings[0].name, /publicly writable/)
  })

  test('a public bucket policy is detected even with a private ACL', async () => {
    const client = fakeClient({
      listBuckets: { Buckets: [{ Name: 'policy-public' }] },
      publicAccessBlock: { 'policy-public': 'not-configured' },
      acl: { 'policy-public': { Grants: [] } },
      policyStatus: { 'policy-public': { PolicyStatus: { IsPublic: true } } },
    })
    const findings = await scanS3Buckets(client)
    assert.equal(findings.length, 1)
    assert.match(findings[0].description, /bucket policy/)
  })

  test('a private bucket with no public access anywhere produces no findings', async () => {
    const client = fakeClient({
      listBuckets: { Buckets: [{ Name: 'private-bucket' }] },
      publicAccessBlock: { 'private-bucket': 'not-configured' },
      acl: { 'private-bucket': { Grants: [{ Grantee: { ID: 'owner-id' }, Permission: 'FULL_CONTROL' }] } },
    })
    const findings = await scanS3Buckets(client)
    assert.equal(findings.length, 0)
  })

  test('multiple buckets are all assessed independently', async () => {
    const client = fakeClient({
      listBuckets: { Buckets: [{ Name: 'safe' }, { Name: 'leaky' }] },
      publicAccessBlock: {
        safe: { PublicAccessBlockConfiguration: { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true } },
        leaky: 'not-configured',
      },
      acl: {
        safe: { Grants: [] },
        leaky: { Grants: [{ Grantee: { URI: 'http://acs.amazonaws.com/groups/global/AllUsers' }, Permission: 'READ' }] },
      },
    })
    const findings = await scanS3Buckets(client)
    assert.equal(findings.length, 1)
    assert.match(findings[0].name, /"leaky"/)
  })
})