// Port of gateway-workers/test/quota.test.ts. The pure maths (allowances, window start, assessment,
// GraphQL parsing) is tested natively in core/src/quota.rs; here the `scheduled` handler runs inside
// workerd against a stub GraphQL endpoint (the test-hooks build lets QUOTA_GRAPHQL_URL redirect the query)
// and the log lines are read from wrangler's output.
import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import { fixture } from './lib/fixture.mjs'
import { freePort, sleep } from './lib/worker.mjs'

const stubs = []
after(async () => { for (const s of stubs) await s() })

/** A GraphQL stub that records requests and answers with `respond`. */
async function graphql(respond) {
  const seen = []
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const rec = { auth: req.headers.authorization, method: req.method, body: JSON.parse(Buffer.concat(chunks).toString() || 'null') }
      seen.push(rec)
      respond(rec, res)
    })
  })
  const port = await freePort()
  await new Promise((r) => server.listen(port, '127.0.0.1', r))
  stubs.push(() => new Promise((r) => server.close(r)))
  return { url: `http://127.0.0.1:${port}/graphql`, seen }
}
const gql = (w, doReq, activeTimeUs) => (_rec, res) => {
  res.setHeader('content-type', 'application/json')
  res.end(JSON.stringify({ data: { viewer: { accounts: [{
    workersInvocationsAdaptive: [{ sum: w }],
    durableObjectsInvocationsAdaptiveGroups: [{ sum: { requests: doReq } }],
    durableObjectsPeriodicGroups: [{ sum: { activeTime: activeTimeUs } }],
  }] } } }))
}

async function runGuard(vars, respond) {
  const g = await graphql(respond ?? gql({ requests: 1000, cpuTimeUs: 0 }, 0, 0))
  const f = await fixture({ name: 'quota', build: 'hooks', scheduled: true, vars: { QUOTA_GRAPHQL_URL: g.url, ...vars } })
  try {
    const r = await fetch(`${f.base}/cdn-cgi/handler/scheduled`)
    assert.equal(r.status, 200)
    await sleep(800)
    return { seen: g.seen, logs: f.w.logs() }
  } finally { await f.close() }
}
const todayUtc = () => new Date().toISOString().slice(0, 10)
const monthStart = () => `${new Date().toISOString().slice(0, 7)}-01T00:00:00.000Z`

describe('the quota guard (scheduled handler)', () => {
  it('Free (default): queries since today 00:00 UTC, converts DO active time to GB-s, warns near a limit', async () => {
    const { seen, logs } = await runGuard(
      { QUOTA_GUARD_ENABLED: 'true', CF_ANALYTICS_TOKEN: 'tok', CF_ACCOUNT_ID: 'acct' },
      gql({ requests: 1000, cpuTimeUs: 0 }, 96_000, 1_000_000_000),
    )
    assert.equal(seen.length, 1)
    assert.equal(seen[0].method, 'POST')
    assert.equal(seen[0].auth, 'Bearer tok')
    assert.equal(seen[0].body.variables.accountTag, 'acct')
    assert.equal(seen[0].body.variables.since, `${todayUtc()}T00:00:00.000Z`)
    assert.equal(seen[0].body.variables.sinceDate, todayUtc())
    assert.match(logs, /quota-guard: usage at 96% of a Workers Free daily limit/)
    assert.match(logs, /doRequests 96%/)
    assert.doesNotMatch(logs, /workerCpuMs/) // not an account-wide meter on Free
  })

  it('Paid: queries since the 1st, meters CPU, warns and says overage is billed', async () => {
    const { seen, logs } = await runGuard(
      { QUOTA_GUARD_ENABLED: 'true', WORKERS_PLAN: 'paid', CF_ANALYTICS_TOKEN: 'tok', CF_ACCOUNT_ID: 'acct' },
      gql({ requests: 9_000_000, cpuTimeUs: 29_000_000_000 }, 999_000, 0),
    )
    assert.equal(seen[0].body.variables.since, monthStart())
    assert.match(logs, /quota-guard: usage at 100% of a Workers Paid monthly included amount \(overage is billed beyond it\)/)
    assert.match(logs, /workerCpuMs 97%/)
  })

  it('stays quiet below 80% of every allowance', async () => {
    const { seen, logs } = await runGuard(
      { QUOTA_GUARD_ENABLED: 'true', CF_ANALYTICS_TOKEN: 'tok', CF_ACCOUNT_ID: 'acct' },
      gql({ requests: 10, cpuTimeUs: 0 }, 10, 1000),
    )
    assert.equal(seen.length, 1)
    assert.doesNotMatch(logs, /quota-guard/)
  })

  it('a GraphQL error is a failed check, never zero usage', async () => {
    const { seen, logs } = await runGuard(
      { QUOTA_GUARD_ENABLED: 'true', CF_ANALYTICS_TOKEN: 'tok', CF_ACCOUNT_ID: 'acct' },
      (_r, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ data: null, errors: [{ message: 'unknown field cpuTimeUs' }] })) },
    )
    assert.equal(seen.length, 1)
    assert.match(logs, /quota-guard: usage query failed: graphql error: unknown field cpuTimeUs/)
  })

  it('never rejects on an HTTP failure', async () => {
    const { logs } = await runGuard(
      { QUOTA_GUARD_ENABLED: 'true', CF_ANALYTICS_TOKEN: 'tok', CF_ACCOUNT_ID: 'acct' },
      (_r, res) => { res.statusCode = 500; res.end('no') },
    )
    assert.match(logs, /quota-guard: usage query failed: graphql http 500/)
  })

  it('skips without credentials, on an invalid WORKERS_PLAN, and when disabled, without querying', async () => {
    const noCreds = await runGuard({ QUOTA_GUARD_ENABLED: 'true' })
    assert.equal(noCreds.seen.length, 0)
    assert.match(noCreds.logs, /CF_ANALYTICS_TOKEN \/ CF_ACCOUNT_ID not set; skipping/)
    // An invalid plan is also a startup error for the request path, so the scheduled run is the only
    // place left that reports it; it must not query.
    const badPlan = await runGuard({ QUOTA_GUARD_ENABLED: 'true', WORKERS_PLAN: 'pro', CF_ANALYTICS_TOKEN: 't', CF_ACCOUNT_ID: 'a' })
    assert.equal(badPlan.seen.length, 0)
    assert.match(badPlan.logs, /WORKERS_PLAN must be one of free, paid; skipping/)
    const off = await runGuard({ QUOTA_GUARD_ENABLED: 'false', CF_ANALYTICS_TOKEN: 't', CF_ACCOUNT_ID: 'a' })
    assert.equal(off.seen.length, 0)
  })
})
