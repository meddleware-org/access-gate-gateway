// Port of gateway-workers/test/redemption.test.ts (the single-use flow) and the store-outage cases of
// gateway-state.test.ts, through the real Worker: signed proof → consume check on the stub fullnode →
// lease in the Durable Object → streamed upstream → commit or release.
//
// Not reachable from outside, mapped elsewhere (README table): "a holder whose lease lapsed before
// commit is told 502" and "a stale holder cannot release or commit over a newer lease" need a lease
// that expires mid-request, which the config forbids (REDEMPTION_LEASE_TTL_SECS must exceed the whole
// request); they are pinned at the store (tests/state.test.mjs, expired-lease scenario) and in the core
// (gateway.rs: lost lease → 502).
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { fixture, nextIp } from './lib/fixture.mjs'
import { newWallet, proofToken, registerConsume } from './lib/proof.mjs'
import { rawRequest } from './lib/http.mjs'
import { sleep } from './lib/worker.mjs'

const vars = {
  // SINGLE_USE stays at wrangler.toml's "true".
  UPSTREAM_TIMEOUT_SECS: '1',
  BODY_READ_TIMEOUT_SECS: '1',
  RATE_LIMIT_PER_MIN: '0',
  GATED_PREAUTH_RATE_LIMIT_PER_MIN: '0',
  CHALLENGE_RATE_LIMIT_PER_MIN: '0',
}
let f
let h // test-hooks build with fault injection
const wallet = newWallet()

before(async () => {
  f = await fixture({
    name: 'redeem',
    vars,
    upstream: {
      respond: (req, res) => {
        res.setHeader('content-type', 'application/json')
        if (req.url.startsWith('/v1/slow')) return setTimeout(() => res.end('{"stored":true}'), 600)
        res.end('{"stored":true}')
      },
    },
  })
  h = await fixture({ name: 'redeem-faults', build: 'hooks', vars: { ...vars, TEST_FAIL_STATE: 'commit' } })
})
after(async () => { await f.close(); await h.close() })

/** One upload attempt for `digest` with a fresh challenge (re-signing is free; the consume is reused). */
async function upload(fx, digest, path = '/v1/blob-upload-relay') {
  const token = await proofToken({ base: fx.base, wallet, consumeDigest: digest })
  return await rawRequest(fx.base, { method: 'PUT', path, headers: { authorization: `Bearer ${token}`, 'CF-Connecting-IP': nextIp() }, body: Buffer.from('blob') })
}
const body = (r) => JSON.parse(r.body.toString())

describe('redeem and forward (owner-bound lease)', () => {
  it('leases, forwards, commits; a second attempt is redeemed', async () => {
    const digest = await registerConsume(f.rpc, wallet)
    f.up.reset()
    const first = await upload(f, digest)
    assert.equal(first.status, 200)
    assert.deepEqual(body(first), { stored: true })
    const again = await upload(f, digest)
    assert.equal(again.status, 409)
    assert.deepEqual(body(again), { error: 'this consume has already been redeemed for an upload', code: 'redeemed' })
    assert.equal(f.up.seen.length, 1) // the second attempt never reached the upstream
  })

  it('a concurrent duplicate gets 409 leased and does not forward', async () => {
    const digest = await registerConsume(f.rpc, wallet)
    f.up.reset()
    const slow = upload(f, digest, '/v1/slow')
    await sleep(250)
    const dup = await upload(f, digest, '/v1/slow')
    assert.equal(dup.status, 409)
    assert.deepEqual(body(dup), { error: 'an upload for this consume is already in progress', code: 'leased' })
    assert.equal((await slow).status, 200)
    assert.equal(f.up.seen.length, 1)
  })

  it('a failed upload releases the lease so the consume stays usable', async () => {
    const digest = await registerConsume(f.rpc, wallet)
    assert.equal((await upload(f, digest, '/v1/fail')).status, 500)
    assert.equal((await upload(f, digest)).status, 200) // retried with the same consume
    assert.equal((await upload(f, digest)).status, 409)
  })

  it('an upstream that stalls (504) or redirects (502) releases the lease too', async () => {
    const digest = await registerConsume(f.rpc, wallet)
    assert.equal((await upload(f, digest, '/v1/stall')).status, 504)
    assert.equal((await upload(f, digest, '/v1/redirect')).status, 502)
    assert.equal((await upload(f, digest)).status, 200)
  })

  it('an unknown consume digest is denied before any lease (and the upstream is not contacted)', async () => {
    f.up.reset()
    const { txDigest } = await import('./lib/stubs.mjs')
    const res = await upload(f, txDigest())
    assert.equal(res.status, 403)
    assert.deepEqual(body(res), { error: 'no matching single-use consume for this address' })
    assert.equal(f.up.seen.length, 0)
  })

  it('a consume made by someone else is denied', async () => {
    const digest = await registerConsume(f.rpc, newWallet())
    assert.equal((await upload(f, digest)).status, 403)
  })

  it('reports a failed commit as 502 (never success) and releases the lease', async () => {
    const digest = await registerConsume(h.rpc, wallet)
    h.up.reset()
    const res = await upload(h, digest)
    assert.equal(res.status, 502)
    assert.deepEqual(body(res), { error: 'redemption commit failed' })
    // Released: the same consume reaches the upstream again instead of being 409 leased.
    const retry = await upload(h, digest)
    assert.equal(retry.status, 502)
    assert.equal(h.up.seen.length, 2)
  })
})

describe('store outage (F30)', () => {
  it('answers a JSON 503 with CORS when the state store throws (challenge)', async () => {
    const o = await fixture({ name: 'outage', build: 'hooks', vars: { TEST_FAIL_STATE: 'all' } })
    try {
      const res = await o.call('GET', '/v1/challenge', { origin: 'https://allowed.example.com', 'CF-Connecting-IP': nextIp() })
      assert.equal(res.status, 503)
      assert.deepEqual(await res.json(), { error: 'gateway state unavailable' })
      assert.equal(res.headers.get('access-control-allow-origin'), 'https://allowed.example.com')
    } finally { await o.close() }
  })

  it('a store error while leasing is a 503, never a conflict, and the upstream is not contacted', async () => {
    const o = await fixture({ name: 'outage-lease', build: 'hooks', vars: { ...vars, TEST_FAIL_STATE: 'lease' } })
    try {
      const digest = await registerConsume(o.rpc, wallet)
      const res = await upload(o, digest)
      assert.equal(res.status, 503)
      assert.deepEqual(body(res), { error: 'gateway state unavailable' })
      assert.equal(o.up.seen.length, 0)
    } finally { await o.close() }
  })

  it('a rate store that cannot answer is a 503 on every path class (never an unmetered pass)', async () => {
    const o = await fixture({ name: 'outage-rate', build: 'hooks', vars: { TEST_FAIL_STATE: 'rate' } })
    try {
      for (const [m, p, hdr] of [['GET', '/v1/challenge', {}], ['GET', '/v1/tip-config', {}], ['POST', '/v1/blob-upload', { authorization: 'Bearer x' }]]) {
        const res = await o.call(m, p, { 'CF-Connecting-IP': nextIp(), ...hdr })
        assert.equal(res.status, 503, p)
      }
      assert.equal(o.up.seen.length, 0)
    } finally { await o.close() }
  })

  it('a nonce store that fails on take is a 503 (not "nonce invalid")', async () => {
    const o = await fixture({ name: 'outage-take', build: 'hooks', vars: { ...vars, TEST_FAIL_STATE: 'take' } })
    try {
      const digest = await registerConsume(o.rpc, wallet)
      const res = await upload(o, digest)
      assert.equal(res.status, 503)
    } finally { await o.close() }
  })
})
