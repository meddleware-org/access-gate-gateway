// Port of the Worker-visible cases of gateway-workers/test/chain.test.ts. The chain logic is the
// core's (parsers and decisions: core/src/chain.rs unit tests, core/tests/transport_stub.rs); here the
// fetch Transport and the policy around it run for real in workerd against the stub fullnode.
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { fixture, nextIp } from './lib/fixture.mjs'
import { newWallet, proofToken, registerConsume } from './lib/proof.mjs'
import { rawRequest } from './lib/http.mjs'
import { sleep } from './lib/worker.mjs'

const base = { RATE_LIMIT_PER_MIN: '0', GATED_PREAUTH_RATE_LIMIT_PER_MIN: '0', CHALLENGE_RATE_LIMIT_PER_MIN: '0', RPC_TIMEOUT_SECS: '1' }
const wallet = newWallet()

async function attempt(f, digest, w = wallet, path = '/v1/blob-upload-relay') {
  const token = await proofToken({ base: f.base, wallet: w, consumeDigest: digest })
  return await rawRequest(f.base, { method: 'PUT', path, headers: { authorization: `Bearer ${token}`, 'CF-Connecting-IP': nextIp() }, body: Buffer.from('x') })
}
const own = async (f, w = wallet) => {
  const token = await proofToken({ base: f.base, wallet: w })
  return await rawRequest(f.base, { method: 'GET', path: '/v1/x', headers: { authorization: `Bearer ${token}`, 'CF-Connecting-IP': nextIp() } })
}

describe('single-use consume check (digest-first)', () => {
  let f
  before(async () => { f = await fixture({ name: 'chain', vars: base }) })
  after(async () => { await f.close() })

  it('accepts a recent successful consume for this sender and gate', async () => {
    assert.equal((await attempt(f, await registerConsume(f.rpc, wallet))).status, 200)
  })

  it('refuses a consume older than the age bound, a failed transaction and a foreign sender', async () => {
    f.rpc.state.consumeAgeMs = 6 * 24 * 3600 * 1000 // CONSUME_MAX_AGE_SECS is 5 days
    assert.equal((await attempt(f, await registerConsume(f.rpc, wallet))).status, 403)
    f.rpc.state.consumeAgeMs = 1000
    const failed = await registerConsume(f.rpc, wallet)
    f.rpc.state.failed.add(failed)
    assert.equal((await attempt(f, failed)).status, 403)
    assert.equal((await attempt(f, await registerConsume(f.rpc, newWallet()))).status, 403)
  })

  it('retries only "not found", then denies (403) instead of erroring', async () => {
    const { txDigest } = await import('./lib/stubs.mjs')
    f.rpc.state.calls.length = 0
    const res = await attempt(f, txDigest())
    assert.equal(res.status, 403)
    assert.equal(f.rpc.state.calls.filter((c) => c.endsWith('GetTransaction')).length, 4) // TX_FETCH_ATTEMPTS
  })

  it('a late-indexed transaction is found on a retry', async () => {
    const { txDigest } = await import('./lib/stubs.mjs')
    const digest = txDigest()
    setTimeout(() => f.rpc.state.consumes.set(digest, wallet.address), 700) // after the first retry
    f.rpc.state.calls.length = 0
    assert.equal((await attempt(f, digest)).status, 200)
    assert.ok(f.rpc.state.calls.filter((c) => c.endsWith('GetTransaction')).length >= 2)
  })

  it('any other failure is an error at once (no amplification): 502, one call', async () => {
    f.rpc.state.failAll = true
    f.rpc.state.calls.length = 0
    const res = await attempt(f, await registerConsume(f.rpc, wallet))
    f.rpc.state.failAll = false
    assert.equal(res.status, 502)
    assert.deepEqual(JSON.parse(res.body.toString()), { error: 'on-chain verification failed' })
    assert.equal(f.rpc.state.calls.length, 1) // the gate read failed; nothing was retried
  })

  it('a hung node is bounded by RPC_TIMEOUT_SECS', async () => {
    f.rpc.state.stall = true
    const started = Date.now()
    const res = await attempt(f, await registerConsume(f.rpc, wallet))
    f.rpc.state.stall = false
    assert.equal(res.status, 502)
    assert.ok(Date.now() - started < 5000, `took ${Date.now() - started} ms`)
  })

  it('reads the gate strictly: a paused gate that blocks access denies, an unpaused one does not', async () => {
    f.rpc.state.paused = true
    const res = await attempt(f, await registerConsume(f.rpc, wallet))
    f.rpc.state.paused = false
    assert.equal(res.status, 403)
    assert.deepEqual(JSON.parse(res.body.toString()), { error: 'the gate is paused' })
    assert.equal((await attempt(f, await registerConsume(f.rpc, wallet))).status, 200)
  })
})

describe('ownership mode', () => {
  let f
  before(async () => { f = await fixture({ name: 'chain-own', vars: { ...base, SINGLE_USE: 'false', OWNERSHIP_CACHE_TTL_MS: '60000' } }) })
  after(async () => { await f.close() })

  it('the ownership cache serves repeat lookups within its TTL (one ListOwnedObjects call)', async () => {
    const w = newWallet()
    f.rpc.state.owners.add(w.address)
    f.rpc.state.calls.length = 0
    assert.equal((await own(f, w)).status, 200)
    assert.equal((await own(f, w)).status, 200)
    assert.equal(f.rpc.state.calls.filter((c) => c.endsWith('ListOwnedObjects')).length, 1)
  })

  it('a non-owner is denied and the denial is cached too', async () => {
    const w = newWallet()
    assert.equal((await own(f, w)).status, 403)
    assert.equal((await own(f, w)).status, 403)
  })
})

describe('ownership mode without a cache (the default)', () => {
  let f
  before(async () => { f = await fixture({ name: 'chain-nocache', vars: { ...base, SINGLE_USE: 'false' } }) })
  after(async () => { await f.close() })

  it('every gated request is checked live', async () => {
    const w = newWallet()
    f.rpc.state.owners.add(w.address)
    f.rpc.state.calls.length = 0
    await own(f, w)
    await own(f, w)
    assert.equal(f.rpc.state.calls.filter((c) => c.endsWith('ListOwnedObjects')).length, 2)
    f.rpc.state.owners.delete(w.address) // transferred away
    assert.equal((await own(f, w)).status, 403)
  })
})

describe('SUI_RPC_AUTH_HEADER', () => {
  it('is sent on every fullnode call', async () => {
    const f = await fixture({ name: 'chain-auth', vars: { ...base, SINGLE_USE: 'false', SUI_RPC_AUTH_HEADER: 'X-Api-Key: k-123' } })
    try {
      const w = newWallet()
      f.rpc.state.owners.add(w.address)
      assert.equal((await own(f, w)).status, 200)
      await sleep(50)
      assert.ok(f.rpc.state.headers.length >= 2)
      for (const h of f.rpc.state.headers) assert.equal(h['x-api-key'], 'k-123')
    } finally { await f.close() }
  })
})
