// Port of the rate-limit cases of gateway-workers/test/gateway-state.test.ts (F9, F30): the public-path
// budget, and IPv6 clients keyed by their /64.
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { fixture, nextIp } from './lib/fixture.mjs'
import { ALLOWED_ORIGIN } from './lib/worker.mjs'

let f
before(async () => { f = await fixture({ name: 'limits' }) })
after(async () => { await f.close() })

describe('rate limits (F9, F30)', () => {
  it('rate-limits public paths per client IP, before the cache and the upstream', async () => {
    const ip = nextIp()
    f.up.reset()
    const call = (addr) => f.call('GET', '/v1/tip-config', { 'CF-Connecting-IP': addr, origin: ALLOWED_ORIGIN })
    for (let i = 0; i < 120; i++) assert.equal((await call(ip)).status, 200) // PUBLIC_RATE_LIMIT_PER_MIN = 120
    const limited = await call(ip)
    assert.equal(limited.status, 429)
    assert.deepEqual(await limited.json(), { error: 'rate limit exceeded' })
    assert.equal(limited.headers.get('access-control-allow-origin'), ALLOWED_ORIGIN)
    // Another client is unaffected, and the budget was charged before the cache: the upstream saw one request.
    assert.equal((await call(nextIp())).status, 200)
    assert.equal(f.up.seen.length, 1)
  })

  it('keys IPv6 clients by their /64', async () => {
    // Rotating the low 64 bits does not buy a fresh budget (CHALLENGE_RATE_LIMIT_PER_MIN = 30).
    const call = (addr) => f.call('GET', '/v1/challenge', { 'CF-Connecting-IP': addr })
    for (let i = 0; i < 30; i++) assert.equal((await call(`2001:db8:a:b::${i + 1}`)).status, 200)
    assert.equal((await call('2001:db8:a:b:f::99')).status, 429)
    assert.equal((await call('2001:DB8:A:B:0:0:0:7')).status, 429) // spelling does not matter
    assert.equal((await call('2001:db8:a:c::1')).status, 200) // another /64
    assert.equal((await call('203.0.113.9')).status, 200) // IPv4 is keyed as is
  })

  it('shares one "unknown" bucket for a request that carries no CF-Connecting-IP', async () => {
    let limited = 0
    for (let i = 0; i < 32; i++) if ((await f.call('GET', '/v1/challenge')).status === 429) limited++
    assert.ok(limited >= 2, `limited ${limited}`)
  })

  it('the per-address budget is enforced after verification (RATE_LIMIT_PER_MIN)', async () => {
    const o = await fixture({ name: 'limits-addr', vars: { SINGLE_USE: 'false', RATE_LIMIT_PER_MIN: '3', GATED_PREAUTH_RATE_LIMIT_PER_MIN: '0', CHALLENGE_RATE_LIMIT_PER_MIN: '0' } })
    try {
      const { newWallet, proofToken } = await import('./lib/proof.mjs')
      const w = newWallet()
      o.rpc.state.owners.add(w.address)
      const statuses = []
      for (let i = 0; i < 5; i++) {
        const token = await proofToken({ base: o.base, wallet: w })
        statuses.push((await o.call('GET', '/v1/x', { authorization: `Bearer ${token}`, 'CF-Connecting-IP': nextIp() })).status)
      }
      assert.deepEqual(statuses, [200, 200, 200, 429, 429])
    } finally { await o.close() }
  })
})
