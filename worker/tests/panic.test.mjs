// What a panic looks like, recorded so the documentation stays true (README "Failure modes"). A trap
// cannot be caught on wasm32, so the request path is linted free of panics (scripts/lint-canary.sh); this
// pins the residual behaviour if one ever happens: the runtime answers 500 without the gateway's JSON/CORS
// shape (it fails closed: nothing is forwarded), and worker-build's trap recovery re-instantiates the
// module so the next request is served normally. The deployed build has no such route.
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { fixture, nextIp } from './lib/fixture.mjs'
import { ALLOWED_ORIGIN } from './lib/worker.mjs'

let f
before(async () => { f = await fixture({ name: 'panic', build: 'hooks' }) })
after(async () => { await f.close() })

describe('a panic (test-hooks only)', () => {
  it('fails closed with the runtime 500 (no JSON, no CORS grant) and the Worker keeps serving', async () => {
    const res = await f.call('GET', '/__test/panic', { origin: ALLOWED_ORIGIN })
    assert.equal(res.status, 500)
    assert.equal(res.headers.get('access-control-allow-origin'), null)
    assert.doesNotMatch(res.headers.get('content-type') ?? '', /json/)
    f.up.reset()
    // Recovered: the next requests are normal, state in the Durable Object is intact.
    assert.equal((await f.call('GET', '/healthz')).status, 200)
    const ch = await f.call('GET', '/v1/challenge', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': nextIp() })
    assert.equal(ch.status, 200)
    assert.equal(ch.headers.get('access-control-allow-origin'), ALLOWED_ORIGIN)
    assert.equal(f.up.seen.length, 0)
  })

  it('the deployed build has no test routes (the production wasm is built without the feature)', async () => {
    const prod = await fixture({ name: 'noroutes' })
    try {
      for (const p of ['/__test/panic', '/__test/mem', '/__test/bench', '/__test/do/g/issue?nonce=x']) {
        const r = await prod.call('GET', p, { 'CF-Connecting-IP': nextIp() })
        assert.equal(r.status, 401, p) // an ordinary gated path without a proof, nothing special
      }
    } finally { await prod.close() }
  })
})
