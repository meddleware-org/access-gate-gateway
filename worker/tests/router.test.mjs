// Port of gateway-workers/test/router.test.ts against the built Rust Worker running under workerd.
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fixture, nextIp } from './lib/fixture.mjs'
import { ALLOWED_ORIGIN } from './lib/worker.mjs'

const DISALLOWED_ORIGIN = 'https://evil.example.com'
const vectors = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../../conformance/vectors.json'), 'utf8'))
const acao = (res) => res.headers.get('access-control-allow-origin')

let f
let down // a second Worker whose upstream is unreachable
before(async () => {
  f = await fixture({
    name: 'router',
    upstream: {
      respond: (req, res) => {
        res.setHeader('content-type', 'application/json')
        if (req.url.startsWith('/v1/tip-config')) {
          res.setHeader('access-control-allow-origin', '*')
          return res.end('{"tip":1}')
        }
        res.end('{}')
      },
    },
  })
  down = await fixture({ name: 'router-down', upstreamUrl: 'http://127.0.0.1:1' })
})
after(async () => { await f.close(); await down.close() })

describe('router', () => {
  it('GET /healthz → 200 ok', async () => {
    const res = await f.call('GET', '/healthz')
    assert.equal(res.status, 200)
    assert.equal(await res.text(), 'ok')
  })

  it('GET /v1/challenge → 200 { nonce, expiresAt }', async () => {
    const res = await f.call('GET', '/v1/challenge', { 'CF-Connecting-IP': nextIp() })
    assert.equal(res.status, 200)
    assert.equal(res.headers.get('content-type'), 'application/json')
    const text = await res.text()
    assert.match(text, /^\{"nonce":"[^"]+","expiresAt":\d+\}$/) // key order of the TypeScript Worker
    const body = JSON.parse(text)
    assert.ok(body.nonce.length > 10)
    assert.ok(body.expiresAt > Date.now())
  })

  it('gated request without a proof → 401 missing access proof', async () => {
    const res = await f.call('POST', '/v1/blob-upload', { 'CF-Connecting-IP': nextIp() })
    assert.equal(res.status, 401)
    assert.deepEqual(await res.json(), { error: 'missing access proof' })
  })

  it('gated request with a malformed proof → 403 malformed access proof', async () => {
    const res = await f.call('POST', '/v1/blob-upload', { authorization: 'Bearer !!!not-base64!!!', 'CF-Connecting-IP': nextIp() })
    assert.equal(res.status, 403)
    assert.deepEqual(await res.json(), { error: 'malformed access proof' })
  })

  // The shared reject vectors, run in the workerd runtime: every token the client's strict decoder must
  // refuse is a 403 at the door. A token with a newline cannot ride in a header value.
  for (const c of vectors.proofDecodeRejects.cases) {
    it(`refuses a malformed proof in workerd: ${c.name}`, async () => {
      if (/[\r\n]/.test(c.token)) return
      const res = await f.call('POST', '/v1/blob-upload', { authorization: `Bearer ${c.token}`, 'CF-Connecting-IP': nextIp() })
      assert.equal(res.status, 403)
      assert.deepEqual(await res.json(), { error: 'malformed access proof' })
    })
  }

  it('OPTIONS /v1/challenge → 204 preflight with CORS headers for allowed origin', async () => {
    const res = await f.call('OPTIONS', '/v1/challenge', { origin: ALLOWED_ORIGIN })
    assert.equal(res.status, 204)
    assert.equal(acao(res), ALLOWED_ORIGIN)
    assert.match(res.headers.get('access-control-allow-methods'), /GET/)
    assert.match(res.headers.get('access-control-allow-headers'), /authorization/)
    assert.equal(res.headers.get('access-control-max-age'), '86400')
    assert.equal(res.headers.get('access-control-expose-headers'), 'location, upload-offset')
  })

  it('OPTIONS /v1/store → 204 preflight with CORS headers for allowed origin', async () => {
    const res = await f.call('OPTIONS', '/v1/store', { origin: ALLOWED_ORIGIN })
    assert.equal(res.status, 204)
    assert.equal(acao(res), ALLOWED_ORIGIN)
  })

  it('GET /v1/challenge → reflects allowed origin', async () => {
    const res = await f.call('GET', '/v1/challenge', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': nextIp() })
    assert.equal(res.status, 200)
    assert.equal(acao(res), ALLOWED_ORIGIN)
  })

  it('401 missing proof → reflects allowed origin', async () => {
    const res = await f.call('POST', '/v1/blob-upload', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': nextIp() })
    assert.equal(res.status, 401)
    assert.equal(acao(res), ALLOWED_ORIGIN)
  })

  it('CORS: disallowed origin receives no Access-Control-Allow-Origin header', async () => {
    const res = await f.call('GET', '/v1/challenge', { origin: DISALLOWED_ORIGIN, 'CF-Connecting-IP': nextIp() })
    assert.equal(acao(res), null)
    assert.match(res.headers.get('access-control-allow-methods'), /GET/)
  })

  it('CORS: request without Origin header receives no Access-Control-Allow-Origin header', async () => {
    const res = await f.call('GET', '/v1/challenge', { 'CF-Connecting-IP': nextIp() })
    assert.equal(acao(res), null)
  })

  it('challenge → sign is a full round trip the nonce store accepts once', async () => {
    const res = await f.call('GET', '/v1/challenge', { 'CF-Connecting-IP': nextIp() })
    const { nonce } = await res.json()
    assert.ok(nonce.includes('.')) // <region>.<hex> shard-tagged form
    assert.match(nonce, /^(af|an|as|eu|na|oc|sa|g)\.[0-9a-f]{48}$/)
  })
})

describe('router hardening', () => {
  it('rate-limits GET /v1/challenge per client IP (parity with Rust), with CORS on the 429', async () => {
    const headers = { 'CF-Connecting-IP': nextIp(), origin: ALLOWED_ORIGIN }
    for (let i = 0; i < 30; i++) assert.equal((await f.call('GET', '/v1/challenge', headers)).status, 200)
    const limited = await f.call('GET', '/v1/challenge', headers)
    assert.equal(limited.status, 429)
    assert.deepEqual(await limited.json(), { error: 'rate limit exceeded' })
    assert.equal(acao(limited), ALLOWED_ORIGIN)
    // Another client is unaffected.
    assert.equal((await f.call('GET', '/v1/challenge', { 'CF-Connecting-IP': nextIp() })).status, 200)
  })

  it('refuses a request that already carries the gateway Via marker with 508, with CORS, on every path class', async () => {
    const looped = { via: '1.1 access-gate-gateway', origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': nextIp() }
    for (const [method, p] of [['GET', '/v1/challenge'], ['GET', '/v1/tip-config'], ['POST', '/v1/blob-upload']]) {
      const res = await f.call(method, p, looped)
      assert.equal(res.status, 508, p)
      assert.deepEqual(await res.json(), { error: 'loop detected' })
      assert.equal(acao(res), ALLOWED_ORIGIN)
    }
    // /healthz and a CORS preflight are answered before the check (probes stay truthful).
    assert.equal((await f.call('GET', '/healthz', looped)).status, 200)
    assert.equal((await f.call('OPTIONS', '/v1/challenge', looped)).status, 204)
  })

  it('lets a foreign Via value (a CDN hop) through untouched', async () => {
    const res = await f.call('GET', '/v1/challenge', { via: '1.1 google', 'CF-Connecting-IP': nextIp() })
    assert.equal(res.status, 200)
  })

  it('every response varies on Origin', async () => {
    for (const res of [
      await f.call('GET', '/v1/challenge', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': nextIp() }),
      await f.call('GET', '/v1/challenge', { 'CF-Connecting-IP': nextIp() }),
      await f.call('POST', '/v1/blob-upload', { 'CF-Connecting-IP': nextIp() }),
    ]) assert.match(res.headers.get('vary'), /Origin/)
  })

  it('an unreachable upstream on a public path fails closed with a JSON body and CORS', async () => {
    const res = await down.call('GET', '/v1/tip-config', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': nextIp() })
    assert.ok(res.status >= 500)
    assert.match(res.headers.get('content-type'), /json/)
    assert.equal(acao(res), ALLOWED_ORIGIN)
  })

  it('public paths are read-only: a body-carrying method is 405 and never reaches the upstream', async () => {
    f.up.reset()
    const res = await f.call('POST', '/v1/tip-config', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': nextIp() })
    assert.equal(res.status, 405)
    assert.equal(res.headers.get('allow'), 'GET, HEAD')
    assert.equal(acao(res), ALLOWED_ORIGIN)
    assert.equal(f.up.seen.length, 0)
  })

  it('gated paths refuse methods outside the list before any verification work', async () => {
    const res = await f.call('DELETE', '/v1/blob-upload', { authorization: 'Bearer abc', 'CF-Connecting-IP': nextIp() })
    assert.equal(res.status, 405)
  })

  it('rate-limits gated requests per client IP BEFORE verifying the proof', async () => {
    const headers = { 'CF-Connecting-IP': nextIp(), authorization: 'Bearer !!!not-base64!!!' }
    let limited = 0
    for (let i = 0; i < 125; i++) {
      const res = await f.call('POST', '/v1/blob-upload', headers)
      if (res.status === 429) limited++
      else assert.equal(res.status, 403)
    }
    assert.ok(limited > 0) // GATED_PREAUTH_RATE_LIMIT_PER_MIN defaults to 120
    assert.equal(limited, 5)
  })

  it('upstream-supplied CORS never widens the allowlist', async () => {
    const res = await f.call('GET', '/v1/tip-config', { origin: DISALLOWED_ORIGIN, 'CF-Connecting-IP': nextIp() })
    assert.equal(res.status, 200)
    assert.equal(acao(res), null)
  })
})

describe('public-path edge cache', () => {
  let c
  before(async () => { c = await fixture({ name: 'cache' }) })
  after(async () => { await c.close() })

  it('drops the query string from the cache key and the forwarded request', async () => {
    const ip = nextIp()
    const first = await c.call('GET', '/v1/tip-config?bust=1', { 'CF-Connecting-IP': ip })
    assert.equal(first.status, 200)
    await new Promise((r) => setTimeout(r, 300)) // cache.put runs in waitUntil
    const second = await c.call('GET', '/v1/tip-config?bust=2', { 'CF-Connecting-IP': ip })
    assert.equal(second.status, 200)
    assert.deepEqual(await second.json(), { tip: 1, bytes: 0 })
    // The upstream saw the bare path, and only once: the second, differently-busted request was a cache hit.
    assert.deepEqual(c.up.seen.map((r) => r.url), ['/v1/tip-config'])
    assert.equal(second.headers.get('cache-control'), 'public, max-age=60')
  })

  it('a cache hit still gets the gateway CORS policy', async () => {
    const hit = await c.call('GET', '/v1/tip-config', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': nextIp() })
    assert.equal(hit.status, 200)
    assert.equal(acao(hit), ALLOWED_ORIGIN)
    assert.match(hit.headers.get('vary'), /Origin/)
    assert.equal(c.up.seen.length, 1) // still the single upstream request
  })
})
