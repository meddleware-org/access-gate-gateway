// Port of gateway-workers/test/proxy.test.ts. The TypeScript tests called forward() directly with a
// stubbed fetch; here every case goes through the real gated path of the built Rust Worker
// (signed proof → stub fullnode → streamed proxy → stub upstream) under workerd.
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { fixture, nextIp } from './lib/fixture.mjs'
import { chunked, payload, rawRequest } from './lib/http.mjs'
import { newWallet, proofToken } from './lib/proof.mjs'
import { sleep } from './lib/worker.mjs'

const CAP = 1000
let f
let down
const wallet = newWallet()

const vars = {
  SINGLE_USE: 'false', // ownership mode: no consume needed, redemption has its own suite
  MAX_BODY_BYTES: String(CAP),
  UPSTREAM_TIMEOUT_SECS: '1',
  RATE_LIMIT_PER_MIN: '0',
  GATED_PREAUTH_RATE_LIMIT_PER_MIN: '0',
  CHALLENGE_RATE_LIMIT_PER_MIN: '0',
  UPSTREAM_AUTH_HEADERS: JSON.stringify([{ name: 'CF-Access-Client-Id', value: 'svc-id' }]),
}

before(async () => {
  f = await fixture({ name: 'proxy', vars })
  f.rpc.state.owners.add(wallet.address)
  down = await fixture({ name: 'proxy-down', vars, upstreamUrl: 'http://127.0.0.1:1' })
  down.rpc.state.owners.add(wallet.address)
})
after(async () => { await f.close(); await down.close() })

/** A request through the gated path with a fresh signed proof. */
async function gated(fx, { method = 'POST', path = '/v1/blob-upload-relay', headers = {}, body = null, raw = false } = {}) {
  const token = await proofToken({ base: fx.base, wallet })
  const h = { authorization: `Bearer ${token}`, 'CF-Connecting-IP': nextIp(), ...headers }
  return await rawRequest(fx.base, { method, path, headers: h, body })
}
const json = (r) => JSON.parse(r.body.toString())

describe('forward body limit', () => {
  it('rejects an over-limit chunked body with 413 and aborts the upstream request', async () => {
    f.up.reset()
    const res = await gated(f, { body: chunked(CAP * 3, 400) })
    assert.equal(res.status, 413)
    assert.deepEqual(json(res), { error: 'request body too large' })
    await sleep(300)
    assert.equal(f.up.seen.filter((r) => r.complete).length, 0) // the upstream never received a complete body
  })

  it('aborts the upstream request when the cap is crossed (the upstream never sees more than the cap)', async () => {
    f.up.reset()
    const res = await gated(f, { body: chunked(CAP + 1, 256) })
    assert.equal(res.status, 413)
    await sleep(300)
    for (const r of f.up.seen) {
      assert.ok(r.bytes <= CAP, `upstream saw ${r.bytes} bytes`)
      assert.equal(r.complete, false)
    }
  })

  it('forwards an under-limit chunked body intact', async () => {
    f.up.reset()
    const data = payload(CAP)
    const res = await gated(f, { body: [data.subarray(0, 300), data.subarray(300, 600), data.subarray(600)] })
    assert.equal(res.status, 200)
    assert.equal(f.up.seen.length, 1)
    assert.ok(f.up.seen[0].buffer.equals(data))
    assert.equal(f.up.seen[0].aborted, false)
  })

  it('forwards an under-limit Content-Length body intact, still Content-Length framed', async () => {
    f.up.reset()
    const data = payload(CAP - 1)
    const res = await gated(f, { body: data, headers: { 'content-length': String(data.length) } })
    assert.equal(res.status, 200)
    assert.ok(f.up.seen[0].buffer.equals(data))
    assert.equal(f.up.seen[0].headers['content-length'], String(data.length))
    assert.equal(f.up.seen[0].headers['transfer-encoding'], undefined)
  })

  it('rejects a declared over-limit Content-Length with 413 before contacting the upstream', async () => {
    f.up.reset()
    const data = payload(CAP + 1)
    const res = await gated(f, { body: data, headers: { 'content-length': String(data.length) } })
    assert.equal(res.status, 413)
    assert.deepEqual(json(res), { error: 'request body too large' })
    await sleep(100)
    assert.equal(f.up.seen.length, 0)
  })

  it('still answers 502 when the upstream itself fails', async () => {
    const res = await gated(down, { body: payload(10), headers: { 'content-length': '10' } })
    assert.equal(res.status, 502)
    assert.deepEqual(json(res), { error: 'upstream error' })
  })
})

describe('forward redirects', () => {
  it('never follows a redirect: the service-token headers must not reach the Location host', async () => {
    f.up.reset()
    const res = await gated(f, { method: 'GET', path: '/v1/redirect' })
    assert.equal(res.status, 502)
    assert.equal(res.headers.location, undefined)
    assert.equal(f.up.seen.length, 1) // one request to the upstream, the Location target was never contacted
    assert.equal(f.up.seen[0].url, '/v1/redirect')
  })
})

describe('forward deadline', () => {
  it('ends a stalled upstream with 504 once the total deadline passes', async () => {
    const started = Date.now()
    const res = await gated(f, { method: 'GET', path: '/v1/stall' })
    assert.equal(res.status, 504)
    assert.deepEqual(json(res), { error: 'upstream timed out' })
    assert.ok(Date.now() - started < 5000)
  })
})

describe('forward header policy', () => {
  it('strips hop-by-hop, credential and spoofable request fields and sets the gateway marker', async () => {
    f.up.reset()
    await gated(f, {
      method: 'GET',
      path: '/v1/x',
      headers: {
        'x-access-proof': 'proof',
        cookie: 'session=1',
        forwarded: 'for=1.2.3.4',
        'x-forwarded-for': '1.2.3.4',
        'x-forwarded-host': 'evil.example',
        'x-forwarded-proto': 'http',
        'x-real-ip': '1.2.3.4',
        via: '1.1 evil',
        'cf-access-client-secret': 'client-supplied',
        'cf-access-client-id': 'client-supplied-id',
        'proxy-authorization': 'Basic abc',
        'x-keep-me': 'yes',
      },
    })
    const sent = f.up.seen[0].headers
    for (const name of ['authorization', 'x-access-proof', 'cookie', 'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-real-ip', 'cf-access-client-secret', 'proxy-authorization']) {
      assert.equal(sent[name], undefined, name)
    }
    // The client's `via` is dropped and replaced by the gateway's own hop marker (F43).
    assert.equal(sent.via, '1.1 nft-gate')
    assert.equal(sent['x-keep-me'], 'yes')
    assert.equal(sent['cf-access-client-id'], 'svc-id') // the gateway's own credential, set last
  })

  it('strips TE and Upgrade (the Connection header itself is consumed by workerd before the Worker runs)', async () => {
    f.up.reset()
    await gated(f, { method: 'GET', path: '/v1/x', headers: { connection: 'x-secret-hop, close', 'x-secret-hop': 'v', te: 'trailers', upgrade: 'websocket' } })
    const sent = f.up.seen[0].headers
    assert.equal(sent.te, undefined)
    assert.equal(sent.upgrade, undefined)
    // Fields NAMED by `Connection` (x-secret-hop) cannot be observed here: workerd removes `Connection`
    // before the Worker sees the request, in the TypeScript Worker as well (the differential run records
    // the same). That rule is pinned by the core's header tests (`connection_named`, `drop_request_header`).
  })

  it('filters the response: no hop-by-hop, cookies or upstream CORS', async () => {
    const res = await gated(f, { method: 'GET', path: '/v1/headers' })
    assert.equal(res.status, 200)
    for (const name of ['keep-alive', 'set-cookie', 'access-control-allow-credentials']) assert.equal(res.headers[name], undefined, name)
    assert.notEqual(res.headers['access-control-allow-origin'], '*')
    assert.equal(res.headers['x-relay'], 'kept')
  })

  it('refuses a method outside the list and an unsafe path before contacting the upstream', async () => {
    f.up.reset()
    assert.equal((await gated(f, { method: 'DELETE', path: '/v1/x' })).status, 405)
    assert.equal((await gated(f, { method: 'GET', path: '/a%2fb' })).status, 400)
    assert.equal((await gated(f, { method: 'GET', path: '/a//b' })).status, 400)
    assert.equal((await gated(f, { method: 'GET', path: '/a%5Cb' })).status, 400)
    assert.equal((await gated(f, { method: 'GET', path: '/a%00b' })).status, 400)
    assert.equal(f.up.seen.length, 0)
  })

  it('forwards the query string of a gated request unchanged', async () => {
    f.up.reset()
    await gated(f, { method: 'GET', path: '/v1/x?a=1&b=%20' })
    assert.equal(f.up.seen[0].url, '/v1/x?a=1&b=%20')
  })
})

/**
 * Loop detection table (F43). Identical in the core (`headers.rs`, `via_loop_table`): the same inputs
 * must give the same answers. Only the received-by name `access-gate-gateway` matches.
 */
export const VIA_TABLE = [
  [null, false],
  ['1.1 nft-gate', true],
  ['1.1 NFT-GATE', true],
  ['HTTP/1.1 nft-gate (gateway)', true],
  ['1.1 google, 1.1 nft-gate', true],
  ['1.1 nft-gate, 1.1 google', true],
  ['1.1 google', false],
  ['1.1 varnish (Varnish/6.0)', false],
  ['1.1 google (access-gate-gateway)', false],
  ['1.1 nft-gateway', false],
  ['1.1 my-nft-gate', false],
  ['nft-gate', false],
  ['1.1 registry-auth-proxy', false],
]

describe('loop detection (Via)', () => {
  it('matches only our own received-by token', async () => {
    for (const [via, looped] of VIA_TABLE) {
      const res = await f.call('GET', '/v1/challenge', { ...(via === null ? {} : { via }), 'CF-Connecting-IP': nextIp() })
      assert.equal(res.status, looped ? 508 : 200, String(via))
    }
  })

  it('adds the marker to the upstream request and a foreign client Via does not survive', async () => {
    f.up.reset()
    const res = await gated(f, { method: 'GET', path: '/v1/x', headers: { via: '1.1 google' } })
    assert.equal(res.status, 200)
    assert.equal(f.up.seen[0].headers.via, '1.1 nft-gate') // the next hop of a loop would refuse this request
  })
})

describe('gated responses are never cached (F30)', () => {
  it('forwarding a gated request neither reads nor writes the edge cache', async () => {
    f.up.reset()
    // The upstream marks the answer cacheable; the Worker must still go back to it every time.
    const a = await gated(f, { method: 'GET', path: '/v1/blob-upload' })
    await sleep(200)
    const b = await gated(f, { method: 'GET', path: '/v1/blob-upload' })
    assert.equal(a.status, 200)
    assert.equal(b.status, 200)
    assert.equal(f.up.seen.length, 2)
  })
})
