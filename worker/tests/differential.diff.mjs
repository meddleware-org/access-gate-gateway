// Differential check: the same client-visible scenarios against the TypeScript Worker (gateway-workers,
// under wrangler dev) and the Rust Worker, asserting identical status codes, bodies and headers (and the
// requests the upstream receives). The TypeScript Worker is the reference until it is retired.
//
// Intended differences (documented in worker/README.md, not asserted here):
//   * ALLOW_INSECURE_HTTP=1 is required by the Rust Worker for the http:// stubs (the TypeScript Worker
//     allowed loopback implicitly); both run with it set so the scenarios are comparable.
//   * stricter shared config rules (core): see the table in core/README.md; scenarios use values both accept.
//   * a missing Durable Object binding answers with the CORS allow-list on the Rust side.
//   * the quota guard's KV "degrade" flag is not carried over (nothing to compare at the HTTP surface).
import fs from 'node:fs'
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import path from 'node:path'
import { chunked, payload, rawRequest } from './lib/http.mjs'
import { newWallet, proofToken, registerConsume } from './lib/proof.mjs'
import { diff, headersOf, record, upstreamSaw } from './lib/transcript.mjs'
import { baseVars, startWorker, WORKER_DIR, ALLOWED_ORIGIN, sleep } from './lib/worker.mjs'
import { startFullnode, startUpstream, txDigest } from './lib/stubs.mjs'

const GW = path.resolve(WORKER_DIR, '../gateway-workers')
// Fail at once, with the cause, instead of every scenario waiting out its start-up timeout.
if (!fs.existsSync(path.join(GW, 'node_modules', 'wrangler'))) {
  throw new Error(`the TypeScript reference Worker has no dependencies: run \`npm ci\` in ${GW} first`)
}
const KINDS = ['ts', 'rust']
let ipn = 0
const ip = () => `203.0.${113 + Math.floor(ipn / 250)}.${(ipn++ % 250) + 1}`

/** Start the TypeScript and the Rust Worker with the same vars, each with its own stubs. */
async function pair(name, vars = {}, upstreamOpts = {}) {
  const make = async (kind) => {
    const rpc = await startFullnode()
    const up = await startUpstream(upstreamOpts)
    const all = baseVars({ UPSTREAM_URL: up.url, SUI_RPC_URL: rpc.url, ...vars })
    let w
    try {
      w = kind === 'ts'
        ? await startWorker({ name: `${name}-ts`, main: path.join(GW, 'src/index.ts'), config: path.join(GW, 'wrangler.toml'), vars: all })
        : await startWorker({ name: `${name}-rust`, vars: all })
    } catch (e) {
      await up.close().catch(() => {})
      await rpc.close().catch(() => {})
      throw e
    }
    return { kind, w, rpc, up, base: w.base, close: async () => { await w.stop(); await up.close(); await rpc.close() } }
  }
  // Start both; if either fails, stop the one that came up (an orphan keeps the test process, and the CI job, alive).
  const settled = await Promise.allSettled([make('ts'), make('rust')])
  const failed = settled.find((r) => r.status === 'rejected')
  if (failed) {
    for (const r of settled) if (r.status === 'fulfilled') await r.value.close().catch(() => {})
    throw failed.reason
  }
  const [ts, rust] = settled.map((r) => r.value)
  return { ts, rust, close: async () => { await ts.close(); await rust.close() } }
}

/** Run `script(side)` against both and assert the transcripts are identical. */
async function same(p, script) {
  const results = {}
  for (const side of [p.ts, p.rust]) {
    side.up.reset()
    results[side.kind] = await script(side)
  }
  const d = diff(results.ts, results.rust)
  assert.equal(d.length, 0, `\n${d.join('\n')}`)
  assert.ok(results.ts.length > 0)
}

const get = (side, path, headers = {}, init = {}) => fetch(side.base + path, { redirect: 'manual', ...init, headers: { 'accept-encoding': 'identity', ...headers } })
/** A gated request with raw control; returns a record plus what the upstream saw. */
async function gatedRec(side, name, { wallet, consume = true, method = 'PUT', path = '/v1/blob-upload-relay', headers = {}, body = Buffer.from('blob'), digest, proofHeaders } = {}) {
  const d = digest ?? (consume ? await registerConsume(side.rpc, wallet) : undefined)
  const token = await proofToken({ base: side.base, wallet, consumeDigest: d, headers: { 'CF-Connecting-IP': ip(), ...proofHeaders } })
  const r = await rawRequest(side.base, { method, path, headers: { authorization: `Bearer ${token}`, 'CF-Connecting-IP': ip(), 'accept-encoding': 'identity', ...headers }, body })
  const text = r.body.toString()
  const h = {}
  for (const [k, v] of Object.entries(r.headers)) if (!['date', 'server', 'connection', 'keep-alive', 'cf-ray', 'content-encoding', 'transfer-encoding'].includes(k) && !k.startsWith('cf-')) h[k] = v
  return { name, status: r.status, headers: h, body: text, digest: d }
}

describe('differential: TypeScript Worker vs Rust Worker (single-use, wrangler.toml defaults)', () => {
  let p
  before(async () => {
    p = await pair('d1', { MAX_BODY_BYTES: '1000', UPSTREAM_TIMEOUT_SECS: '1', UPSTREAM_AUTH_HEADERS: JSON.stringify([{ name: 'CF-Access-Client-Id', value: 'svc-id' }]) })
  })
  after(async () => { await p.close() })

  it('routes, CORS and error shapes', async () => {
    await same(p, async (s) => {
      const t = []
      const o = { origin: ALLOWED_ORIGIN }
      t.push(await record('healthz', await get(s, '/healthz')))
      t.push(await record('healthz POST', await get(s, '/healthz', {}, { method: 'POST' })))
      t.push(await record('challenge', await get(s, '/v1/challenge', { ...o, 'CF-Connecting-IP': ip() })))
      t.push(await record('challenge disallowed origin', await get(s, '/v1/challenge', { origin: 'https://evil.example.com', 'CF-Connecting-IP': ip() })))
      t.push(await record('challenge no origin', await get(s, '/v1/challenge', { 'CF-Connecting-IP': ip() })))
      t.push(await record('challenge POST (gated, no proof)', await get(s, '/v1/challenge', { ...o, 'CF-Connecting-IP': ip() }, { method: 'POST' })))
      t.push(await record('preflight', await get(s, '/v1/challenge', { ...o }, { method: 'OPTIONS' })))
      t.push(await record('preflight any path', await get(s, '/v1/store', { origin: 'https://evil.example.com' }, { method: 'OPTIONS' })))
      t.push(await record('gated no proof', await get(s, '/v1/blob-upload', { ...o, 'CF-Connecting-IP': ip() }, { method: 'POST' })))
      t.push(await record('gated malformed proof', await get(s, '/v1/blob-upload', { ...o, authorization: 'Bearer !!!not-base64!!!', 'CF-Connecting-IP': ip() }, { method: 'POST' })))
      t.push(await record('gated x-access-proof malformed', await get(s, '/v1/blob-upload', { 'x-access-proof': 'abc', 'CF-Connecting-IP': ip() }, { method: 'POST' })))
      t.push(await record('gated DELETE', await get(s, '/v1/blob-upload', { authorization: 'Bearer abc', 'CF-Connecting-IP': ip() }, { method: 'DELETE' })))
      t.push(await record('gated PATCH', await get(s, '/v1/blob-upload', { 'CF-Connecting-IP': ip() }, { method: 'PATCH' })))
      for (const via of ['1.1 nft-gate', '1.1 google', 'HTTP/1.1 NFT-GATE (x)', '1.1 google (nft-gate)']) {
        for (const [m, pth] of [['GET', '/v1/challenge'], ['GET', '/v1/tip-config'], ['POST', '/v1/blob-upload']]) {
          t.push(await record(`via ${via} ${m} ${pth}`, await get(s, pth, { via, ...o, 'CF-Connecting-IP': ip() }, { method: m })))
        }
      }
      t.push(await record('healthz looped', await get(s, '/healthz', { via: '1.1 nft-gate' })))
      t.push(await record('preflight looped', await get(s, '/v1/challenge', { via: '1.1 nft-gate' }, { method: 'OPTIONS' })))
      return t
    })
  })

  it('public path: methods, query handling, cache, upstream request', async () => {
    await same(p, async (s) => {
      const t = []
      const o = { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': ip() }
      t.push(await record('public GET', await get(s, '/v1/tip-config?bust=1', o)))
      await sleep(400)
      t.push(await record('public GET (cache hit, other query)', await get(s, '/v1/tip-config?bust=2', o)))
      t.push(await record('public GET disallowed origin', await get(s, '/v1/tip-config', { origin: 'https://evil.example.com', 'CF-Connecting-IP': ip() })))
      t.push(await record('public POST', await get(s, '/v1/tip-config', o, { method: 'POST' })))
      t.push(await record('public PUT', await get(s, '/v1/tip-config', o, { method: 'PUT' })))
      t.push(await record('public DELETE', await get(s, '/v1/tip-config', o, { method: 'DELETE' })))
      t.push(await record('public HEAD', await get(s, '/v1/tip-config?x=1', o, { method: 'HEAD' })))
      t.push({ name: 'upstream saw', saw: s.up.seen.map(upstreamSaw) })
      return t
    })
  })

  it('rate limits: challenge, public, gated pre-auth (status sequences) and IPv6 /64 keying', async () => {
    await same(p, async (s) => {
      const seq = async (n, f) => { const out = []; for (let i = 0; i < n; i++) out.push((await f(i)).status); return out.join(',') }
      const t = []
      const c = ip()
      t.push({ name: 'challenge x32', seq: await seq(32, () => get(s, '/v1/challenge', { 'CF-Connecting-IP': c })) })
      t.push({ name: 'challenge other ip', seq: await seq(1, () => get(s, '/v1/challenge', { 'CF-Connecting-IP': ip() })) })
      t.push({ name: 'challenge ipv6 rotating low 64 bits x32', seq: await seq(32, (i) => get(s, '/v1/challenge', { 'CF-Connecting-IP': `2001:db8:a:b::${i + 1}` })) })
      t.push({ name: 'challenge other /64', seq: await seq(1, () => get(s, '/v1/challenge', { 'CF-Connecting-IP': '2001:db8:a:c::1' })) })
      t.push({ name: 'challenge no cf ip (shared unknown bucket) x2', seq: await seq(2, () => get(s, '/v1/challenge')) })
      const pub = ip()
      t.push({ name: 'public x122', seq: await seq(122, () => get(s, '/v1/tip-config', { 'CF-Connecting-IP': pub })) })
      const pre = ip()
      t.push({ name: 'gated preauth x125', seq: await seq(125, () => get(s, '/v1/blob-upload', { 'CF-Connecting-IP': pre, authorization: 'Bearer !!!' }, { method: 'POST' })) })
      return t
    })
  })

  it('single-use flow: success, replay, redeemed, leased, release on failure, denials, chain faults', async () => {
    const wallet = newWallet()
    await same(p, async (s) => {
      const t = []
      const w = newWallet() // fresh per side: the per-address budget is 30/min
      // success then redeemed
      const first = await gatedRec(s, 'upload ok', { wallet: w })
      t.push({ ...first, digest: undefined })
      t.push({ name: 'upstream saw (ok)', saw: s.up.seen.map(upstreamSaw) })
      t.push({ ...(await gatedRec(s, 'same consume again → redeemed', { wallet: w, digest: first.digest })), digest: undefined })
      // concurrent duplicate while the first is in flight
      const slowDigest = await registerConsume(s.rpc, w)
      const slow = gatedRec(s, 'slow upload', { wallet: w, path: '/v1/slow', digest: slowDigest })
      await sleep(300)
      t.push({ ...(await gatedRec(s, 'duplicate while in flight → leased', { wallet: w, path: '/v1/slow', digest: slowDigest })), digest: undefined })
      t.push({ ...(await slow), digest: undefined })
      // failed upload releases
      const fd = await registerConsume(s.rpc, w)
      t.push({ ...(await gatedRec(s, 'upstream 500', { wallet: w, path: '/v1/fail', digest: fd })), digest: undefined })
      t.push({ ...(await gatedRec(s, 'retry after failure', { wallet: w, digest: fd })), digest: undefined })
      t.push({ ...(await gatedRec(s, 'stall → 504 releases', { wallet: w, path: '/v1/stall' })), digest: undefined })
      t.push({ ...(await gatedRec(s, 'redirect → 502', { wallet: w, path: '/v1/redirect' })), digest: undefined })
      // someone else's consume / unknown digest / paused gate / missing digest / malformed digest
      t.push({ ...(await gatedRec(s, 'foreign consume', { wallet: w, digest: await registerConsume(s.rpc, newWallet()) })), digest: undefined })
      t.push({ ...(await gatedRec(s, 'unknown digest', { wallet: w, digest: txDigest() })), digest: undefined })
      s.rpc.state.paused = true
      t.push({ ...(await gatedRec(s, 'gate paused', { wallet: w })), digest: undefined })
      s.rpc.state.paused = false
      // replay of a used proof
      const token = await proofToken({ base: s.base, wallet: w, consumeDigest: await registerConsume(s.rpc, w), headers: { 'CF-Connecting-IP': ip() } })
      const send = () => rawRequest(s.base, { method: 'PUT', path: '/v1/blob-upload-relay', headers: { authorization: `Bearer ${token}`, 'CF-Connecting-IP': ip() }, body: Buffer.from('x') })
      t.push({ name: 'proof first use', status: (await send()).status })
      const rep = await send()
      t.push({ name: 'proof replay', status: rep.status, body: rep.body.toString() })
      // chain down
      s.rpc.state.failAll = true
      t.push({ ...(await gatedRec(s, 'fullnode failing', { wallet: w, digest: txDigest() })), digest: undefined })
      s.rpc.state.failAll = false
      return t
    })
    void wallet
  })

  it('proxy: body cap, declared length, framing, header policy, response filtering, unsafe paths', async () => {
    await same(p, async (s) => {
      const t = []
      const w = newWallet()
      t.push({ ...(await gatedRec(s, 'chunked over cap', { wallet: w, body: chunked(3000, 400) })), digest: undefined })
      t.push({ ...(await gatedRec(s, 'declared over cap', { wallet: w, body: payload(1001), headers: { 'content-length': '1001' } })), digest: undefined })
      t.push({ name: 'upstream complete bodies after refusals', n: s.up.seen.filter((r) => r.complete).length })
      s.up.reset()
      t.push({ ...(await gatedRec(s, 'chunked under cap', { wallet: w, body: [payload(300), payload(300)] })), digest: undefined })
      t.push({ ...(await gatedRec(s, 'content-length under cap', { wallet: w, body: payload(999), headers: { 'content-length': '999' } })), digest: undefined })
      t.push({ name: 'upstream saw (bodies)', saw: s.up.seen.map((r) => ({ ...upstreamSaw(r), te: r.headers['transfer-encoding'] ?? null, cl: r.headers['content-length'] ?? null, same: Buffer.isBuffer(r.buffer) ? r.buffer.length : null })) })
      s.up.reset()
      t.push({ ...(await gatedRec(s, 'headers in/out', {
        wallet: w, method: 'GET', path: '/v1/headers?q=1', body: null,
        headers: { cookie: 'a=b', 'x-forwarded-for': '1.2.3.4', forwarded: 'for=1', 'x-real-ip': '1.1.1.1', via: '1.1 evil', 'cf-access-client-secret': 'x', 'x-access-proof': 'p', 'x-keep-me': 'yes', origin: ALLOWED_ORIGIN, te: 'trailers' },
      })), digest: undefined })
      t.push({ name: 'upstream saw (headers)', saw: s.up.seen.map(upstreamSaw) })
      s.up.reset()
      for (const [m, pth] of [['GET', '/a%2fb'], ['GET', '/a//b'], ['GET', '/a%5Cb'], ['GET', '/a%00b'], ['GET', '/a%2E%2Eb'], ['DELETE', '/v1/x']]) {
        t.push({ ...(await gatedRec(s, `${m} ${pth}`, { wallet: w, method: m, path: pth, body: null })), digest: undefined })
      }
      t.push({ name: 'upstream saw (refused paths)', n: s.up.seen.length })
      return t
    })
  })
})

describe('differential: ownership mode and the upstream being down', () => {
  let p, down
  before(async () => {
    p = await pair('d2', { SINGLE_USE: 'false' })
    down = await pair('d3', { SINGLE_USE: 'false' }) // upstream replaced below
  })
  after(async () => { await p.close(); await down.close() })

  it('owner is allowed, non-owner is denied', async () => {
    await same(p, async (s) => {
      const t = []
      const owner = newWallet(), other = newWallet()
      s.rpc.state.owners.add(owner.address)
      t.push({ ...(await gatedRec(s, 'owner', { wallet: owner, consume: false })), digest: undefined })
      t.push({ ...(await gatedRec(s, 'non-owner', { wallet: other, consume: false })), digest: undefined })
      t.push({ ...(await gatedRec(s, 'owner again', { wallet: owner, consume: false })), digest: undefined })
      s.rpc.state.paused = true
      t.push({ ...(await gatedRec(s, 'paused', { wallet: owner, consume: false })), digest: undefined })
      s.rpc.state.paused = false
      return t
    })
  })

  it('an unreachable upstream fails closed with the same JSON shape', async () => {
    // Point both at a closed port by stopping their upstream stubs.
    for (const side of [down.ts, down.rust]) await side.up.close()
    await same(down, async (s) => {
      const t = []
      const owner = newWallet()
      s.rpc.state.owners.add(owner.address)
      t.push(await record('public path, upstream down', await get(s, '/v1/tip-config', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': ip() })))
      t.push({ ...(await gatedRec(s, 'gated, upstream down', { wallet: owner, consume: false, method: 'GET', body: null })), digest: undefined })
      return t
    })
  })
})

describe('differential: startup configuration errors answer the same shape', () => {
  for (const [name, vars] of [
    ['invalid NFT_TYPE', { NFT_TYPE: '0x2::coin::Coin<0x2::sui::SUI>' }],
    ['unknown NETWORK', { NETWORK: 'moonnet' }],
    ['SINGLE_USE typo', { SINGLE_USE: 'yes' }],
    ['negative number', { RATE_LIMIT_PER_MIN: '-1' }],
    ['non-canonical GATEWAY_ORIGIN', { GATEWAY_ORIGIN: 'https://GW.example.com/' }],
    ['upstream is the gateway', { UPSTREAM_URL: 'https://gw.example.com' }],
  ]) {
    it(name, async () => {
      const p = await pair('d4', vars)
      try {
        await same(p, async (s) => {
          const t = []
          t.push(await record('challenge', await get(s, '/v1/challenge', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': ip() })))
          t.push(await record('healthz', await get(s, '/healthz')))
          t.push(await record('preflight', await get(s, '/v1/x', { origin: ALLOWED_ORIGIN }, { method: 'OPTIONS' })))
          return t
        })
      } finally { await p.close() }
    })
  }
})
