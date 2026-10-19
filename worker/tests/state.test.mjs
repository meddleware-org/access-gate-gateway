// The Durable Object, reached directly through the test-hooks build (`/__test/do/<shard>/<op>`, with a
// pinned clock): core/tests/scenario.json against the real SQLite DO (the same file drives the pure
// state machines in core/tests/scenario.rs), the atomicity checks, the store cases of
// gateway-workers/test/state.test.ts, and the upgrade of a table that predates the owner token.
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fixture, nextIp } from './lib/fixture.mjs'
import { newWallet, proofToken, registerConsume } from './lib/proof.mjs'

const scenario = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../../core/tests/scenario.json'), 'utf8'))
let f
before(async () => { f = await fixture({ name: 'state', build: 'hooks' }) })
after(async () => { await f.close() })

const run = Math.random().toString(36).slice(2, 8)
let n = 0
const shardName = () => `t${run}x${n++}`
/** One DO operation on `shard`; params are query parameters. */
async function op(shard, name, params = {}) {
  const q = new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)]))
  const r = await fetch(`${f.base}/__test/do/${shard}/${name}?${q}`)
  assert.equal(r.status, 200, `${name}: ${await r.clone().text()}`)
  return await r.json()
}
const key = () => '0xdigest' + Math.random().toString(16).slice(2)

describe('scenario.json against the SQLite Durable Object (same file as the pure state machines)', () => {
  for (const section of scenario.sections) {
    it(section.name, async () => {
      const shard = shardName()
      const vars = {}
      for (const [i, step] of section.steps.entries()) {
        const params = {}
        for (const [k, v] of Object.entries(step)) {
          if (['op', 'expect', 'bind'].includes(k)) continue
          params[k] = typeof v === 'string' && v.startsWith('$') ? vars[v.slice(1)] : v
        }
        const body = await op(shard, step.op, params)
        if (step.bind) vars[step.bind] = body.token
        if (step.expect) {
          const got = Object.fromEntries(Object.keys(step.expect).map((k) => [k, body[k]]))
          assert.deepEqual(got, step.expect, `${section.name} / step ${i}: ${JSON.stringify(body)}`)
        }
      }
    })
  }
})

describe('atomicity (real clock): one winner under 100 concurrent callers', () => {
  it('100 simultaneous takes of one nonce → exactly one true; 100 leases of one consume → one ok, then all redeemed', async () => {
    const shard = shardName()
    await op(shard, 'issue', { nonce: 'N1', ttl: 300, max: 1000 })
    const takes = await Promise.all(Array.from({ length: 100 }, () => op(shard, 'take', { nonce: 'N1' })))
    assert.equal(takes.filter((t) => t.ok).length, 1)
    const leases = await Promise.all(Array.from({ length: 100 }, () => op(shard, 'lease', { key: 'D1', ttl: 900, max: 1000 })))
    const winners = leases.filter((l) => l.status === 'ok')
    assert.equal(winners.length, 1)
    assert.equal(leases.filter((l) => l.status === 'leased').length, 99)
    assert.equal((await op(shard, 'commit', { key: 'D1', token: winners[0].token, retention: 60 })).result, 'ok')
    const after = await Promise.all(Array.from({ length: 100 }, () => op(shard, 'lease', { key: 'D1', ttl: 900, max: 1000 })))
    assert.ok(after.every((l) => l.status === 'redeemed'))
  })
})

// gateway-workers/test/state.test.ts, "nonce backend: durable-object" (the KV half is not carried over).
describe('nonce store', () => {
  it('a nonce is valid once, then used', async () => {
    const s = shardName()
    await op(s, 'issue', { nonce: 'g.aaa', ttl: 300, max: 100 })
    assert.equal((await op(s, 'take', { nonce: 'g.aaa' })).ok, true)
    assert.equal((await op(s, 'take', { nonce: 'g.aaa' })).ok, false)
  })
  it('an unknown nonce is rejected', async () => {
    assert.equal((await op(shardName(), 'take', { nonce: 'g.never-issued' })).ok, false)
  })
  it('an expired nonce is rejected', async () => {
    const s = shardName()
    await op(s, 'issue', { nonce: 'g.b', ttl: 0, max: 100 }) // immediate expiry
    assert.equal((await op(s, 'take', { nonce: 'g.b' })).ok, false)
  })
  it('hard cap keeps the nonce store bounded', async () => {
    const s = shardName()
    for (let i = 0; i < 20; i++) await op(s, 'issue', { nonce: `g.${i}`, ttl: 300, max: 4 })
    const rows = (await op(s, 'sql', { q: 'SELECT COUNT(*) AS c FROM nonces' })).rows
    assert.equal(rows[0].c, 4)
    await op(s, 'issue', { nonce: 'g.last', ttl: 300, max: 4 })
    assert.equal((await op(s, 'take', { nonce: 'g.last' })).ok, true)
  })
})

describe('redemption store', () => {
  const lease = async (s, k, ttl = 120) => {
    const r = await op(s, 'lease', { key: k, ttl, max: 10_000 })
    assert.equal(r.status, 'ok', `expected a lease, got ${r.status}`)
    return r.token
  }
  const status = async (s, k) => (await op(s, 'lease', { key: k, ttl: 120, max: 10_000 })).status

  it('leases once; a concurrent lease is rejected; commit marks it redeemed', async () => {
    const s = shardName(), k = key()
    const token = await lease(s, k)
    assert.equal(await status(s, k), 'leased')
    assert.equal((await op(s, 'commit', { key: k, token, retention: 3600 })).result, 'ok')
    assert.equal(await status(s, k), 'redeemed')
  })
  it('release makes an interrupted consume immediately re-leasable (use not lost)', async () => {
    const s = shardName(), k = key()
    await op(s, 'release', { key: k, token: await lease(s, k) })
    assert.equal(await status(s, k), 'ok')
  })
  it('release never clears a committed redemption', async () => {
    const s = shardName(), k = key()
    const token = await lease(s, k)
    await op(s, 'commit', { key: k, token, retention: 3600 })
    await op(s, 'release', { key: k, token })
    assert.equal(await status(s, k), 'redeemed')
  })
  it('an expired lease is reclaimable (crashed in-flight upload)', async () => {
    const s = shardName(), k = key()
    await lease(s, k, 0)
    assert.equal(await status(s, k), 'ok')
  })
  it('a stale holder can neither release nor commit over a newer lease', async () => {
    const s = shardName(), k = key()
    const stale = await lease(s, k, 0) // lapses at once
    const fresh = await lease(s, k, 120) // a newer holder
    assert.notEqual(stale, fresh)
    await op(s, 'release', { key: k, token: stale })
    assert.equal(await status(s, k), 'leased')
    assert.equal((await op(s, 'commit', { key: k, token: stale, retention: 3600 })).result, 'lost')
    assert.equal(await status(s, k), 'leased')
    assert.equal((await op(s, 'commit', { key: k, token: fresh, retention: 3600 })).result, 'ok')
    assert.equal(await status(s, k), 'redeemed')
  })
  it('a commit after the lease lapsed is lost, never recorded', async () => {
    const s = shardName(), k = key()
    const token = await lease(s, k, 0)
    assert.equal((await op(s, 'commit', { key: k, token, retention: 3600 })).result, 'lost')
  })
  it('the cap evicts a lease, never a committed redemption', async () => {
    const s = shardName()
    const t = (await op(s, 'lease', { key: 'c1', ttl: 900, max: 2 })).token
    await op(s, 'commit', { key: 'c1', token: t, retention: 900 })
    await op(s, 'lease', { key: 'c2', ttl: 900, max: 2 })
    await op(s, 'lease', { key: 'c3', ttl: 900, max: 2 })
    assert.equal((await op(s, 'lease', { key: 'c1', ttl: 900, max: 2 })).status, 'redeemed')
  })
})

describe('rate limiter', () => {
  it('allows up to the limit then denies, per key', async () => {
    const s = shardName(), a = '0xaaa' + Math.random().toString(16).slice(2)
    for (let i = 0; i < 3; i++) assert.equal((await op(s, 'rate', { addr: a, max: 3 })).ok, true)
    assert.equal((await op(s, 'rate', { addr: a, max: 3 })).ok, false) // 4th within the window
    assert.equal((await op(s, 'rate', { addr: '0xbbb' + Math.random().toString(16).slice(2), max: 3 })).ok, true) // independent key
  })
  it('a limit of 0 disables', async () => {
    const s = shardName()
    for (let i = 0; i < 50; i++) assert.equal((await op(s, 'rate', { addr: '0xzero', max: 0 })).ok, true)
  })
  it('windows older than a minute are swept (the table is bounded by recent keys)', async () => {
    const s = shardName()
    // Old windows at a pinned past clock, then enough calls at the real clock that the 2% sweep fires.
    for (let i = 0; i < 30; i++) await op(s, 'rate', { addr: `old${i}`, max: 5, now: 1000 })
    for (let b = 0; b < 16; b++) await Promise.all(Array.from({ length: 50 }, (_, i) => op(s, 'rate', { addr: `new${b}-${i}`, max: 5 })))
    const rows = (await op(s, 'sql', { q: "SELECT COUNT(*) AS c FROM rate WHERE addr LIKE 'old%'" })).rows
    assert.ok(rows[0].c < 30, `old windows left: ${rows[0].c}`)
    assert.equal((await op(s, 'rate', { addr: '0xafter', max: 5 })).ok, true)
  })
})

describe('schema', () => {
  it('has the exact tables and columns the TypeScript Worker created (a deploy over the live script keeps its data)', async () => {
    const s = shardName()
    await op(s, 'migrate')
    const cols = async (t) => (await op(s, 'sql', { q: `PRAGMA table_info('${t}')` })).rows.map((r) => `${r.name}:${r.type}:${r.notnull}:${r.pk}`)
    assert.deepEqual(await cols('nonces'), ['nonce:TEXT:0:1', 'expiry:INTEGER:1:0'])
    assert.deepEqual(await cols('rate'), ['addr:TEXT:0:1', 'start:INTEGER:1:0', 'count:INTEGER:1:0'])
    assert.deepEqual(await cols('redemptions'), ['key:TEXT:0:1', 'state:TEXT:1:0', 'expiry:INTEGER:1:0', 'token:TEXT:0:0'])
  })

  it('adds the owner-token column to a redemptions table that predates it, keeping its rows', async () => {
    const s = shardName()
    const sql = async (q) => (await op(s, 'sql', { q })).rows
    await sql('DROP TABLE redemptions')
    await sql('CREATE TABLE redemptions (key TEXT PRIMARY KEY, state TEXT NOT NULL, expiry INTEGER NOT NULL)')
    await sql("INSERT INTO redemptions (key, state, expiry) VALUES ('old-committed', 'committed', 9999999999999), ('old-leased', 'leased', 9999999999999)")
    assert.ok(!(await sql("PRAGMA table_info('redemptions')")).some((c) => c.name === 'token'))
    await op(s, 'migrate')
    await op(s, 'migrate') // idempotent
    assert.ok((await sql("PRAGMA table_info('redemptions')")).some((c) => c.name === 'token'))
    assert.equal((await sql('SELECT COUNT(*) AS c FROM redemptions'))[0].c, 2)
    // The old committed row still blocks re-redemption; the old (token-less) lease cannot be committed or released by anyone.
    assert.equal((await op(s, 'lease', { key: 'old-committed', ttl: 120, max: 100 })).status, 'redeemed')
    assert.equal((await op(s, 'lease', { key: 'old-leased', ttl: 120, max: 100 })).status, 'leased')
    assert.equal((await op(s, 'commit', { key: 'old-leased', token: 'anything', retention: 60 })).result, 'lost')
    assert.equal((await op(s, 'lease', { key: 'fresh', ttl: 120, max: 100 })).status, 'ok')
  })
})

describe('shard tags', () => {
  it('a forged shard tag is refused at the gateway without touching a shard (403 nonce invalid)', async () => {
    const wallet = newWallet()
    const digest = await registerConsume(f.rpc, wallet)
    // Sign a proof over a nonce whose shard prefix was never issued here.
    const { buildAccessProof } = await import('./.gen/client.mjs')
    const token = await buildAccessProof({
      address: wallet.address,
      challenge: { nonce: 'attacker-shard-1.deadbeef', expiresAt: Date.now() + 1e5 },
      sign: async (m) => ({ signature: (await wallet.kp.signPersonalMessage(m)).signature }),
      gateway: 'https://gw.example.com',
      gateId: (await import('./lib/worker.mjs')).GATE_ID,
      network: 'testnet',
      consumeDigest: digest,
    })
    const res = await f.call('PUT', '/v1/blob-upload', { authorization: `Bearer ${token}`, 'CF-Connecting-IP': nextIp() }, { body: 'x' })
    assert.equal(res.status, 403)
    assert.deepEqual(await res.json(), { error: 'challenge nonce invalid, expired, or already used' })
  })

  it('a region-sharded nonce is accepted by the shard that issued it, exactly once', async () => {
    const wallet = newWallet()
    const digest = await registerConsume(f.rpc, wallet)
    const headers = { 'CF-Connecting-IP': nextIp() }
    const token = await proofToken({ base: f.base, wallet, consumeDigest: digest, headers })
    const send = () => f.call('PUT', '/v1/blob-upload', { authorization: `Bearer ${token}`, 'CF-Connecting-IP': nextIp() }, { body: 'x' })
    assert.equal((await send()).status, 200)
    // The same proof again: the nonce was consumed (and the consume is redeemed): a replay is refused.
    const replay = await send()
    assert.equal(replay.status, 403)
    assert.deepEqual(await replay.json(), { error: 'challenge nonce invalid, expired, or already used' })
  })
})
