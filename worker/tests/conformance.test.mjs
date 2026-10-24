// The shared conformance vectors (conformance/vectors.json) inside workerd: the signature code runs as
// wasm in V8 here, not natively (core/tests/conformance.rs). Three layers:
//   1. every golden signature verifies in the Worker (test-hooks /__test/bench) — real wasm, real V8;
//   2. the golden proof tokens are accepted end to end by a Worker configured with the vectors' audience;
//   3. the audience-mismatch vectors are refused by a Worker whose audience differs in one bound field;
//   4. the `responses` vectors: for each outcome the Worker is put in the situation and must answer the
//      shared status and body (every outcome but a lease that lapses mid-request, which the config forbids).
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fixture, nextIp } from './lib/fixture.mjs'
import { newWallet, proofToken, registerConsume } from './lib/proof.mjs'
import { rawRequest } from './lib/http.mjs'

const vectors = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../../conformance/vectors.json'), 'utf8'))
const golden = vectors.signatures[0].context // origin, gateId, network, nonce
const NFT_TYPE = '0xd7ddaa94b74330979b2b618fc81206d160a264f1c9ca148a77fa2144301388c9::access_gate::SoulboundAccessNFT'

const common = {
  GATEWAY_ORIGIN: golden.origin,
  GATE_ID: golden.gateId,
  NETWORK: golden.network,
  NFT_TYPE,
  RATE_LIMIT_PER_MIN: '0',
  GATED_PREAUTH_RATE_LIMIT_PER_MIN: '0',
}
const fixtures = {}
before(async () => {
  const start = async (name, vars, upstream) => {
    const f = await fixture({ name: `conf-${name}`, build: 'hooks', vars: { ...common, ...vars }, upstream })
    f.rpc.state.gate = (vars.GATE_ID ?? golden.gateId)
    return (fixtures[name] = f)
  }
  await Promise.all([
    start('own', { SINGLE_USE: 'false' }),
    // /v1/slow answers after 600 ms: a second upload for the same consume meets the lease (409 leased).
    start('single', { SINGLE_USE: 'true' }, { respond: (req, res) => (req.url.startsWith('/v1/slow') ? setTimeout(() => res.end('{}'), 600) : res.end('{}')) }),
    start('other-origin', { SINGLE_USE: 'false', GATEWAY_ORIGIN: 'https://other.example' }),
    start('other-gate', { SINGLE_USE: 'false', GATE_ID: '0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2' }),
    start('mainnet', { SINGLE_USE: 'false', NETWORK: 'mainnet' }),
    start('chain-down', { SINGLE_USE: 'false', SUI_RPC_URL: 'http://127.0.0.1:1' }),
    start('outage', { SINGLE_USE: 'false', TEST_FAIL_STATE: 'rate' }),
    start('limited', { SINGLE_USE: 'false', CHALLENGE_RATE_LIMIT_PER_MIN: '1' }),
    start('commit-fails', { SINGLE_USE: 'true', TEST_FAIL_STATE: 'commit' }),
  ])
})
after(async () => { for (const f of Object.values(fixtures)) await f.close() })

/** Issue the vectors' fixed nonce in the Worker's global shard, then present `token`. */
async function present(f, token, { owner, consume } = {}) {
  const r = await fetch(`${f.base}/__test/do/g/issue?nonce=${encodeURIComponent(golden.nonce)}&ttl=300&max=100`)
  assert.equal(r.status, 200)
  if (owner) f.rpc.state.owners.add(owner)
  if (consume) f.rpc.state.consumes.set(consume.digest, consume.sender)
  return await f.call('PUT', '/v1/upload', { authorization: `Bearer ${token}`, 'CF-Connecting-IP': nextIp() }, { body: 'x' })
}

describe('golden signatures verify as wasm in workerd', () => {
  for (const sig of vectors.signatures) {
    it(sig.scheme, async () => {
      const r = await fixtures.own.call('GET', `/__test/bench?scheme=${encodeURIComponent(sig.scheme)}&iters=3&warmup=0`)
      assert.equal(r.status, 200)
      const b = await r.json()
      assert.equal(b.valid, true)
    })
  }
})

describe('golden proof tokens are accepted end to end', () => {
  for (const sig of vectors.signatures.filter((s) => !s.context.consumeDigest)) {
    it(`${sig.scheme} (ownership mode)`, async () => {
      const res = await present(fixtures.own, sig.proofToken, { owner: sig.address })
      assert.equal(res.status, 200, await res.clone().text())
    })
  }
  it('ed25519 single-use (consume check + lease + commit)', async () => {
    const sig = vectors.signatures.find((s) => s.context.consumeDigest)
    const res = await present(fixtures.single, sig.proofToken, { consume: { digest: sig.context.consumeDigest, sender: sig.address } })
    assert.equal(res.status, 200, await res.clone().text())
  })
})

describe('audience-mismatch vectors are refused', () => {
  const ed = vectors.signatures[0]
  it('wrong origin', async () => {
    const res = await present(fixtures['other-origin'], ed.proofToken, { owner: ed.address })
    assert.equal(res.status, 403)
    assert.equal((await res.json()).error, 'signature does not recover address')
  })
  it('wrong gate', async () => {
    const res = await present(fixtures['other-gate'], ed.proofToken, { owner: ed.address })
    assert.equal(res.status, 403)
    assert.equal((await res.json()).error, 'signature does not recover address')
  })
  it('wrong network', async () => {
    const res = await present(fixtures.mainnet, ed.proofToken, { owner: ed.address })
    assert.equal(res.status, 403)
    assert.equal((await res.json()).error, 'signature does not recover address')
  })
  it('a single-use gateway refuses a proof signed without the consume line (ConsumeMissing)', async () => {
    const res = await present(fixtures.single, ed.proofToken, { owner: ed.address })
    assert.equal(res.status, 403)
    assert.equal((await res.json()).error, 'no matching single-use consume for this address')
  })
  it('an ownership gateway refuses a proof signed for single-use (the consume line is signed)', async () => {
    const sig = vectors.signatures.find((s) => s.context.consumeDigest)
    const res = await present(fixtures.own, sig.proofToken, { owner: sig.address })
    assert.equal(res.status, 403)
    assert.equal((await res.json()).error, 'signature does not recover address')
  })
})

// ── the `responses` vectors ──────────────────────────────────────────────────────────────────────
const wallet = newWallet()

/** One upload with a fresh challenge for `digest` on the single-use Worker `f`. */
async function uploadConsume(f, digest, path = '/v1/upload') {
  const token = await proofToken({ base: f.base, origin: golden.origin, gateId: golden.gateId, network: golden.network, wallet, consumeDigest: digest })
  return await rawRequest(f.base, { method: 'PUT', path, headers: { authorization: `Bearer ${token}`, 'CF-Connecting-IP': nextIp() }, body: Buffer.from('blob') })
}
const asJson = (r) => (r.body ? JSON.parse(r.body.toString()) : r.json())

const ed = vectors.signatures[0]
/** Each driver returns { status, body } for its outcome. */
const drivers = {
  'missing-proof': async () => answer(await fixtures.own.call('PUT', '/v1/upload', { 'CF-Connecting-IP': nextIp() })),
  'bad-proof': async () => answer(await fixtures.own.call('PUT', '/v1/upload', { authorization: 'Bearer !!!not-base64!!!', 'CF-Connecting-IP': nextIp() })),
  'bad-signature': async () => answer(await present(fixtures['other-origin'], ed.proofToken, { owner: ed.address })),
  'not-owner': async () => {
    fixtures.own.rpc.state.owners.delete(ed.address)
    return answer(await present(fixtures.own, ed.proofToken))
  },
  'nonce-invalid': async () => {
    fixtures.own.rpc.state.owners.add(ed.address)
    assert.equal((await present(fixtures.own, ed.proofToken, { owner: ed.address })).status, 200)
    // The nonce was consumed by that request; the same proof again finds it spent.
    return answer(await fixtures.own.call('PUT', '/v1/upload', { authorization: `Bearer ${ed.proofToken}`, 'CF-Connecting-IP': nextIp() }, { body: 'x' }))
  },
  'consume-missing': async () => answer(await present(fixtures.single, ed.proofToken, { owner: ed.address })),
  'gate-paused': async () => {
    fixtures.own.rpc.state.paused = true
    try {
      return answer(await present(fixtures.own, ed.proofToken, { owner: ed.address }))
    } finally {
      fixtures.own.rpc.state.paused = false
    }
  },
  'chain-error': async () => answer(await present(fixtures['chain-down'], ed.proofToken, { owner: ed.address })),
  'state-unavailable': async () => answer(await fixtures.outage.call('GET', '/v1/challenge', { 'CF-Connecting-IP': nextIp() })),
  'rate-limited': async () => {
    const ip = nextIp()
    assert.equal((await fixtures.limited.call('GET', '/v1/challenge', { 'CF-Connecting-IP': ip })).status, 200)
    return answer(await fixtures.limited.call('GET', '/v1/challenge', { 'CF-Connecting-IP': ip }))
  },
  'method-not-allowed': async () => answer(await fixtures.own.call('DELETE', '/v1/upload', { 'CF-Connecting-IP': nextIp() })),
  'loop-detected': async () => answer(await fixtures.own.call('PUT', '/v1/upload', { via: '1.1 access-gate-gateway', 'CF-Connecting-IP': nextIp() })),
  'consume-redeemed': async () => {
    const digest = await registerConsume(fixtures.single.rpc, wallet)
    assert.equal((await uploadConsume(fixtures.single, digest)).status, 200)
    return answer(await uploadConsume(fixtures.single, digest))
  },
  'consume-leased': async () => {
    const digest = await registerConsume(fixtures.single.rpc, wallet)
    const slow = uploadConsume(fixtures.single, digest, '/v1/slow')
    await new Promise((r) => setTimeout(r, 250))
    const dup = answer(await uploadConsume(fixtures.single, digest, '/v1/slow'))
    assert.equal((await slow).status, 200)
    return dup
  },
  'commit-failed': async () => answer(await uploadConsume(fixtures['commit-fails'], await registerConsume(fixtures['commit-fails'].rpc, wallet))),
}
/** Not reachable from outside: a lease that lapses mid-request (the config forbids a lease shorter than the request); pinned in core (gateway.rs) and at the store (state.test.mjs). */
const UNREACHABLE = ['lease-lost']

function answer(r) {
  return typeof r.json === 'function' ? r : { status: r.status, json: async () => asJson(r) }
}

describe('response vectors: the Worker answers what the shared contract says', () => {
  it('drives every outcome in the vectors (bar the documented unreachable one)', () => {
    assert.deepEqual([...Object.keys(drivers), ...UNREACHABLE].sort(), vectors.responses.cases.map((c) => c.outcome).sort())
  })
  for (const c of vectors.responses.cases.filter((c) => !UNREACHABLE.includes(c.outcome))) {
    it(`${c.outcome}: ${c.status} ${c.error}`, async () => {
      const res = await drivers[c.outcome]()
      assert.equal(res.status, c.status)
      assert.deepEqual(await res.json(), c.code ? { error: c.error, code: c.code } : { error: c.error })
    })
  }
})
