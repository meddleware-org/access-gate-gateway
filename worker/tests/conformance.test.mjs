// The shared conformance vectors (conformance/vectors.json) inside workerd: the signature code runs as
// wasm in V8 here, not natively (core/tests/conformance.rs). Three layers:
//   1. every golden signature verifies in the Worker (test-hooks /__test/bench) — real wasm, real V8;
//   2. the golden proof tokens are accepted end to end by a Worker configured with the vectors' audience;
//   3. the audience-mismatch vectors are refused by a Worker whose audience differs in one bound field.
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fixture, nextIp } from './lib/fixture.mjs'

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
  const start = async (name, vars) => {
    const f = await fixture({ name: `conf-${name}`, build: 'hooks', vars: { ...common, ...vars } })
    f.rpc.state.gate = (vars.GATE_ID ?? golden.gateId)
    return (fixtures[name] = f)
  }
  await Promise.all([
    start('own', { SINGLE_USE: 'false' }),
    start('single', { SINGLE_USE: 'true' }),
    start('other-origin', { SINGLE_USE: 'false', GATEWAY_ORIGIN: 'https://other.example' }),
    start('other-gate', { SINGLE_USE: 'false', GATE_ID: '0xb2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2' }),
    start('mainnet', { SINGLE_USE: 'false', NETWORK: 'mainnet' }),
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
