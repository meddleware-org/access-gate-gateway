// The 100 MB path under workerd: a body of that size streams through the Worker without being
// buffered (wasm linear memory stays flat), the cap is exact, and the upstream never sees a byte more
// than MAX_BODY_BYTES. Port of the spike's stream.mjs onto the production gated path.
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { fixture, nextIp } from './lib/fixture.mjs'
import { chunked, rawRequest } from './lib/http.mjs'
import { newWallet, proofToken } from './lib/proof.mjs'

const CAP = 100_000_000
const MIB = 1024 * 1024
let f
const wallet = newWallet()
before(async () => {
  f = await fixture({
    name: 'stream',
    build: 'hooks',
    upstream: { keepBodies: false },
    vars: { SINGLE_USE: 'false', RATE_LIMIT_PER_MIN: '0', GATED_PREAUTH_RATE_LIMIT_PER_MIN: '0', CHALLENGE_RATE_LIMIT_PER_MIN: '0' },
  })
  f.rpc.state.owners.add(wallet.address)
})
after(async () => { await f.close() })

const wasm = async () => (await (await fetch(`${f.base}/__test/mem`)).json()).wasmMemoryBytes
async function put(body, headers = {}) {
  const token = await proofToken({ base: f.base, wallet })
  return await rawRequest(f.base, { method: 'PUT', path: '/v1/blob-upload-relay', headers: { authorization: `Bearer ${token}`, 'CF-Connecting-IP': nextIp(), ...headers }, body, timeoutMs: 120_000 })
}

describe('streaming proxy', () => {
  it('streams 90 MiB through (chunked and Content-Length framed) with flat wasm memory', async () => {
    const total = 90 * MIB
    const before = await wasm()
    f.up.reset()
    const a = await put(chunked(total, MIB))
    assert.equal(a.status, 200)
    assert.equal(JSON.parse(a.body.toString()).bytes, total)
    const afterChunked = await wasm()

    const b = await put(chunked(total, MIB), { 'content-length': String(total) })
    assert.equal(b.status, 200)
    assert.equal(JSON.parse(b.body.toString()).bytes, total)
    // Re-framed with the declared length (FixedLengthStream), not chunked.
    assert.equal(f.up.seen[1].headers['content-length'], String(total))
    assert.equal(f.up.seen[1].headers['transfer-encoding'], undefined)
    const afterBoth = await wasm()
    // Linear memory is the code's working set, not the body: a buffered 90 MiB body would grow it by 90 MiB.
    assert.ok(afterBoth - before < 8 * MIB, `wasm memory grew ${(afterBoth - before) / MIB} MiB (${before} → ${afterChunked} → ${afterBoth})`)
  })

  it('answers 413 once a chunked body crosses the cap, and the upstream never sees more than the cap', async () => {
    f.up.reset()
    const res = await put(chunked(CAP + MIB, MIB))
    assert.equal(res.status, 413)
    assert.deepEqual(JSON.parse(res.body.toString()), { error: 'request body too large' })
    await new Promise((r) => setTimeout(r, 500))
    for (const r of f.up.seen) assert.ok(r.bytes <= CAP, `upstream saw ${r.bytes}`)
  })

  it('refuses a declared Content-Length over the cap up front, with nothing sent upstream', async () => {
    f.up.reset()
    const size = CAP + MIB
    const res = await put(chunked(size, MIB), { 'content-length': String(size) })
    assert.equal(res.status, 413)
    assert.deepEqual(JSON.parse(res.body.toString()), { error: 'request body too large' })
    assert.equal(f.up.seen.length, 0) // refused before any upstream work, not after reading the body
  })
})
