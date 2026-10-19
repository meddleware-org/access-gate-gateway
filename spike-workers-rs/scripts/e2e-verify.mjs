// End-to-end under workerd: POST /verify runs the SHARED nft_gate_core::decision::verify_access_request in
// the Worker, with nonces from the SQLite Durable Object and chain reads over `fetch` against a local
// gRPC-web stub fullnode (SUI_RPC_URL must point at it: wrangler dev --var SUI_RPC_URL:http://127.0.0.1:18081).
//   node scripts/e2e-verify.mjs http://127.0.0.1:8799
import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import assert from 'node:assert/strict'

const base = process.argv[2] ?? 'http://127.0.0.1:8799'
const vectors = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '../../conformance/vectors.json'), 'utf8'))
const v = vectors.signatures.find((s) => s.scheme === 'ed25519 single-use')
const GATE = v.context.gateId

// minimal protobuf writer
const varint = (n) => { const o = []; do { let b = n & 0x7f; n = Math.floor(n / 128); if (n) b |= 0x80; o.push(b) } while (n); return Buffer.from(o) }
const len = (f, b) => Buffer.concat([varint((f << 3) | 2), varint(b.length), Buffer.isBuffer(b) ? b : Buffer.from(b)])
const uint = (f, n) => Buffer.concat([varint(f << 3), varint(n)])
const str = (f, s) => len(f, Buffer.from(s))
const strVal = (s) => str(3, s)
const boolVal = (b) => uint(4, b ? 1 : 0)
const structOf = (entries) => len(5, Buffer.concat(entries.map(([k, val]) => len(1, Buffer.concat([str(1, k), len(2, val)])))))
const grpc = (msg, status = '0') => {
  const trailer = Buffer.from(`grpc-status:${status}\r\n`)
  const f = Buffer.alloc(5); f.writeUInt32BE(msg.length, 1)
  const t = Buffer.alloc(5); t[0] = 0x80; t.writeUInt32BE(trailer.length, 1)
  return Buffer.concat([f, msg, t, trailer])
}
const gateObject = (paused, blocks) => len(1, len(100, structOf([['paused', boolVal(paused)], ['policy', structOf([['pause_blocks_access', boolVal(blocks)]])]])))
const consumeTx = (sender) => {
  const ev = Buffer.concat([str(3, sender), str(4, '0x' + '0'.repeat(61) + 'abc::access_gate::AccessConsumedEvent'),
    len(6, structOf([['gate_id', strVal(GATE)], ['timestamp_ms', strVal(String(Date.now() - 1000))]]))])
  const tx = Buffer.concat([len(4, len(4, uint(1, 1))), len(5, len(3, ev))])
  return len(1, tx)
}

let mode = { paused: false, sender: v.address }
const seen = []
const stub = http.createServer((req, res) => {
  seen.push(req.url)
  req.resume(); req.on('end', () => {
    res.setHeader('content-type', 'application/grpc-web+proto'); res.setHeader('access-control-allow-origin', '*')
    if (req.url.endsWith('LedgerService/GetObject')) return res.end(grpc(gateObject(mode.paused, true)))
    if (req.url.endsWith('LedgerService/GetTransaction')) return res.end(grpc(consumeTx(mode.sender)))
    res.statusCode = 404; res.end()
  })
}).listen(18081, '127.0.0.1')
await new Promise((r) => stub.on('listening', r))

const issue = (n) => fetch(`${base}/do/g/issue?nonce=${n}&ttl=300&max=1000`)
const verify = async () => { const r = await fetch(`${base}/verify`, { method: 'POST', headers: { authorization: `Bearer ${v.proofToken}` } }); return [r.status, await r.json()] }

await issue(v.context.nonce)
let [s, b] = await verify()
console.log('valid single-use proof     ->', s, JSON.stringify(b)); assert.equal(s, 200); assert.equal(b.address, v.address)
;[s, b] = await verify()
console.log('replay (nonce consumed)    ->', s, JSON.stringify(b)); assert.equal(s, 403); assert.equal(b.denied, 'NonceInvalid')
await issue(v.context.nonce); mode.paused = true
;[s, b] = await verify()
console.log('gate paused                ->', s, JSON.stringify(b)); assert.equal(b.denied, 'GatePaused')
await issue(v.context.nonce); mode.paused = false; mode.sender = '0xdead'
;[s, b] = await verify()
console.log('consume by someone else    ->', s, JSON.stringify(b)); assert.equal(b.denied, 'ConsumeMissing')
await issue(v.context.nonce); mode.sender = v.address
stub.close(); await new Promise((r) => setTimeout(r, 50))
;[s, b] = await verify()
console.log('fullnode unreachable       ->', s, JSON.stringify(b)); assert.equal(s, 502); assert.equal(b.denied, 'ChainError')
console.log('stub saw', seen.length, 'gRPC-web calls, e.g.', seen[0])
