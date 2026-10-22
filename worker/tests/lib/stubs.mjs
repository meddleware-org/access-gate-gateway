// Local stand-ins for the two things the Worker talks to: the protected upstream and the Sui fullnode
// (gRPC-web, the handful of messages the gateway reads). Test code only.
import http from 'node:http'
import { GATE_ID, freePort, NFT_PKG } from './worker.mjs'

// ── minimal protobuf writer ────────────────────────────────────────────────────────────────────
const varint = (n) => { const o = []; do { let b = n & 0x7f; n = Math.floor(n / 128); if (n) b |= 0x80; o.push(b) } while (n); return Buffer.from(o) }
const len = (f, b) => Buffer.concat([varint((f << 3) | 2), varint(b.length), Buffer.isBuffer(b) ? b : Buffer.from(b)])
const uint = (f, n) => Buffer.concat([varint(f << 3), varint(n)])
const str = (f, s) => len(f, Buffer.from(s))
const strVal = (s) => str(3, s)
const boolVal = (b) => uint(4, b ? 1 : 0)
const structOf = (entries) => len(5, Buffer.concat(entries.map(([k, val]) => len(1, Buffer.concat([str(1, k), len(2, val)])))))
const grpc = (msg) => {
  const trailer = Buffer.from('grpc-status:0\r\n')
  const f = Buffer.alloc(5); f.writeUInt32BE(msg.length, 1)
  const t = Buffer.alloc(5); t[0] = 0x80; t.writeUInt32BE(trailer.length, 1)
  return Buffer.concat([f, msg, t, trailer])
}

// An `Object` message: object_id=2, version=3, object_type=6, json=100 (what both clients read).
const gateJson = (paused, blocks) => structOf([['paused', boolVal(paused)], ['policy', structOf([['pause_blocks_access', boolVal(blocks)]])]])
const objectMsg = (id, type, json) => Buffer.concat([str(2, id), uint(3, 1), str(6, type), len(100, json)])
// GetObject (the Rust Worker's gRPC-web client): GetObjectResponse { Object object = 1 }.
const gateObject = (gate, paused, blocks) => len(1, objectMsg(gate, `${NFT_PKG}::access_gate::Gate`, gateJson(paused, blocks)))
// BatchGetObjects (the TypeScript Worker's @mysten/sui client): { repeated GetObjectResult objects = 1 }, result.object = 1.
const batchGateObjects = (gate, paused, blocks, n) => Buffer.concat(Array.from({ length: n }, () => len(1, len(1, objectMsg(gate, `${NFT_PKG}::access_gate::Gate`, gateJson(paused, blocks))))))
const consumeTx = (sender, gate, ageMs, success = true) => {
  const ev = Buffer.concat([
    str(1, NFT_PKG),
    str(2, 'access_gate'),
    str(3, sender),
    str(4, `${NFT_PKG}::access_gate::AccessConsumedEvent`),
    len(6, structOf([['gate_id', strVal(gate)], ['timestamp_ms', strVal(String(Date.now() - ageMs))]])),
  ])
  return len(1, Buffer.concat([len(4, len(4, success ? uint(1, 1) : Buffer.alloc(0))), len(5, len(3, ev))]))
}
const ownedList = (gate) => len(1, objectMsg('0x' + 'ab'.repeat(32), `${NFT_PKG}::access_gate::SoulboundAccessNFT`, structOf([['data', structOf([['gate_id', strVal(gate)], ['variant', structOf([['@variant', strVal('UnlimitedPass')]])]])]])))

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
/** A random 32-byte transaction digest in base58 (the form the proof carries): each leading zero byte is a `1`. */
export function txDigest() {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  let n = BigInt('0x' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(''))
  let s = ''
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n }
  return '1'.repeat(bytes.findIndex((b) => b !== 0) === -1 ? 32 : bytes.findIndex((b) => b !== 0)) + s
}

/**
 * A fullnode stub. `consumes` maps a digest to the sender that made it; `owners` is the set of
 * addresses that own a pass. `paused` pauses the gate. Counts calls per method.
 */
export async function startFullnode() {
  const state = { stall: false, failed: new Set(), headers: [], paused: false, consumes: new Map(), owners: new Set(), calls: [], failAll: false, consumeAgeMs: 1000, gate: GATE_ID }
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      state.calls.push(req.url)
      state.headers.push(req.headers)
      if (state.stall) return // never answer
      // The Rust Worker speaks binary gRPC-web; @mysten/sui's client (the TypeScript Worker) speaks grpc-web-text (base64).
      const text = String(req.headers['content-type'] ?? '').includes('grpc-web-text')
      const body = text ? Buffer.from(Buffer.concat(chunks).toString(), 'base64') : Buffer.concat(chunks)
      res.setHeader('content-type', text ? 'application/grpc-web-text+proto' : 'application/grpc-web+proto')
      const end = res.end.bind(res)
      res.end = (b) => end(text && Buffer.isBuffer(b) && b.length ? b.toString('base64') : b)
      if (state.failAll) { res.statusCode = 500; return res.end() }
      if (req.url.endsWith('LedgerService/GetObject')) return res.end(grpc(gateObject(state.gate, state.paused, true)))
      if (req.url.endsWith('LedgerService/BatchGetObjects')) {
        // one result per request entry: count the `requests` (field 1) in the body
        const msg = body.subarray(5)
        let n = 0
        for (let i = 0; i < msg.length;) { const tag = msg[i++]; if (tag === 0x0a) { let l = 0, sh = 0; for (;;) { const b = msg[i++]; l |= (b & 0x7f) << sh; if (!(b & 0x80)) break; sh += 7 } i += l; n++ } else break }
        return res.end(grpc(batchGateObjects(state.gate, state.paused, true, Math.max(1, n))))
      }
      if (req.url.endsWith('LedgerService/GetTransaction')) {
        // The digest is the first string field of the request (field 1, after the 5-byte frame header).
        const msg = body.subarray(5)
        const digest = msg.subarray(2, 2 + msg[1]).toString()
        const sender = state.consumes.get(digest)
        if (!sender) { res.setHeader('grpc-status', '5'); return res.end() } // NOT_FOUND (trailers-only)
        return res.end(grpc(consumeTx(sender, state.gate, state.consumeAgeMs, !state.failed.has(digest))))
      }
      if (req.url.endsWith('StateService/ListOwnedObjects')) {
        const owner = body.toString('latin1').match(/0x[0-9a-f]{64}/)?.[0] // field 1 of the request
        return res.end(grpc(owner && state.owners.has(owner) ? ownedList(state.gate) : Buffer.alloc(0)))
      }
      res.statusCode = 404; res.end()
    })
  })
  const port = await freePort()
  await new Promise((r) => server.listen(port, '127.0.0.1', r))
  return {
    url: `http://127.0.0.1:${port}`,
    state,
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r) }),
  }
}

/**
 * An upstream stub. Every request is recorded (`seen`) with its body bytes. Behaviour by path:
 *   /v1/stall       never answers (until the client gives up)
 *   /v1/redirect    302 to an evil host
 *   /v1/fail        500
 *   /v1/headers     answers with hop-by-hop, cookie and CORS headers set
 *   anything else   200 with a body naming the byte count (`bytes=<n>`), or `opts.respond(req)` when given
 */
export async function startUpstream(opts = {}) {
  const seen = []
  const open = new Set()
  const server = http.createServer((req, res) => {
    const rec = { method: req.method, url: req.url, headers: req.headers, bytes: 0, body: [], complete: false, aborted: false }
    seen.push(rec)
    const keep = opts.keepBodies !== false
    req.on('data', (c) => { rec.bytes += c.length; if (keep && rec.bytes < 1_000_000) rec.body.push(c) })
    req.on('aborted', () => { rec.aborted = true })
    req.on('error', () => { rec.aborted = true })
    req.on('close', () => open.delete(res))
    open.add(res)
    req.on('end', () => {
      rec.complete = true
      rec.buffer = Buffer.concat(rec.body)
      if (req.url.startsWith('/v1/stall')) return // hold the response open
      if (req.url.startsWith('/v1/redirect')) { res.statusCode = 302; res.setHeader('location', 'https://evil.example/steal'); return res.end() }
      if (req.url.startsWith('/v1/fail')) { res.statusCode = 500; return res.end('{"error":"boom"}') }
      if (req.url.startsWith('/v1/headers')) {
        res.setHeader('keep-alive', 'timeout=5'); res.setHeader('set-cookie', 'a=b')
        res.setHeader('access-control-allow-origin', '*'); res.setHeader('access-control-allow-credentials', 'true')
        res.setHeader('x-relay', 'kept'); res.setHeader('content-type', 'application/json')
        return res.end('{"ok":true}')
      }
      if (opts.respond) return opts.respond(req, res, rec)
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({ tip: 1, bytes: rec.bytes }))
    })
  })
  const port = await freePort()
  await new Promise((r) => server.listen(port, '127.0.0.1', r))
  return {
    url: `http://127.0.0.1:${port}`,
    seen,
    reset: () => { seen.length = 0 },
    close: () => new Promise((r) => { for (const s of open) s.destroy(); server.closeAllConnections?.(); server.close(r) }),
  }
}
