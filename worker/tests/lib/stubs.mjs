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

const gateObject = (paused, blocks) => len(1, len(100, structOf([['paused', boolVal(paused)], ['policy', structOf([['pause_blocks_access', boolVal(blocks)]])]])))
const consumeTx = (sender, gate, ageMs) => {
  const ev = Buffer.concat([
    str(3, sender),
    str(4, `${NFT_PKG}::access_gate::AccessConsumedEvent`),
    len(6, structOf([['gate_id', strVal(gate)], ['timestamp_ms', strVal(String(Date.now() - ageMs))]])),
  ])
  return len(1, Buffer.concat([len(4, len(4, uint(1, 1))), len(5, len(3, ev))]))
}
const ownedList = (gate) => len(1, len(100, structOf([['data', structOf([['gate_id', strVal(gate)], ['variant', structOf([['@variant', strVal('UnlimitedPass')]])]])]])))

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
/** A random 32-byte transaction digest in base58 (the form the proof carries). */
export function txDigest() {
  let n = BigInt('0x' + [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join(''))
  let s = ''
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n }
  return s.padStart(43, '1')
}

/**
 * A fullnode stub. `consumes` maps a digest to the sender that made it; `owners` is the set of
 * addresses that own a pass. `paused` pauses the gate. Counts calls per method.
 */
export async function startFullnode() {
  const state = { paused: false, consumes: new Map(), owners: new Set(), calls: [], failAll: false, consumeAgeMs: 1000, gate: GATE_ID }
  const server = http.createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      state.calls.push(req.url)
      const body = Buffer.concat(chunks)
      res.setHeader('content-type', 'application/grpc-web+proto')
      if (state.failAll) { res.statusCode = 500; return res.end() }
      if (req.url.endsWith('LedgerService/GetObject')) return res.end(grpc(gateObject(state.paused, true)))
      if (req.url.endsWith('LedgerService/GetTransaction')) {
        // The digest is the first string field of the request (field 1, after the 5-byte frame header).
        const msg = body.subarray(5)
        const digest = msg.subarray(2, 2 + msg[1]).toString()
        const sender = state.consumes.get(digest)
        if (!sender) { res.setHeader('grpc-status', '5'); return res.end() } // NOT_FOUND (trailers-only)
        return res.end(grpc(consumeTx(sender, state.gate, state.consumeAgeMs)))
      }
      if (req.url.endsWith('StateService/ListOwnedObjects')) {
        const owner = body.toString('latin1').match(/0x[0-9a-f]{64}/)?.[0]
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
