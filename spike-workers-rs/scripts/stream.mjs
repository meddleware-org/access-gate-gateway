// Item 4: streaming proxy with a byte cap and no buffering, under workerd (`wrangler dev`).
//   node scripts/stream.mjs http://127.0.0.1:8799 [mib=90]
// A local upstream consumes the body without keeping it. Evidence reported:
//   - bytes the upstream received, and when its first byte arrived relative to the client's last (streaming),
//   - workerd's resident-set before / peak (VmHWM) / after, and the wasm linear memory size from /mem,
//   - the 413 behaviours: declared Content-Length over the cap (immediate) and a chunked body that crosses the cap.
import http from 'node:http'
import fs from 'node:fs'
import { execFileSync } from 'node:child_process'
import assert from 'node:assert/strict'

const base = process.argv[2] ?? 'http://127.0.0.1:8799'
const mib = Number(process.argv[3] ?? 90)
const prefix = process.env.PROXY_PREFIX ?? '/proxy'
const CAP = Number(process.env.CAP ?? 100_000_000) // MAX_BODY_BYTES (wrangler.toml)
const pids = () => execFileSync('pgrep', ['-x', 'workerd']).toString().trim().split('\n')
const mem = () => {
  let rss = 0, hwm = 0
  for (const p of pids()) {
    const s = fs.readFileSync(`/proc/${p}/status`, 'utf8')
    rss += Number(/VmRSS:\s+(\d+)/.exec(s)[1]); hwm += Number(/VmHWM:\s+(\d+)/.exec(s)[1])
  }
  return { rssMiB: +(rss / 1024).toFixed(1), peakMiB: +(hwm / 1024).toFixed(1) }
}

let rec = { bytes: 0, firstAt: 0, lastAt: 0, method: '', headers: {} }
const upstream = http.createServer((req, res) => {
  rec = { bytes: 0, firstAt: 0, lastAt: 0, method: req.method, headers: req.headers }
  req.on('data', (c) => { if (!rec.firstAt) rec.firstAt = performance.now(); rec.bytes += c.length })
  req.on('end', () => { rec.lastAt = performance.now(); res.setHeader('set-cookie', 'a=b'); res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ received: rec.bytes })) })
  req.on('error', () => {})
}).listen(18080, '127.0.0.1')
await new Promise((r) => upstream.on('listening', r))

const chunk = Buffer.alloc(1 << 20, 0x61)
const body = (total) => new ReadableStream({
  start() { this.sent = 0 },
  async pull(c) {
    if (this.sent >= total) return c.close()
    const n = Math.min(chunk.length, total - this.sent); this.sent += n
    c.enqueue(chunk.subarray(0, n))
    await new Promise((r) => setImmediate(r)) // a real, paced client, not one giant write
  },
})
const wasm = async () => (await (await fetch(`${base}/mem`)).json()).wasmMemoryBytes
const send = async (total, extra = {}) => {
  const t0 = performance.now()
  const r = await fetch(`${base}${prefix}/v1/upload?x=1`, { method: 'PUT', body: body(total), duplex: 'half', headers: { 'content-type': 'application/octet-stream', cookie: 'secret=1', 'x-access-proof': 'p', ...extra } })
  const text = await r.text()
  return { status: r.status, text, ms: performance.now() - t0, setCookie: r.headers.get('set-cookie') }
}

console.log('baseline', mem(), 'wasmMemoryBytes', await wasm())
const total = mib * 1024 * 1024
const a = await send(total) // chunked (no content-length): the cap is enforced by the counter
console.log(`chunked ${mib} MiB:`, a.status, a.text.slice(0, 80), `${a.ms.toFixed(0)} ms`, JSON.stringify(mem()), 'wasmMemoryBytes', await wasm())
assert.equal(a.status, 200); assert.equal(JSON.parse(a.text).received, total)
assert.equal(rec.headers['via'], '1.1 nft-gate'); assert.equal(rec.headers['cookie'], undefined); assert.equal(rec.headers['x-access-proof'], undefined)
assert.equal(a.setCookie, null, 'upstream set-cookie stripped')
console.log(`  upstream saw first byte ${(rec.firstAt - (rec.lastAt - 0)).toFixed(0)} ms relative to its last byte; streaming window ${(rec.lastAt - rec.firstAt).toFixed(0)} ms`)

// with a declared Content-Length: re-framed through FixedLengthStream (upstream sees a length, not chunked)
const t1 = performance.now()
const b = await (await fetch(`${base}${prefix}/v1/upload`, { method: 'PUT', headers: { 'content-length': String(total) }, body: body(total), duplex: 'half' }).catch((e) => ({ err: e }))).text?.()
console.log('content-length', mib, 'MiB ->', b, `${(performance.now() - t1).toFixed(0)} ms`, 'upstream content-length header:', rec.headers['content-length'], 'transfer-encoding:', rec.headers['transfer-encoding'])
console.log('after both', mem(), 'wasmMemoryBytes', await wasm())

// over the cap, chunked: 413 once the counter crosses MAX_BODY_BYTES
const c = await send(CAP + 1024 * 1024)
console.log('chunked over cap:', c.status, c.text, `${c.ms.toFixed(0)} ms`, 'upstream received', rec.bytes, 'bytes (cap', CAP + ')')
assert.equal(c.status, 413)
// over the cap, declared (Content-Length known): refused up front, nothing reaches the upstream.
rec.bytes = 0
const dres = await fetch(`${base}${prefix}/v1/upload`, { method: 'PUT', body: Buffer.alloc(CAP + 1024, 0x61) }).then(async (r) => `${r.status} ${await r.text()}`, (e) => `client error: ${e.message}`)
console.log('declared over cap:', dres, '| upstream bytes:', rec.bytes)
console.log('final', mem(), 'wasmMemoryBytes', await wasm())
upstream.close()
