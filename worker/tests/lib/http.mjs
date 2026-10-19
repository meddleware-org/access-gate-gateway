// Exact control over what goes on the wire (header casing, odd paths, chunked bodies), which fetch hides.
import http from 'node:http'

/**
 * @param {string} base
 * @param {{method?:string, path:string, headers?:Record<string,string|string[]>, body?:Buffer|string|Iterable<Buffer>|AsyncIterable<Buffer>|null, timeoutMs?:number}} o
 */
export function rawRequest(base, { method = 'GET', path, headers = {}, body = null, timeoutMs = 30_000 }) {
  const url = new URL(base)
  return new Promise((resolve, reject) => {
    const req = http.request({ host: url.hostname, port: url.port, method, path, headers, timeout: timeoutMs, agent: false }, (res) => {
      const chunks = []
      res.on('data', (c) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, rawHeaders: res.rawHeaders, body: Buffer.concat(chunks) }))
      res.on('error', reject)
    })
    req.on('error', reject)
    req.on('timeout', () => req.destroy(new Error('timeout')))
    if (body === null || typeof body === 'string' || Buffer.isBuffer(body)) req.end(body ?? undefined)
    else (async () => { try { for await (const c of body) if (!req.write(c)) await new Promise((r) => req.once('drain', r)); req.end() } catch (e) { req.destroy(e) } })()
  })
}

/** A body of `total` bytes delivered in `chunk`-byte pieces, as an async iterable (no Content-Length ⇒ chunked). */
export async function* chunked(total, chunk = 400, fill = 0x61) {
  let sent = 0
  while (sent < total) {
    const n = Math.min(chunk, total - sent)
    sent += n
    yield Buffer.alloc(n, fill)
    await new Promise((r) => setImmediate(r))
  }
}

/** Deterministic payload of `n` bytes. */
export const payload = (n) => Buffer.from(Uint8Array.from({ length: n }, (_, i) => i % 251))
