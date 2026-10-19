// Normalised records of what a client sees (and what the upstream receives), so two Workers can be
// compared field for field.

/** Response headers that legitimately differ per run or per runtime wrapper. */
const VOLATILE = new Set(['date', 'server', 'connection', 'keep-alive', 'cf-ray', 'content-encoding', 'transfer-encoding'])
/** Request headers added by the HTTP client or the runtime, not by the Worker. */
const UPSTREAM_IGNORE = new Set(['host', 'connection', 'accept', 'accept-encoding', 'accept-language', 'user-agent', 'sec-fetch-mode', 'keep-alive', 'content-length', 'transfer-encoding'])

const normText = (t) => t
  .replace(/"nonce":"([a-z]{1,2})\.[0-9a-f]{48}"/g, '"nonce":"$1.<hex48>"')
  .replace(/"expiresAt":\d+/g, '"expiresAt":<ms>')

export function headersOf(res) {
  const o = {}
  for (const [k, v] of res.headers) if (!VOLATILE.has(k) && !k.startsWith('cf-')) o[k] = v
  return o
}

/** A response, normalised: status, headers, and the body text with nonces/timestamps masked. */
export async function record(name, res) {
  const text = await res.text()
  return { name, status: res.status, headers: headersOf(res), body: normText(text) }
}

/** What the upstream received for one request: method, url, headers minus runtime noise, body size. */
export function upstreamSaw(rec) {
  const headers = {}
  for (const [k, v] of Object.entries(rec.headers)) if (!UPSTREAM_IGNORE.has(k) && !k.startsWith('cf-') && !k.startsWith('sec-')) headers[k] = v
  return { method: rec.method, url: rec.url, headers, bytes: rec.bytes, complete: rec.complete }
}

/** Compare two transcripts; returns a list of human-readable differences (empty = identical). */
export function diff(a, b) {
  const out = []
  const n = Math.max(a.length, b.length)
  for (let i = 0; i < n; i++) {
    const x = JSON.stringify(a[i] ?? null, null, 1), y = JSON.stringify(b[i] ?? null, null, 1)
    if (x !== y) out.push(`step ${i} ${a[i]?.name ?? b[i]?.name}:\n  ts  : ${x.replace(/\n\s*/g, ' ')}\n  rust: ${y.replace(/\n\s*/g, ' ')}`)
  }
  return out
}
