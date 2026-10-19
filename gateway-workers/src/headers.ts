/**
 * Header policy for a forwarding hop (RFC 9110 §7.6.1). Hop-by-hop fields describe one connection,
 * not the message, so they are removed in both directions: the fixed set plus every field the
 * `Connection` header names. Forwarding and credential fields a client could use to spoof the hop
 * are removed from the request, and the gateway's own are set.
 */

/** Fields that are hop-by-hop by definition. */
const HOP_BY_HOP = [
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]

/**
 * The `Via` entry (RFC 9110 §7.6.3) this gateway adds to every upstream request. A request that
 * arrives already carrying it has looped back to the gateway (F43), whichever hostname it took.
 */
export const VIA_TOKEN = '1.1 nft-gate'

/**
 * True if `headers` already carry this gateway's own `Via` entry. Only the received-by name
 * `nft-gate` matches: any other value (e.g. a CDN's `1.1 google`) is foreign and passes. Each
 * comma-separated entry is `protocol received-by [comment]`; a comment is not examined.
 */
export function isLooped(headers: Headers): boolean {
  const via = headers.get('via')
  if (!via) return false
  return via.split(',').some((entry) => entry.trim().split(/\s+/)[1]?.toLowerCase() === 'nft-gate')
}

/** Client-supplied fields the gateway never forwards: credentials for the gate, spoofable forwarding data, cookies. */
const REQUEST_STRIP = [
  'host',
  'authorization',
  'x-access-proof',
  'content-length',
  'cookie',
  'forwarded',
  'via',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-real-ip',
]

/** Upstream fields the gateway never returns: cookies, and CORS (the gateway emits its own from its allowlist). */
const RESPONSE_STRIP = ['content-length', 'set-cookie', 'set-cookie2', 'alt-svc']

/** Remove the hop-by-hop fields, including those named in `Connection`, from `headers` in place. */
export function stripHopByHop(headers: Headers): void {
  const named = (headers.get('connection') ?? '')
    .split(',')
    .map((t) => t.trim().toLowerCase())
    .filter((t) => t.length > 0)
  for (const name of [...HOP_BY_HOP, ...named]) headers.delete(name)
}

/** The headers to send upstream: the client's, minus hop-by-hop, credentials and spoofable fields. */
export function upstreamRequestHeaders(incoming: Headers, injected: Array<{ name: string; value: string }>): Headers {
  const headers = new Headers(incoming)
  stripHopByHop(headers)
  for (const name of REQUEST_STRIP) headers.delete(name)
  // The upstream's own access credentials are the gateway's alone: drop anything the client sent in
  // that namespace before setting the configured ones.
  for (const name of [...headers.keys()]) if (name.startsWith('cf-access-')) headers.delete(name)
  for (const { name, value } of injected) headers.set(name, value)
  // The gateway's own hop marker, set after the client's `via` was dropped (F43).
  headers.set('via', VIA_TOKEN)
  return headers
}

/** The headers to return to the client: the upstream's, minus hop-by-hop, cookies and every CORS field. */
export function clientResponseHeaders(upstream: Headers): Headers {
  const headers = new Headers(upstream)
  stripHopByHop(headers)
  for (const name of RESPONSE_STRIP) headers.delete(name)
  for (const name of [...headers.keys()]) if (name.startsWith('access-control-')) headers.delete(name)
  return headers
}

/** True if `path` is safe to append to the upstream URL: no encoded separators, NUL, backslash or empty segments. */
export function isSafePath(path: string): boolean {
  if (/%2f|%5c|%00|%2e%2e/i.test(path) || path.includes('\\') || /[\u0000-\u001f\u007f]/.test(path)) return false
  return !path.includes('//')
}
