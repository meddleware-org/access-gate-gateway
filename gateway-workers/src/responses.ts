/**
 * The answers the gateway generates itself: status plus the JSON body `{ "error", "code"? }` of the
 * response contract in `@meddleware/access-gate-gateway-client` (`contract.ts`). One definition per outcome, used
 * by the router and by the redemption flow, so the shared `responses` conformance vectors
 * (`conformance/vectors.json`) can be checked against the real answers (`test/conformance.test.ts`).
 * Mirror of `JsonReply` and `denied_reply` in `access-gate-gateway-core` (`gateway.rs`).
 *
 * Kept out of the Worker entry module, which may only export the fetch/scheduled handlers and Durable
 * Object classes.
 */

import type { Denied } from './verify.js'
import { deniedReason } from './verify.js'

/**
 * A JSON `{"error": reason}` response with the given status, optionally with a stable
 * machine-readable `code` (e.g. `"redeemed"` vs `"leased"`) so the client can react precisely.
 *
 * @param status - HTTP status code.
 * @param reason - Short, client-visible error description.
 * @param code - Optional stable code for programmatic handling.
 */
export function deny(status: number, reason: string, code?: string): Response {
  return new Response(JSON.stringify(code ? { error: reason, code } : { error: reason }), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

/** 401: no access proof on a gated path. */
export const missingProof = (): Response => deny(401, 'missing access proof')

/** 429: a rate budget is spent. */
export const rateLimited = (): Response => deny(429, 'rate limit exceeded')

/** 503: the gateway's own state store cannot answer (never reported as a conflict). */
export const stateUnavailable = (): Response => deny(503, 'gateway state unavailable')

/** 508: the request already carries this gateway's `Via` marker. */
export const loopDetected = (): Response => deny(508, 'loop detected')

/** 405, with an `Allow` header on a public path. */
export function methodNotAllowed(allow?: string): Response {
  const res = deny(405, 'method not allowed')
  if (allow) res.headers.set('allow', allow)
  return res
}

/** A refused proof: 502 when the chain lookup failed, otherwise 403 with the denial's reason. */
export function deniedResponse(denied: Denied): Response {
  return deny(denied === 'ChainError' ? 502 : 403, deniedReason(denied))
}
