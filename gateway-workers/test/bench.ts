/**
 * Shared CPU micro-benchmark of the request path's signature verification (Workers audit F11):
 * per scheme, the shared conformance vector is verified through `verifyPersonalMessageSignature`
 * exactly as `verifyAccessRequest` does (base64 decode, blake2b intent digest, curve verify, address
 * derivation). `clock` is injected: workerd only offers `performance.now()` (wall time; it advances
 * locally but is coarse, ~1 ms), Node offers `process.cpuUsage()` (CPU time, µs).
 */
import vectors from '../../conformance/vectors.json'
import { verifyPersonalMessageSignature } from '../src/verify.js'
import { personalMessage } from '../src/wire.js'

export interface BenchResult {
  scheme: string
  /** The first verification of this scheme in this isolate (includes lazy curve set-up). */
  firstMs: number
  /** Mean of `iterations` warm verifications. */
  warmMeanMs: number
  iterations: number
}

/** Free plan CPU limit per HTTP request (Cloudflare docs, 2026-10-19). */
export const FREE_CPU_MS_PER_REQUEST = 10

export function benchSchemes(clockMs: () => number, iterations = 200, warmup = 20): BenchResult[] {
  return vectors.signatures.map((sig) => {
    const message = personalMessage(sig.context as Parameters<typeof personalMessage>[0])
    const verify = () => {
      if (!verifyPersonalMessageSignature(sig.address, message, sig.signature)) throw new Error(`${sig.scheme} vector failed`)
    }
    const f0 = clockMs()
    verify()
    const firstMs = clockMs() - f0
    for (let i = 0; i < warmup; i++) verify()
    const t0 = clockMs()
    for (let i = 0; i < iterations; i++) verify()
    return { scheme: sig.scheme, firstMs, warmMeanMs: (clockMs() - t0) / iterations, iterations }
  })
}

export function report(label: string, results: BenchResult[]): void {
  for (const r of results) {
    console.log(
      `cpu-bench [${label}] ${r.scheme}: first ${r.firstMs.toFixed(2)} ms, warm mean ${r.warmMeanMs.toFixed(3)} ms over ${r.iterations}`,
    )
  }
}
