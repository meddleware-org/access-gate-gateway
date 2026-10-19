import { describe, expect, it } from 'vitest'
import { benchSchemes, FREE_CPU_MS_PER_REQUEST, report } from './bench.js'

// Runs inside workerd (the same V8 and the same bundle as production). workerd exposes no CPU clock to
// the Worker; `performance.now()` is wall time with ~1 ms resolution (frozen between I/O on the edge,
// advancing locally). A synchronous loop with no I/O is single-threaded, so its wall time is close to
// its CPU time on this machine — an estimate for the 10 ms Free limit, not the edge's CPU accounting.
// The authoritative figure is the CPU-time percentile in Workers analytics after a deploy.
describe('CPU micro-benchmark per signature scheme (workerd, F11)', () => {
  it('reports the time per verification and stays well inside the Free 10 ms per-request CPU limit', () => {
    const results = benchSchemes(() => performance.now())
    report('workerd wall', results)
    expect(new Set(results.map((r) => r.scheme.split(' ')[0]))).toEqual(new Set(['ed25519', 'secp256k1', 'secp256r1']))
    for (const r of results) expect(r.warmMeanMs).toBeLessThan(FREE_CPU_MS_PER_REQUEST)
  })
})
