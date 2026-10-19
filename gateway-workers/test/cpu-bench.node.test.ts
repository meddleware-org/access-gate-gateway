import { describe, expect, it } from 'vitest'
import { benchSchemes, FREE_CPU_MS_PER_REQUEST, report } from './bench.js'

// The same code path in Node, measured with process CPU time (`process.cpuUsage`, user + system µs):
// a real CPU-time figure for the verification code, on this machine's CPU and Node's V8.
describe('CPU micro-benchmark per signature scheme (Node CPU time, F11)', () => {
  it('reports CPU per verification and stays well inside the Free 10 ms per-request CPU limit', () => {
    const cpuMs = () => {
      const u = process.cpuUsage()
      return (u.user + u.system) / 1000
    }
    const results = benchSchemes(cpuMs)
    report('node cpu', results)
    for (const r of results) expect(r.warmMeanMs).toBeLessThan(FREE_CPU_MS_PER_REQUEST)
  })
})
