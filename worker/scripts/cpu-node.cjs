// Native CPU time of the SAME wasm under Node/V8.
//   wasm-bindgen --target nodejs <nft_gate_spike_worker.wasm> --out-dir <dir>   (+ wasm-opt -O; see README)
//   node scripts/cpu-node.cjs <dir>/nft_gate_spike_worker.js [iterations]
// Fresh process per invocation. Two clocks, both user+system:
//   thread  = process.threadCpuUsage(): the main (request) thread only. This is the closest analogue of what a
//             per-request CPU limit meters (work done on the thread that runs the request).
//   process = process.cpuUsage(): all threads, including V8's background Turbofan tier-up compiles, which run
//             concurrently and do NOT block the request. An upper bound.
// Reports: (1) loading+compiling+instantiating the module, (2) the FIRST verification of each scheme in the
// process (after the Node-side Request/Response paths are warmed with /healthz so they are not billed to it),
// (3) warm mean over `iterations`. Node's wasm engine is V8 (Liftoff, then Turbofan), as in workerd.
const [, , glue, itersArg] = process.argv
const iters = Number(itersArg ?? 500)
const th = () => { const u = process.threadCpuUsage(); return (u.user + u.system) / 1000 }
const pr = () => { const u = process.cpuUsage(); return (u.user + u.system) / 1000 }
const both = () => [th(), pr()]
const diff = (a) => { const b = both(); return { thread: +(b[0] - a[0]).toFixed(2), process: +(b[1] - a[1]).toFixed(2) } }
const t0 = both()
const w = require(require('node:path').resolve(glue))
const load = diff(t0)
const ctx = { waitUntil() {}, passThroughOnException() {} }
const call = async (q) => (await w.fetch(new Request('http://x' + q), {}, ctx)).json()
;(async () => {
  for (let i = 0; i < 220; i++) await w.fetch(new Request('http://x/healthz'), {}, ctx)
  const out = { loadCompileInstantiateCpuMs: load, first: {}, warmMean: {} }
  const schemes = ['ed25519', 'secp256k1', 'secp256r1', 'ed25519 single-use']
  for (const s of schemes) {
    const a = both()
    await call(`/bench?scheme=${encodeURIComponent(s)}&iters=1&warmup=0`)
    out.first[s] = diff(a)
  }
  for (const s of schemes) {
    await call(`/bench?scheme=${encodeURIComponent(s)}&iters=200&warmup=50`) // tier up
    const a = both()
    await call(`/bench?scheme=${encodeURIComponent(s)}&iters=${iters}&warmup=0`)
    const d = diff(a)
    out.warmMean[s] = { thread: +(d.thread / iters).toFixed(3), process: +(d.process / iters).toFixed(3) }
  }
  console.log(JSON.stringify(out))
})()
