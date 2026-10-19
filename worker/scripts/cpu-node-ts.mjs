// Same CPU measurement as cpu-node.cjs, for the existing TypeScript Worker's verification path: a scratch
// Worker (see docs/SPIKE-FINDINGS.md: a scratch Worker outside the repo) whose /bench?scheme= calls gateway-workers' verifyPersonalMessageSignature over the
// shared vectors and reports thread/process CPU around the verification calls, bundled by
// `wrangler deploy --dry-run --outdir`. Module load CPU is measured outside, as in the Rust harness.
//   node scripts/cpu-node-ts.mjs <bundle.js> [iterations]
const [, , bundle, itersArg] = process.argv
const iters = Number(itersArg ?? 500)
const th = () => { const u = process.threadCpuUsage(); return (u.user + u.system) / 1000 }
const pr = () => { const u = process.cpuUsage(); return (u.user + u.system) / 1000 }
const both = () => [th(), pr()]
const diff = (a) => { const b = both(); return { thread: +(b[0] - a[0]).toFixed(2), process: +(b[1] - a[1]).toFixed(2) } }
const t0 = both()
const mod = (await import(new URL(bundle, `file://${process.cwd()}/`).href)).default
const load = diff(t0)
for (let i = 0; i < 220; i++) await mod.fetch(new Request('http://x/healthz'))
const out = { loadCompileInstantiateCpuMs: load, first: {}, warmMean: {} }
const schemes = ['ed25519', 'secp256k1', 'secp256r1', 'ed25519 single-use']
const call = async (s, iters, warmup) => (await mod.fetch(new Request(`http://x/bench?scheme=${encodeURIComponent(s)}&iters=${iters}&warmup=${warmup}`))).json()
for (const s of schemes) {
  const r = await call(s, 1, 0)
  out.first[s] = { thread: +r.thread.toFixed(2), process: +r.process.toFixed(2) }
}
for (const s of schemes) {
  await call(s, 50, 50)
  const r = await call(s, iters, 0)
  out.warmMean[s] = { thread: +r.thread.toFixed(3), process: +r.process.toFixed(3) }
}
console.log(JSON.stringify(out))
