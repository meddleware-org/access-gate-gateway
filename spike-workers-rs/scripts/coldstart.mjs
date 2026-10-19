// Cold-start / first-verification measurement under real workerd, one fresh workerd process per sample.
//   node scripts/coldstart.mjs rust <dir with index.js + index_bg.wasm> [samples]
//   node scripts/coldstart.mjs ts   <esbuild bundle .js>                [samples]
//   env WORKERD=<path to workerd> (default: gateway-workers/node_modules/@cloudflare/workerd-linux-64/bin/workerd)
//
// Method and its limits: workerd exposes no CPU clock to a Worker. Per sample we spawn workerd and report
//   spawnToListenMs  process start until the TCP port accepts (workerd + config load),
//   firstReqMs       wall time of the first request (GET /healthz) after the port opens: isolate creation,
//                    module compile/instantiate (wasm) or parse/evaluate (JS) and dispatch,
//   benchMs          wall time of the requests that perform the FIRST verification of each scheme,
//   repeatMs         the same request when warm,
// plus the in-Worker performance.now() deltas (first/warm per scheme; ~1 ms resolution locally).
// Includes loopback HTTP and process effects, so compare rust vs ts on the same machine; do not read the
// absolute figures as the Free plan's 10 ms CPU budget.
import { spawn } from 'node:child_process'
import net from 'node:net'
import path from 'node:path'
import fs from 'node:fs'
import os from 'node:os'

const [, , kind, target, samplesArg] = process.argv
const samples = Number(samplesArg ?? 15)
const workerd = process.env.WORKERD ?? path.resolve(import.meta.dirname, '../../gateway-workers/node_modules/@cloudflare/workerd-linux-64/bin/workerd')
const schemes = ['ed25519', 'secp256k1', 'secp256r1', 'ed25519 single-use']
const stats = (a) => {
  const s = [...a].sort((x, y) => x - y)
  const q = (p) => s[Math.min(s.length - 1, Math.floor(p * s.length))]
  return { n: s.length, min: s[0], median: q(0.5), p90: q(0.9), max: s[s.length - 1], mean: s.reduce((x, y) => x + y, 0) / s.length }
}
const fmt = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, +v.toFixed(2)]))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function configFor(dir, port) {
  const mods = kind === 'rust'
    ? `(name = "index.js", esModule = embed "index.js"), (name = "index_bg.wasm", wasm = embed "index_bg.wasm")`
    : `(name = "entry.js", esModule = embed "entry.js")`
  const extra = kind === 'rust'
    ? `durableObjectNamespaces = [(className = "NonceRateState", uniqueKey = "spike", enableSql = true)], durableObjectStorage = (inMemory = void), bindings = [(name = "NONCE_STATE", durableObjectNamespace = "NonceRateState")],`
    : ''
  return `using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [(name = "main", worker = .w)],
  sockets = [(name = "http", address = "127.0.0.1:${port}", http = (), service = "main")]
);
const w :Workerd.Worker = (
  modules = [${mods}],
  compatibilityDate = "2026-06-01",
  ${extra}
);
`
}

async function waitPort(port, t0) {
  for (;;) {
    const ok = await new Promise((res) => { const s = net.connect(port, '127.0.0.1'); s.on('connect', () => { s.destroy(); res(true) }); s.on('error', () => res(false)) })
    if (ok) return performance.now() - t0
    await sleep(2)
  }
}

const out = { listen: [], t0: [], t1: [], t2: [], first: Object.fromEntries(schemes.map((s) => [s, []])), warm: Object.fromEntries(schemes.map((s) => [s, []])) }
for (let i = 0; i < samples; i++) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cold-'))
  if (kind === 'rust') {
    fs.symlinkSync(path.resolve(target, 'index.js'), path.join(dir, 'index.js'))
    fs.symlinkSync(path.resolve(target, 'index_bg.wasm'), path.join(dir, 'index_bg.wasm'))
  } else fs.symlinkSync(path.resolve(target), path.join(dir, 'entry.js'))
  const port = 20000 + Math.floor(Math.random() * 20000)
  fs.writeFileSync(path.join(dir, 'c.capnp'), configFor(dir, port))
  const t0 = performance.now()
  const p = spawn(workerd, ['serve', '--experimental', path.join(dir, 'c.capnp')], { cwd: dir, stdio: 'ignore' })
  out.listen.push(await waitPort(port, t0))
  const t = async (u) => { const a = performance.now(); const r = await fetch(`http://127.0.0.1:${port}${u}`); const b = await r.text(); return [performance.now() - a, b] }
  out.t0.push((await t('/healthz'))[0])
  // A: the first verification of each scheme in this fresh isolate (1 iteration, no warm-up).
  // B: warm means (200 iterations after 20 warm-up) in the same isolate.
  let t1 = 0
  if (kind === 'rust') {
    for (const s of schemes) {
      const [x, b1] = await t(`/bench?scheme=${encodeURIComponent(s)}&iters=1&warmup=0`); t1 += x
      out.first[s].push(JSON.parse(b1).firstMs)
    }
    out.t1.push(t1)
    for (const s of schemes) out.warm[s].push(JSON.parse((await t(`/bench?scheme=${encodeURIComponent(s)}&iters=200`))[1]).warmMeanMs)
    out.t2.push((await t('/bench?scheme=ed25519&iters=1&warmup=0'))[0])
  } else {
    const [x, b1] = await t('/bench?iters=1&warmup=0'); out.t1.push(x)
    for (const r of JSON.parse(b1)) out.first[r.scheme].push(r.firstMs)
    for (const r of JSON.parse((await t('/bench?iters=200&warmup=20'))[1])) out.warm[r.scheme].push(r.warmMeanMs)
    out.t2.push((await t('/bench?iters=1&warmup=0'))[0])
  }
  p.kill('SIGKILL'); await new Promise((r) => p.on('exit', r))
  fs.rmSync(dir, { recursive: true, force: true })
}
console.log(JSON.stringify({ kind, samples,
  spawnToListenMs: fmt(stats(out.listen)),
  firstRequestMs: fmt(stats(out.t0)),
  benchRequestsFirstRunMs: fmt(stats(out.t1)),
  benchRequestRepeatMs: fmt(stats(out.t2)),
  inWorkerFirstVerifyMs: Object.fromEntries(schemes.map((s) => [s, fmt(stats(out.first[s]))])),
  inWorkerWarmMeanMs: Object.fromEntries(schemes.map((s) => [s, fmt(stats(out.warm[s]))])),
}, null, 1))
