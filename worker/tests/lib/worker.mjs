// Start a Worker under `wrangler dev` (workerd) for the black-box suites, from a config generated out
// of the REAL wrangler.toml (so a var added or changed there is what the tests run with), with explicit
// overrides. Test code only: nothing here is Worker logic.
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import { parse } from 'smol-toml'

export const WORKER_DIR = path.resolve(import.meta.dirname, '../..')
const WRANGLER = path.join(WORKER_DIR, 'node_modules/.bin/wrangler')

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// Ports handed out in this process. The OS may give the same port to two callers that probe at the same
// time (the probe socket is closed before wrangler binds it), which made two `wrangler dev` starts in
// parallel collide intermittently; never hand the same port out twice.
const handedOut = new Set()

export async function freePort() {
  for (let attempt = 0; attempt < 50; attempt++) {
    const port = await new Promise((resolve, reject) => {
      const s = net.createServer()
      s.once('error', reject)
      s.listen(0, '127.0.0.1', () => {
        const { port: p } = s.address()
        s.close(() => resolve(p))
      })
    })
    if (!handedOut.has(port)) {
      handedOut.add(port)
      return port
    }
  }
  throw new Error('could not find a free port that was not already handed out')
}

// Every child we spawn, so a suite that fails in a `before` hook cannot leave workerd running: an orphan
// keeps the test process alive until the CI job times out.
const live = new Set()
const killAll = () => { for (const c of live) { try { c.kill('SIGKILL') } catch { /* gone */ } } }
process.on('exit', killAll)
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { killAll(); process.exit(1) })

/** Where `worker-build` put each build variant (see tests/build.sh). */
export const BUILDS = {
  prod: path.join(WORKER_DIR, 'build'),
  hooks: path.join(WORKER_DIR, 'build-hooks'),
}

export const GATE_ID = '0x316f1bf9764db352e925bb598aff44ea77be4ab652f0bd2eb3fdcc0a378faddc'
export const NFT_PKG = '0xd7ddaa94b74330979b2b618fc81206d160a264f1c9ca148a77fa2144301388c9'
export const ALLOWED_ORIGIN = 'https://allowed.example.com'

/** The vars the suites run with on top of wrangler.toml's. */
export function baseVars(extra = {}) {
  return {
    GATEWAY_ORIGIN: 'https://gw.example.com',
    NETWORK: 'testnet',
    ALLOW_INSECURE_HTTP: '1',
    ALLOWED_ORIGINS: `${ALLOWED_ORIGIN},https://sui-walrus-storage.meddleware.co.uk`,
    ...extra,
  }
}

/**
 * @param {object} o
 * @param {'prod'|'hooks'} [o.build] which Rust build to run
 * @param {Record<string,string>} o.vars overrides on top of wrangler.toml [vars]
 * @param {string} [o.main] run an arbitrary prebuilt entry instead (the TypeScript Worker, for the differential)
 * @param {string} [o.config] a wrangler.toml to derive from (default: this crate's)
 * @param {boolean} [o.scheduled] pass --test-scheduled
 */
export async function startWorker({ build = 'prod', vars, main, config, scheduled = false, name = 'w', dropDo = false, healthPath = '/healthz' }) {
  const toml = parse(fs.readFileSync(config ?? path.join(WORKER_DIR, 'wrangler.toml'), 'utf8'))
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `nft-gate-${name}-`))
  const cfg = {
    name: `nft-gate-test-${name}`,
    main: main ?? path.join(BUILDS[build], 'index.js'),
    compatibility_date: toml.compatibility_date,
    compatibility_flags: toml.compatibility_flags ?? [],
    vars: { ...toml.vars, ...vars },
    durable_objects: dropDo ? undefined : toml.durable_objects,
    migrations: dropDo ? undefined : toml.migrations,
  }
  // The suites exercise the Worker, not the zone routes or the deploy-time build step.
  const cfgPath = path.join(main ? path.dirname(path.resolve(main)) : BUILDS[build], `.wrangler-test-${name}.json`)
  fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2))
  const port = await freePort()
  const args = [
    'dev', '-c', cfgPath, '--ip', '127.0.0.1', '--port', String(port), '--inspector-port', String(await freePort()),
    '--persist-to', path.join(dir, 'state'), '--log-level', 'info',
  ]
  if (scheduled) args.push('--test-scheduled')
  const child = spawn(WRANGLER, args, {
    cwd: path.dirname(cfgPath),
    env: { ...process.env, CI: '1', WRANGLER_SEND_METRICS: 'false', NO_COLOR: '1', WRANGLER_LOG_PATH: path.join(dir, 'logs'), XDG_CONFIG_HOME: path.join(dir, 'xdg') },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  live.add(child)
  child.once('exit', () => live.delete(child))
  let logs = ''
  const onData = (d) => { logs += d.toString() }
  child.stdout.on('data', onData)
  child.stderr.on('data', onData)
  const base = `http://127.0.0.1:${port}`
  const deadline = Date.now() + 120_000
  for (;;) {
    if (child.exitCode !== null) { throw new Error(`wrangler dev exited (${child.exitCode}):\n${logs}`) }
    try {
      const r = await fetch(`${base}${healthPath}`, { signal: AbortSignal.timeout(2000) })
      if (r.status === 200) break
    } catch { /* not up yet */ }
    if (Date.now() > deadline) { child.kill('SIGKILL'); throw new Error(`wrangler dev did not start:\n${logs}`) }
    await sleep(250)
  }
  return {
    base,
    cfg,
    logs: () => logs,
    async stop() {
      child.kill('SIGTERM')
      await new Promise((r) => { child.once('exit', r); setTimeout(() => { child.kill('SIGKILL'); r() }, 5000) })
      fs.rmSync(dir, { recursive: true, force: true })
      fs.rmSync(cfgPath, { force: true })
    },
  }
}
