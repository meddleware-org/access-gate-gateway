// Port of gateway-workers/test/origin-lock.test.ts, "check-origin-locked.mjs" half: the script that runs
// in .github/workflows/origin-lock.yml (scripts/check-origin-locked.sh, verdicts from `nft-gate-ci`).
// The classification cases ("classifyOriginResponse") are unit-tested in ci/src/lib.rs.
import { after, before, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import path from 'node:path'
import fs from 'node:fs'
import { spawn, spawnSync } from 'node:child_process'
import { freePort } from './lib/worker.mjs'

const ROOT = path.resolve(import.meta.dirname, '../..')
const CLI = path.join(ROOT, 'target/debug/nft-gate-ci')

before(() => {
  if (!fs.existsSync(CLI)) {
    const b = spawnSync('cargo', ['build', '--quiet', '--locked', '-p', 'nft-gate-ci'], { cwd: ROOT, encoding: 'utf8' })
    assert.equal(b.status, 0, b.stderr)
  }
})

// Asynchronous: the stub origin lives in this process and must keep answering while the script runs.
function run(env, args = []) {
  return new Promise((resolve) => {
    const c = spawn('bash', [path.join(ROOT, 'scripts/check-origin-locked.sh'), ...args], {
      env: { PATH: process.env.PATH, NFT_GATE_CI: CLI, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let out = ''
    c.stdout.on('data', (d) => { out += d })
    c.stderr.on('data', (d) => { out += d })
    const t = setTimeout(() => c.kill('SIGKILL'), 90_000)
    c.on('close', (status) => { clearTimeout(t); resolve({ status, out }) })
  })
}

/** An origin stub: `answer(req)` -> [status, headers]. */
async function origin(answer) {
  const seen = []
  const server = http.createServer((req, res) => {
    seen.push({ url: req.url, headers: req.headers })
    const [status, headers] = answer(req)
    res.writeHead(status, headers)
    res.end()
  })
  const port = await freePort()
  await new Promise((r) => server.listen(port, '127.0.0.1', r))
  return { url: `http://127.0.0.1:${port}/v1/tip-config`, seen, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r) }) }
}
const test = (url) => ({ UPSTREAM_CHECK_URL: url, ORIGIN_LOCK_TEST_HTTP: '1', ORIGIN_LOCK_RETRY_SLEEP: '0' })

describe('check-origin-locked.sh', () => {
  it('fails closed when the origin URL is not configured', async () => {
    const r = await run({})
    assert.equal(r.status, 1)
    assert.match(r.out, /UPSTREAM_CHECK_URL is not set/)
  })

  it('refuses a non-https origin URL without sending anything', async () => {
    const r = await run({ UPSTREAM_CHECK_URL: 'http://origin.invalid/v1/tip-config' })
    assert.equal(r.status, 1)
    assert.match(r.out, /must be an https URL/)
  })

  it('passes when every probe is refused by Access (and sends no credential but the made-up token)', async () => {
    const o = await origin(() => [403, { 'cf-access-domain': 'origin.example' }])
    try {
      const r = await run(test(o.url))
      assert.equal(r.status, 0, r.out)
      assert.match(r.out, /Origin lock holds/)
      assert.equal(o.seen.length, 3)
      assert.equal(o.seen[2].headers['cf-access-client-id'], `${'0'.repeat(32)}.access`)
      assert.equal(o.seen[0].headers['cf-access-client-id'], undefined)
      assert.equal(o.seen[1].url, '/') // the root probe
    } finally { await o.close() }
  })

  it('passes on a redirect to the Access login', async () => {
    const o = await origin(() => [302, { location: 'https://team.cloudflareaccess.com/cdn-cgi/access/login/x?kid=1' }])
    try { assert.equal((await run(test(o.url))).status, 0) } finally { await o.close() }
  })

  it('fails when the origin answers a request without the token, or refuses for another reason', async () => {
    for (const [status, headers] of [[200, {}], [403, { server: 'cloudflare' }], [404, {}], [502, {}]]) {
      const o = await origin(() => [status, headers])
      try {
        const r = await run(test(o.url))
        assert.equal(r.status, 1, `${status}: ${r.out}`)
        assert.match(r.out, /::error::Origin lock check failed/)
      } finally { await o.close() }
    }
  })

  it('warns, but does not fail, when the zone challenges the runner', async () => {
    let n = 0
    const o = await origin(() => (n++ === 0 ? [403, { 'cf-mitigated': 'challenge' }] : [403, { 'cf-access-domain': 'origin.example' }]))
    try {
      const r = await run(test(o.url))
      assert.equal(r.status, 0, r.out)
      assert.match(r.out, /::warning::1 of 3 probes were challenged/)
    } finally { await o.close() }
  })

  it('fails when the origin cannot be reached', async () => {
    const r = await run(test('http://127.0.0.1:1/v1/tip-config'))
    assert.equal(r.status, 1)
    assert.match(r.out, /request failed after 3 attempts/)
  })
})
