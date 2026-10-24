// Startup validation seen from outside: a bad variable never leaks detail, never takes /healthz or the
// CORS preflight down, and always answers the JSON + CORS shape. (The rules themselves are the core's
// `config` tests; this proves the Worker wires them and fails closed.)
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { fixture, nextIp } from './lib/fixture.mjs'
import { ALLOWED_ORIGIN } from './lib/worker.mjs'

async function with_(vars, fn, opts = {}) {
  const f = await fixture({ name: 'cfg', vars, ...opts })
  try { await fn(f) } finally { await f.close() }
}

const misconfigured = async (f, { cors = false } = {}) => {
  const res = await f.call('GET', '/v1/challenge', { origin: ALLOWED_ORIGIN, 'CF-Connecting-IP': nextIp() })
  assert.equal(res.status, 500)
  assert.deepEqual(await res.json(), { error: 'gateway misconfigured' })
  // No config means no allow-list: no ACAO, but the static grants and Vary are still there.
  // (A missing Durable Object binding is found after the config loaded, so there the allow-list is known.)
  assert.equal(res.headers.get('access-control-allow-origin'), cors ? ALLOWED_ORIGIN : null)
  assert.match(res.headers.get('vary'), /Origin/)
  assert.match(res.headers.get('access-control-allow-methods'), /GET/)
  // /healthz and the preflight do not depend on the config; the 508 guard does not either.
  assert.equal((await f.call('GET', '/healthz')).status, 200)
  assert.equal((await f.call('OPTIONS', '/v1/challenge', { origin: ALLOWED_ORIGIN })).status, 204)
  assert.equal((await f.call('GET', '/v1/challenge', { via: '1.1 access-gate-gateway' })).status, 508)
}

describe('misconfiguration fails closed', () => {
  for (const [name, vars] of [
    ['an invalid NFT_TYPE (a fungible coin)', { NFT_TYPE: '0x2::coin::Coin<0x2::sui::SUI>' }],
    ['an unknown NETWORK', { NETWORK: 'moonnet' }],
    ['a non-canonical GATEWAY_ORIGIN', { GATEWAY_ORIGIN: 'https://GW.example.com/' }],
    ['an upstream that is the gateway itself (request loop)', { UPSTREAM_URL: 'https://gw.example.com' }],
    ['a typo in a boolean (SINGLE_USE=yes)', { SINGLE_USE: 'yes' }],
    ['a negative number', { RATE_LIMIT_PER_MIN: '-1' }],
    ['NONCE_BACKEND=kv (not carried over)', { NONCE_BACKEND: 'kv' }],
    ['an unknown WORKERS_PLAN', { WORKERS_PLAN: 'pro' }],
    ['a lease that does not outlive the upload deadline', { REDEMPTION_LEASE_TTL_SECS: '30', UPSTREAM_TIMEOUT_SECS: '600' }],
    ['the retired UPSTREAM_AUTH_HEADERS "Name: value" format', { UPSTREAM_AUTH_HEADERS: 'CF-Access-Client-Id: abc' }],
    ['a malformed SUI_RPC_AUTH_HEADER', { SUI_RPC_AUTH_HEADER: 'Bearer tok' }],
    ['an ALLOWED_ORIGINS entry that is not an origin', { ALLOWED_ORIGINS: 'https://a.example/path' }],
  ]) {
    it(name, async () => with_(vars, misconfigured))
  }

  it('a missing Durable Object binding is a 500 gateway misconfigured', async () => {
    const f = await fixture({ name: 'cfg-nodo', dropDo: true })
    try { await misconfigured(f, { cors: true }) } finally { await f.close() }
  })

  it('a missing required variable is a 500 (UPSTREAM_URL is a secret and may be unset)', async () => {
    const f = await fixture({ name: 'cfg-noup', vars: { UPSTREAM_URL: '' } })
    try { await misconfigured(f) } finally { await f.close() }
  })

  it('http:// URLs need the explicit ALLOW_INSECURE_HTTP opt-in (stricter than the TypeScript Worker)', async () => {
    await with_({ ALLOW_INSECURE_HTTP: '0' }, misconfigured)
  })
})
