import { startFullnode, startUpstream } from './stubs.mjs'
import { baseVars, startWorker } from './worker.mjs'

/**
 * One Worker under wrangler dev with a stub upstream and a stub fullnode.
 * @param {object} [o]
 * @param {Record<string,string>} [o.vars] overrides (strings), applied over wrangler.toml and baseVars
 * @param {'prod'|'hooks'} [o.build]
 * @param {object} [o.upstream] startUpstream options
 * @param {string|null} [o.upstreamUrl] override UPSTREAM_URL (null: leave the stub's)
 */
export async function fixture({ vars = {}, build = 'prod', upstream: uo = {}, upstreamUrl, name = 'f', scheduled = false, dropDo = false } = {}) {
  const rpc = await startFullnode()
  const up = await startUpstream(uo)
  const w = await startWorker({
    build,
    name,
    scheduled,
    dropDo,
    vars: baseVars({ UPSTREAM_URL: upstreamUrl ?? up.url, SUI_RPC_URL: rpc.url, ...vars }),
  })
  return {
    w,
    up,
    rpc,
    base: w.base,
    /** A request to the Worker. */
    call: (method, path, headers = {}, init = {}) => fetch(w.base + path, { method, headers, redirect: 'manual', ...init }),
    async close() { await w.stop(); await up.close(); await rpc.close() },
  }
}

let ip = 0
/** A fresh documentation-range client address, so rate budgets never bleed between tests. */
export const nextIp = () => `198.51.${100 + Math.floor(ip / 250)}.${(ip++ % 250) + 1}`
