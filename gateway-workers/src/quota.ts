/**
 * OPTIONAL quota guard (off by default; `QUOTA_GUARD_ENABLED=true` plus a cron trigger). Cloudflare
 * exposes account **usage** through the GraphQL Analytics API but **not** the account's limit values,
 * so this compares usage with the published allowances of the plan named by `WORKERS_PLAN`:
 *
 * - `free` (default): the Workers Free **daily** limits, which reset at 00:00 UTC and fail requests
 *   once exceeded (Worker requests answer error 1027; Durable Object calls throw).
 * - `paid`: the Workers Paid **monthly** included amounts; beyond them usage is billed as overage,
 *   nothing fails.
 *
 * The limits below were checked against the Cloudflare docs on 2026-10-19
 * (developers.cloudflare.com/workers/platform/limits/, …/workers/platform/pricing/ and
 * …/durable-objects/platform/pricing/); re-check them when the plan changes.
 *
 * It (a) logs a warning as usage approaches an allowance and (b) on Free only, can set a KV
 * `quota:degrade` flag that ownership-mode deployments honour to prefer the KV nonce backend before
 * the Durable Object limit bites. Single-use deployments ignore the flag (redemptions never leave the
 * Durable Object; `getState` in `index.ts`), so this guard can never weaken single-use. It never
 * pre-pays or maintains a balance; it needs only a read-only Analytics API token.
 */

import { WORKERS_PLANS, type Env, type WorkersPlan } from './config.js'

/** One plan's allowances. A meter that is `undefined` has no account-wide allowance on that plan. */
export interface PlanLimits {
  /** `day`: resets at 00:00 UTC (Free). `month`: the UTC calendar month (Paid billing period approximation). */
  window: 'day' | 'month'
  /** `true` when exceeding an allowance fails requests (Free); `false` when it is billed (Paid). */
  hardLimit: boolean
  workerRequests: number
  /** Worker CPU milliseconds. Free has only a per-request cap (10 ms), no account-wide allowance. */
  workerCpuMs?: number
  doRequests: number
  doGbSeconds: number
}

/** Published plan allowances (Cloudflare docs, checked 2026-10-19). */
export const PLAN_LIMITS: Readonly<Record<WorkersPlan, Readonly<PlanLimits>>> = {
  // Workers Free: 100,000 requests/day; Durable Objects 100,000 requests/day and 13,000 GB-s/day.
  free: { window: 'day', hardLimit: true, workerRequests: 100_000, doRequests: 100_000, doGbSeconds: 13_000 },
  // Workers Paid: 10M requests and 30M CPU-ms a month; Durable Objects 1M requests and 400,000 GB-s a month.
  paid: {
    window: 'month',
    hardLimit: false,
    workerRequests: 10_000_000,
    workerCpuMs: 30_000_000,
    doRequests: 1_000_000,
    doGbSeconds: 400_000,
  },
}

/** Log a warning when usage reaches this fraction of any allowance. */
export const WARN_AT = 0.8
/** On a plan with hard limits, set the KV degrade flag at this fraction of any allowance. */
export const DEGRADE_AT = 0.95
/**
 * Durable Object duration is billed at 128 MB per active object: GB-s = active seconds × 128 MB / 1 GB
 * (the Durable Objects pricing examples use exactly this factor).
 */
export const DO_GB_PER_ACTIVE_SECOND = 0.128

/** Cloudflare GraphQL Analytics API endpoint. */
const GRAPHQL_URL = 'https://api.cloudflare.com/client/v4/graphql'

/** Account-wide usage since the start of the plan's window. */
export interface Usage {
  /** Worker invocations (`workersInvocationsAdaptive.sum.requests`). */
  workerRequests: number
  /** Worker CPU time in ms (`workersInvocationsAdaptive.sum.cpuTimeUs` ÷ 1000). */
  workerCpuMs: number
  /** Durable Object requests, RPC calls included (`durableObjectsInvocationsAdaptiveGroups.sum.requests`). */
  doRequests: number
  /** Durable Object duration in GB-s (`durableObjectsPeriodicGroups.sum.activeTime` µs → s × 0.128). */
  doGbSeconds: number
}

/** The result of comparing {@link Usage} with a plan's {@link PlanLimits}. */
export interface QuotaAssessment {
  plan: WorkersPlan
  /** Usage ÷ allowance per metered dimension (only the dimensions the plan meters). */
  ratios: Partial<Record<keyof Usage, number>>
  /** The largest ratio. */
  worst: number
  warn: boolean
  /** Set the degrade flag (only on a plan with hard limits). */
  degrade: boolean
}

/**
 * Parse `WORKERS_PLAN` exactly as `loadConfig` does: `free` when unset, else `free` or `paid`.
 *
 * @throws If the value is anything else (a typo must not select the wrong allowances).
 */
export function parseWorkersPlan(raw: string | undefined): WorkersPlan {
  if (raw === undefined) return 'free'
  if ((WORKERS_PLANS as readonly string[]).includes(raw)) return raw as WorkersPlan
  throw new Error(`WORKERS_PLAN must be one of ${WORKERS_PLANS.join(', ')}`)
}

/**
 * Start of the current usage window in UTC: today 00:00 for a daily plan, the 1st 00:00 for a monthly one.
 *
 * @param plan - The Workers plan.
 * @param now - The current time.
 */
export function windowStart(plan: WorkersPlan, now: Date): Date {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()))
  if (PLAN_LIMITS[plan].window === 'month') d.setUTCDate(1)
  return d
}

/**
 * Compare usage with the plan's allowances.
 *
 * @param usage - Usage since {@link windowStart}.
 * @param plan - The Workers plan.
 */
export function assessUsage(usage: Usage, plan: WorkersPlan): QuotaAssessment {
  const limits = PLAN_LIMITS[plan]
  const ratios: Partial<Record<keyof Usage, number>> = {
    workerRequests: usage.workerRequests / limits.workerRequests,
    doRequests: usage.doRequests / limits.doRequests,
    doGbSeconds: usage.doGbSeconds / limits.doGbSeconds,
  }
  if (limits.workerCpuMs !== undefined) ratios.workerCpuMs = usage.workerCpuMs / limits.workerCpuMs
  const worst = Math.max(...Object.values(ratios))
  return { plan, ratios, worst, warn: worst >= WARN_AT, degrade: limits.hardLimit && worst >= DEGRADE_AT }
}

/**
 * Run the optional quota guard. Reads usage for the plan's window from the Cloudflare GraphQL
 * Analytics API, logs a warning near an allowance, and on Free sets (or clears) the KV
 * `quota:degrade` flag. On Paid it only warns (exceeding an included amount is billed, not refused)
 * and clears a flag left from Free.
 *
 * @param env - Worker environment bindings. Requires `CF_ANALYTICS_TOKEN` and `CF_ACCOUNT_ID`;
 *   reads `WORKERS_PLAN`; optionally uses `NONCE_KV` for the degrade flag.
 * @param now - The current time (injectable for tests).
 * @returns The assessment, or `undefined` when the guard could not run. Never rejects: errors are
 *   logged and suppressed.
 */
export async function runQuotaGuard(env: Env, now: Date = new Date()): Promise<QuotaAssessment | undefined> {
  let plan: WorkersPlan
  try {
    plan = parseWorkersPlan(env.WORKERS_PLAN)
  } catch (e) {
    console.warn('quota-guard:', (e as Error).message, '; skipping')
    return undefined
  }
  if (!env.CF_ANALYTICS_TOKEN || !env.CF_ACCOUNT_ID) {
    console.warn('quota-guard: CF_ANALYTICS_TOKEN / CF_ACCOUNT_ID not set; skipping')
    return undefined
  }
  let usage: Usage
  try {
    usage = await fetchUsage(env.CF_ANALYTICS_TOKEN, env.CF_ACCOUNT_ID, windowStart(plan, now))
  } catch (e) {
    console.warn('quota-guard: usage query failed:', (e as Error).message)
    return undefined
  }

  const a = assessUsage(usage, plan)
  if (a.warn) {
    const parts = Object.entries(a.ratios).map(([k, r]) => `${k} ${(r * 100).toFixed(0)}%`)
    const what = PLAN_LIMITS[plan].hardLimit ? 'of a Workers Free daily limit' : 'of a Workers Paid monthly included amount (overage is billed beyond it)'
    console.warn(`quota-guard: usage at ${(a.worst * 100).toFixed(0)}% ${what} (${parts.join(', ')})`)
  }
  // Dormant unless a NONCE_KV binding exists (wrangler.toml ships it commented out).
  if (env.NONCE_KV) {
    try {
      if (a.degrade) {
        await env.NONCE_KV.put('quota:degrade', '1', { expirationTtl: 3600 })
        console.warn('quota-guard: set KV degrade flag (ownership mode prefers KV; single-use ignores it)')
      } else {
        await env.NONCE_KV.delete('quota:degrade')
      }
    } catch (e) {
      console.warn('quota-guard: KV degrade-flag update failed:', (e as Error).message)
    }
  }
  return a
}

type SumRow = { sum?: { requests?: number; cpuTimeUs?: number; activeTime?: number } }

/**
 * Fetch account-wide Workers and Durable Object usage since `since`.
 *
 * @param token - Read-only Cloudflare Analytics API token.
 * @param accountId - Cloudflare account ID (`CF_ACCOUNT_ID`).
 * @param since - Window start (00:00 UTC).
 * @throws If the HTTP response is not OK or the API reports a GraphQL error (an unknown field must not
 *   read as zero usage).
 */
async function fetchUsage(token: string, accountId: string, since: Date): Promise<Usage> {
  const query = `query($accountTag: String!, $since: Time!, $sinceDate: Date!) {
    viewer { accounts(filter: { accountTag: $accountTag }) {
      workersInvocationsAdaptive(limit: 10000, filter: { datetime_geq: $since }) { sum { requests cpuTimeUs } }
      durableObjectsInvocationsAdaptiveGroups(limit: 10000, filter: { date_geq: $sinceDate }) { sum { requests } }
      durableObjectsPeriodicGroups(limit: 10000, filter: { date_geq: $sinceDate }) { sum { activeTime } }
    } }
  }`
  const resp = await fetch(GRAPHQL_URL, {
    signal: AbortSignal.timeout(15_000),
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      query,
      variables: { accountTag: accountId, since: since.toISOString(), sinceDate: since.toISOString().slice(0, 10) },
    }),
  })
  if (!resp.ok) throw new Error(`graphql http ${resp.status}`)
  const json = (await resp.json()) as {
    data?: { viewer?: { accounts?: Array<Record<string, SumRow[] | undefined>> } } | null
    errors?: Array<{ message?: string }> | null
  }
  if (json.errors && json.errors.length > 0) {
    throw new Error(`graphql error: ${json.errors.map((e) => e.message ?? '?').join('; ')}`)
  }
  const acct = json.data?.viewer?.accounts?.[0]
  if (!acct) throw new Error('graphql response has no account')
  const total = (rows: SumRow[] | undefined, key: 'requests' | 'cpuTimeUs' | 'activeTime'): number =>
    (rows ?? []).reduce((n, r) => n + (r.sum?.[key] ?? 0), 0)
  return {
    workerRequests: total(acct.workersInvocationsAdaptive, 'requests'),
    workerCpuMs: total(acct.workersInvocationsAdaptive, 'cpuTimeUs') / 1000,
    doRequests: total(acct.durableObjectsInvocationsAdaptiveGroups, 'requests'),
    doGbSeconds: (total(acct.durableObjectsPeriodicGroups, 'activeTime') / 1_000_000) * DO_GB_PER_ACTIVE_SECOND,
  }
}
