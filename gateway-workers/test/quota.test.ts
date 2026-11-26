// Tests of the quota guard (src/quota.ts) of the TypeScript Workers gateway: the plan allowances, the usage window, the assessment and the
// scheduled handler against a stubbed analytics API. The Rust twin is core/src/quota.rs.
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Env } from '../src/config.js'
import {
  assessUsage,
  DO_GB_PER_ACTIVE_SECOND,
  parseWorkersPlan,
  PLAN_LIMITS,
  runQuotaGuard,
  windowStart,
  type Usage,
} from '../src/quota.js'

// A usage window with nothing used.
const zero: Usage = { workerRequests: 0, workerCpuMs: 0, doRequests: 0, doGbSeconds: 0 }

describe('plan allowances (Cloudflare docs, 2026-10-19)', () => {
  it('Free: daily, hard limits, no account-wide CPU allowance', () => {
    expect(PLAN_LIMITS.free).toEqual({
      window: 'day',
      hardLimit: true,
      workerRequests: 100_000,
      doRequests: 100_000,
      doGbSeconds: 13_000,
    })
  })
  it('Paid: monthly included amounts, billed beyond', () => {
    expect(PLAN_LIMITS.paid).toEqual({
      window: 'month',
      hardLimit: false,
      workerRequests: 10_000_000,
      workerCpuMs: 30_000_000,
      doRequests: 1_000_000,
      doGbSeconds: 400_000,
    })
  })
})

// `free` by default; only `free` or `paid` are accepted.
describe('parseWorkersPlan', () => {
  it('defaults to free and accepts exactly free or paid', () => {
    expect(parseWorkersPlan(undefined)).toBe('free')
    expect(parseWorkersPlan('free')).toBe('free')
    expect(parseWorkersPlan('paid')).toBe('paid')
    for (const bad of ['Paid', 'pro', '']) expect(() => parseWorkersPlan(bad)).toThrow(/WORKERS_PLAN/)
  })
})

// The Free plan's window is the day; the paid plan's is the month.
describe('windowStart', () => {
  const now = new Date('2026-10-19T17:42:05.123Z')
  it('Free: today 00:00 UTC', () => {
    expect(windowStart('free', now).toISOString()).toBe('2026-10-19T00:00:00.000Z')
  })
  it('Paid: the 1st of the month 00:00 UTC', () => {
    expect(windowStart('paid', now).toISOString()).toBe('2026-10-01T00:00:00.000Z')
  })
})

// Usage against the allowances: which meters apply to which plan, and when a warning is due.
describe('assessUsage', () => {
  it('Free: Worker and DO requests are separate meters (not summed)', () => {
    const a = assessUsage({ ...zero, workerRequests: 60_000, doRequests: 60_000 }, 'free')
    expect(a.ratios.workerRequests).toBeCloseTo(0.6)
    expect(a.ratios.doRequests).toBeCloseTo(0.6)
    expect(a.warn).toBe(false)
    expect(a.degrade).toBe(false)
  })
  // The Free plan's CPU allowance is per request, which the analytics cannot meter.
  it('Free: CPU is not an account-wide meter', () => {
    const a = assessUsage({ ...zero, workerCpuMs: 1e12 }, 'free')
    expect(a.ratios.workerCpuMs).toBeUndefined()
    expect(a.worst).toBe(0)
  })
  // Two thresholds: a warning, then a switch to the cheaper nonce path.
  it('Free: warns at 80% and degrades at 95% of any meter', () => {
    // 10,400 of 13,000 GB-s is 80 %.
    expect(assessUsage({ ...zero, doGbSeconds: 10_400 }, 'free')).toMatchObject({ warn: true, degrade: false })
    // 95,000 of 100,000 requests is 95 %.
    expect(assessUsage({ ...zero, doRequests: 95_000 }, 'free')).toMatchObject({ warn: true, degrade: true })
  })
  // On the paid plan going over costs money but breaks nothing, so there is nothing to degrade to.
  it('Paid: meters CPU, warns, and never degrades (overage is billed, nothing fails)', () => {
    // 29 million of the 30 million CPU milliseconds included.
    const a = assessUsage({ ...zero, workerCpuMs: 29_000_000 }, 'paid')
    expect(a.ratios.workerCpuMs).toBeCloseTo(29 / 30)
    expect(a.warn).toBe(true)
    expect(a.degrade).toBe(false)
    expect(assessUsage({ ...zero, doRequests: 5_000_000 }, 'paid').degrade).toBe(false)
  })
})

/** A GraphQL response with one row per dataset. */
function gql(w: { requests: number; cpuTimeUs: number }, doReq: number, activeTimeUs: number): Response {
  // A response shaped like Cloudflare's analytics API.
  return Response.json({
    data: {
      viewer: {
        accounts: [
          {
            workersInvocationsAdaptive: [{ sum: w }],
            durableObjectsInvocationsAdaptiveGroups: [{ sum: { requests: doReq } }],
            durableObjectsPeriodicGroups: [{ sum: { activeTime: activeTimeUs } }],
          },
        ],
      },
    },
  })
}

/** A KV binding that records its writes. */
function kvSpy() {
  // The guard's only write is the degrade flag in KV.
  return { put: vi.fn(async () => undefined), delete: vi.fn(async () => undefined), get: vi.fn() }
}

/** The test environment with these values added. */
function env(extra: Partial<Env>): Env {
  // Placeholder credentials: the analytics API is a stub.
  return { CF_ANALYTICS_TOKEN: 't', CF_ACCOUNT_ID: 'a', ...extra } as unknown as Env
}

// The scheduled handler end to end, with a stubbed analytics API.
describe('runQuotaGuard', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })
  const now = new Date('2026-10-19T12:00:00Z')

  it('Free (default): queries since today 00:00 UTC, converts DO active time to GB-s, sets the degrade flag near a limit', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const fetchMock = vi.fn(async () => gql({ requests: 1_000, cpuTimeUs: 0 }, 96_000, 1_000_000_000))
    vi.stubGlobal('fetch', fetchMock)
    const kv = kvSpy()
    const a = await runQuotaGuard(env({ NONCE_KV: kv as unknown as KVNamespace }), now)
    expect(a?.plan).toBe('free')
    expect(a?.ratios.doGbSeconds).toBeCloseTo((1_000 * DO_GB_PER_ACTIVE_SECOND) / 13_000)
    expect(a?.degrade).toBe(true)
    expect(kv.put).toHaveBeenCalledWith('quota:degrade', '1', { expirationTtl: 3600 })
    const body = JSON.parse((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body as string)
    expect(body.variables.since).toBe('2026-10-19T00:00:00.000Z')
    expect(body.variables.sinceDate).toBe('2026-10-19')
  })

  it('Paid: queries since the 1st, meters CPU, warns, never sets the flag (clears a stale one)', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const fetchMock = vi.fn(async () => gql({ requests: 9_000_000, cpuTimeUs: 29_000_000_000 }, 999_000, 0))
    vi.stubGlobal('fetch', fetchMock)
    const kv = kvSpy()
    const a = await runQuotaGuard(env({ WORKERS_PLAN: 'paid', NONCE_KV: kv as unknown as KVNamespace }), now)
    expect(a?.plan).toBe('paid')
    expect(a?.ratios.workerCpuMs).toBeCloseTo(29 / 30)
    expect(a?.warn).toBe(true)
    expect(a?.degrade).toBe(false)
    expect(kv.put).not.toHaveBeenCalled()
    expect(kv.delete).toHaveBeenCalledWith('quota:degrade')
    expect(warn.mock.calls.some((c) => String(c[0]).includes('Workers Paid monthly included amount'))).toBe(true)
    const body = JSON.parse((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].body as string)
    expect(body.variables.since).toBe('2026-10-01T00:00:00.000Z')
  })

  it('a GraphQL error is a failed check, never zero usage', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ data: null, errors: [{ message: 'unknown field cpuTimeUs' }] })))
    const kv = kvSpy()
    expect(await runQuotaGuard(env({ NONCE_KV: kv as unknown as KVNamespace }), now)).toBeUndefined()
    expect(kv.delete).not.toHaveBeenCalled()
    expect(kv.put).not.toHaveBeenCalled()
  })

  it('skips without credentials, and on an invalid WORKERS_PLAN, without querying', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    expect(await runQuotaGuard({} as Env, now)).toBeUndefined()
    expect(await runQuotaGuard(env({ WORKERS_PLAN: 'pro' }), now)).toBeUndefined()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('never rejects on an HTTP failure', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => undefined)
    vi.stubGlobal('fetch', vi.fn(async () => new Response('no', { status: 500 })))
    await expect(runQuotaGuard(env({}), now)).resolves.toBeUndefined()
  })
})
