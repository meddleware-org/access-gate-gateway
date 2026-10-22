# @meddleware/nft-gate-gateway

[![npm](https://img.shields.io/npm/v/%40meddleware%2Fnft-gate-gateway)](https://www.npmjs.com/package/@meddleware/nft-gate-gateway)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

> **Superseded, pending cutover (0.0.27).** The standing rule is no JS/TS backend code, so this Worker is being replaced 1:1 by the Rust Worker
> [`../worker`](../worker/README.md) (same Worker name, Durable Object class and schema). The Rust Worker is built and tested, with a differential run against this one;
> it is not yet deployed. **This package stays the live deployment and the rollback until the maintainer has shadow-deployed the Rust Worker, read its CPU-time p99/p99.9, and cut over**
> (runbook below), and is retired after a clean week. It is not deleted. Do not add features here; change the core and the Rust Worker.
>
> **Runbook (maintainer).** 1. Actions → *Deploy Worker (Rust)* → `mode=shadow` (a different Worker name, its own empty Durable Object namespace, workers.dev). 2. `cd integrations/paywall && node run.mjs --relay <shadow origin>`.
> 3. Workers analytics for the shadow: **CPU time p99 ≤ 5 ms and p99.9 ≤ 10 ms over a week of real traffic on Free.** 4. *Deploy Worker (Rust)* → `mode=cutover`, `confirm=cutover` (same name, class and migration tag: the live
> nonce, rate and redemption data are kept). 5. Rollback = *Deploy Workers* (this package) at the last TypeScript tag. 6. Retire this package. Details: [`../worker/README.md`](../worker/README.md) "Runbook".

Cloudflare Workers implementation of the [nft-gate](../README.md) NFT-gated reverse proxy.
Wire-identical to the [Rust gateway](../gateway-rust/): same routes, status codes, proof format,
Sui RPC calls, and env-var names. Deploy it at the same URL the Rust gateway serves and nothing
else changes.

## Prerequisites

| Tool | Minimum version | Install |
| --- | --- | --- |
| Node.js | 22.x | [nodejs.org](https://nodejs.org) |
| npm | 10.x | bundled with Node |
| Wrangler | 4.x | `npm install -g wrangler` |
| Cloudflare account | — | [dash.cloudflare.com](https://dash.cloudflare.com) |

## Getting started

### 1. Get the source

Clone or fork the repo, then work from the `gateway-workers/` directory:

```bash
git clone https://github.com/meddleware-org/nft-gate.git
cd nft-gate/gateway-workers
npm install
```

Alternatively, the package is published to npm for reference:

```bash
npm install @meddleware/nft-gate-gateway
```

### 2. Configure `wrangler.toml`

Edit the `[[routes]]` stanza to bind the Worker to your hostname:

```toml
[[routes]]
pattern = "gate.example.com/*"
zone_name = "example.com"
```

The default `[vars]` block already contains safe defaults for all optional settings. Review
`SUI_RPC_URL` and change it to your preferred Sui fullnode:

| Network | Public fullnode URL |
| --- | --- |
| Mainnet | `https://fullnode.mainnet.sui.io:443` |
| Testnet | `https://fullnode.testnet.sui.io:443` |

### 3. Create the Worker (first deploy)

```bash
npm run deploy
```

Wrangler creates the Worker and the Durable Object namespace in your account. The Worker will
respond to requests immediately but will return errors until the required secrets are set.

### 4. Set required secrets

Run these once from the `gateway-workers/` directory after the Worker exists:

```bash
# The upstream origin the Worker proxies to.
wrangler secret put UPSTREAM_URL
# Value: https://your-relay.example.com

# The pass type (NFT_TYPE), the gate (GATE_ID) and the RPC URL (SUI_RPC_URL) are public values:
# set them in wrangler.toml [vars], e.g.
#   NFT_TYPE = "0x<ACCESS_GATE_ORIGINAL_ID>::access_gate::SoulboundAccessNFT"

# CF Access service-token headers to authenticate to your origin (if Access-locked).
# Omit if your upstream is publicly reachable or uses another auth mechanism.
wrangler secret put UPSTREAM_AUTH_HEADERS
# Value (JSON): [{"name":"CF-Access-Client-Id","value":"<id>"},{"name":"CF-Access-Client-Secret","value":"<secret>"}]
```

Secrets are encrypted at rest and never appear in `wrangler.toml` or workflow logs. They survive
`wrangler deploy` — setting them once is sufficient.

### 5. Verify

```bash
curl https://gate.example.com/v1/challenge
# → {"nonce":"...","expiresAt":...}
```

Any gated route without a valid proof token returns `401 Unauthorized`.

## Upstream reachability

The Rust gateway usually runs **inside** your network and reaches a private upstream directly.
This Worker runs at Cloudflare's **edge**, so `UPSTREAM_URL` must be **publicly routable**.

**Recommended pattern**: expose your upstream via a dedicated `cloudflared` public hostname
locked to this Worker via Cloudflare Access, then point `UPSTREAM_URL` at it.

Every upstream request carries `Via: 1.1 nft-gate` (any `Via` the client sent is dropped). A request
that arrives already carrying it has looped back to the gateway (the upstream hostname resolves to
this route) and gets `508 {"error":"loop detected"}` before any work; other `Via` values, such as a
CDN's `1.1 google`, pass.

**Single-use failure outcomes.** If the upstream answers 2xx but the redemption commit then fails,
the client gets `502` and the consume is released, so it can be redeemed again: the user may upload
twice (bounded by the lease TTL and the per-upload limits) but never loses a paid use.

### Locking the origin with a Cloudflare Access service token

1. Cloudflare Zero Trust → Access → Service Tokens → **Create Service Token**.
2. Create an Access **application** for your relay hostname (e.g. `relay.example.com`).
3. Add a policy: allow requests where **Service Token** is the token you just created.
4. Set the Worker secret — both token headers, as a JSON array (a malformed value makes the
   gateway fail closed with `500 gateway misconfigured` until it is fixed):

   ```bash
   wrangler secret put UPSTREAM_AUTH_HEADERS
   # [{"name":"CF-Access-Client-Id","value":"<id>"},{"name":"CF-Access-Client-Secret","value":"<secret>"}]
   ```

   Alternatively store the same JSON as the GitHub secret `UPSTREAM_AUTH_HEADERS` and deploy with
   the `Deploy Workers` workflow: it validates the value and ships it with the code as one
   version. While that GitHub secret exists it overrides the Cloudflare value on every workflow
   deploy, so rotate it in GitHub.

5. The Worker injects these headers on every upstream `fetch`. Direct browser or bot traffic to
   the origin gets an Access login page or `403`, depending on the policy fallback.
6. Verify the lock stays in place. `Deploy Workers` checks that the origin **accepts** the token
   (repository variable `UPSTREAM_CHECK_URL`); the `Origin lock` workflow
   (`.github/workflows/origin-lock.yml`, daily and on demand) checks the opposite with
   `scripts/check-origin-locked.mjs`: GET requests without a token, and with an unknown one, must be
   refused by Access (401/403 with `cf-access-domain`, or a redirect to the Access login). It sends no
   secret. A run fails when the origin answers, or is refused by anything other than Access.

## State backend

Single-use nonces and per-address rate limits need atomicity that a stateless isolate cannot
provide. Two backends are available:

| Backend | Binding | Consistency | Plan |
| --- | --- | --- | --- |
| `durable-object` (default) | `NONCE_STATE` (auto-created) | Strong — atomic single-use consume | Free tier |
| `kv` | `NONCE_KV` (create manually) | Eventual — weak cross-region replay window in `SINGLE_USE=false` | Free tier |

To use the KV backend, create a namespace and uncomment the binding in `wrangler.toml`:

```bash
wrangler kv namespace create NONCE_KV
# Copy the returned ID into wrangler.toml:
# [[kv_namespaces]]
# binding = "NONCE_KV"
# id = "<returned-id>"
```

Then set `NONCE_BACKEND = "kv"` in `[vars]`.

## Request body limit

`MAX_BODY_BYTES` is enforced twice, without buffering the body:

1. **Declared length.** A `Content-Length` above the cap gets `413 {"error":"request body too large"}`
   before the upstream is contacted.
2. **Streamed bytes.** Every body passes through a byte counter. A body with no declared length
   (`Transfer-Encoding: chunked`) that crosses the cap aborts the upstream request and gets the
   same `413`. Bodies within the cap are forwarded unchanged, still `Content-Length`-framed when the
   client declared one.

The **effective limit is the lower of `MAX_BODY_BYTES` and the zone's Cloudflare plan limit** on
request bodies (Free/Pro 100 MB, Business 200 MB, Enterprise configurable up to 5 GB — see
[Workers limits](https://developers.cloudflare.com/workers/platform/limits/#request-and-response-limits)).
The deployed value is `100000000` (10⁸ B, the Free/Pro "100 MB", which is decimal), so a too-large
upload gets the gateway's own JSON `413` with CORS headers rather than Cloudflare's page (through 0.0.24 it
was `104857600`, 100 MiB, so bodies between 10⁸ and 1.048 × 10⁸ B got the platform's `413` first).
The body limit follows the **zone's** plan and does not change when the account moves from Workers Free
to Workers Paid. Raising `MAX_BODY_BYTES` has no effect beyond the zone limit. Keep the relay origin's own
cap (e.g. `nginx.org/client-max-body-size` on its ingress) at least as large, so the gateway, not the
origin, is the binding limit.

The Rust gateway enforces the same cap with the same status codes (see
[`gateway-rust`](../gateway-rust/README.md)).

## Full configuration reference

| Var | Required | Default | Notes |
| --- | --- | --- | --- |
| `UPSTREAM_URL` | ✓ | — | Base URL of the protected upstream (set via `wrangler secret put`) |
| `GATEWAY_ORIGIN` | ✓ | — | This gateway's canonical public origin (`https://host`, no path, lower-case); signed into every proof (`nft-gate:access:v2`), so a proof made for another gateway is useless here (`wrangler.toml` `[vars]`) |
| `NETWORK` | ✓ | — | `localnet` \| `devnet` \| `testnet` \| `mainnet`; signed into every proof, and labels the RPC client |
| `SUI_RPC_URL` | ✓ | `https://fullnode.testnet.sui.io:443` | Sui fullnode (queried over gRPC-web); change to mainnet for production |
| `NFT_TYPE` | ✓ | — | `<pkg>::access_gate::AccessNFT` or `SoulboundAccessNFT`, with `<pkg>` the access_gate original id (a `[vars]` entry in `wrangler.toml`); any other type — e.g. a fungible `Coin<T>` — is rejected at startup |
| `GATE_ID` | ✓ | — | The gate whose passes are accepted; also read live so a paused gate with `pause_blocks_access` denies holders (`403 the gate is paused`) |
| `SINGLE_USE` | | `false` | Require a `consumeDigest` naming a successful `access_gate::consume` by the proof address on `GATE_ID`; each digest is redeemable once |
| `PUBLIC_PATHS` | | `/v1/tip-config` | Comma-separated paths served without authentication |
| `RATE_LIMIT_PER_MIN` | | `30` | Requests per verified address per 60s window (`0` disables) |
| `MAX_BODY_BYTES` | | `262144` | Request body cap (256 KiB); `wrangler.toml` sets `100000000` (10⁸ B, the Free/Pro zone limit) for Walrus uploads. See [Request body limit](#request-body-limit) |
| `CHALLENGE_TTL_SECS` | | `300` | Nonce lifetime in seconds |
| `OWNERSHIP_CACHE_TTL_MS` | | `0` | Ownership-check cache TTL (`0` = live check on every request) |
| `NONCE_BACKEND` | | `durable-object` | `durable-object` or `kv` |
| `NONCE_SHARD` | | `region` | DO shard granularity: `region` (near users) or `global` (one instance) |
| `NONCE_MAX_ENTRIES` | | `1000000` | Hard nonce entry cap per DO shard (evict oldest when reached) |
| `UPSTREAM_AUTH_HEADERS` | | — | JSON array `[{"name":…,"value":…}]` of headers injected on every upstream request (secret); invalid JSON fails closed |
| `CHALLENGE_RATE_LIMIT_PER_MIN` | | `30` | Per-client-IP budget for `GET /v1/challenge` (0 disables) |
| `SUI_RPC_AUTH_HEADER` | | — | `Name: value` header added to Sui RPC calls (secret, for authenticated nodes) |
| `QUOTA_GUARD_ENABLED` | | `false` | Enable the scheduled quota guard (never moves single-use redemptions off the Durable Object) |
| `WORKERS_PLAN` | | `free` | The account's Workers plan, `free` or `paid`: selects the quota guard's allowances. See [Switch to Workers Paid](#switch-to-workers-paid) |
| `ALLOWED_ORIGINS` | | none | Comma-separated canonical browser origins granted CORS (`wrangler.toml` lists Meddleware's apps; an unset value grants none) |
| `UPSTREAM_TIMEOUT_SECS` | | `600` | Total deadline for one upstream exchange (request body and response); `504` past it |
| `RPC_TIMEOUT_SECS` | | `15` | Deadline for each Sui RPC read |
| `GATED_PREAUTH_RATE_LIMIT_PER_MIN` | | `120` | Per-client-IP budget for gated requests, checked **before** signature verification (`0` disables) |
| `REDEMPTION_LEASE_TTL_SECS` | | `900` | Single-use lease; must exceed `UPSTREAM_TIMEOUT_SECS` (checked at startup) |
| `REDEMPTION_RETENTION_SECS` | | `2592000` | How long a spent consume is remembered |
| `CONSUME_MAX_AGE_SECS` | | `432000` | Oldest accepted consume (5 days, inside public fullnodes' transaction retention); at most the retention |

Every value is validated at startup: a boolean must be exactly `true`/`false`, numbers are integers
within bounds, origins must be canonical, and `SINGLE_USE=true` is refused with `NONCE_BACKEND=kv`
(KV's lease is not atomic). A bad value is a `500 gateway misconfigured`, never a weaker mode.

Vars listed in `wrangler.toml` are overwritten on every `wrangler deploy`. Values that must
survive deployments (credentials, contract addresses) must be set with `wrangler secret put`.

## Local development

```bash
npm run dev          # wrangler dev — local Worker runtime with DO + KV stubs
npm test             # Vitest in the workerd runtime (tests DO, KV, crypto, routing)
npm run type-check   # tsc --noEmit
```

## Optional: quota guard

Off by default (`QUOTA_GUARD_ENABLED = "false"`). When enabled with a cron trigger, `src/quota.ts`
reads the account's usage from the Cloudflare GraphQL Analytics API and compares it with the
allowances of the plan named by `WORKERS_PLAN` (Cloudflare docs, checked 2026-10-19):

| `WORKERS_PLAN` | Window | Worker requests | Worker CPU | DO requests | DO duration | Past the allowance |
| --- | --- | --- | --- | --- | --- | --- |
| `free` (default) | day (00:00 UTC) | 100,000 | 10 ms per request (no account allowance) | 100,000 | 13,000 GB-s | requests fail (Worker error 1027, DO calls throw) |
| `paid` | UTC calendar month | 10,000,000 | 30,000,000 ms | 1,000,000 | 400,000 GB-s | billed as overage |

DO duration is computed as active seconds × 0.128 GB (128 MB per object, as in Cloudflare's billing
examples). The guard logs a warning at 80% of any allowance. On `free` it also sets a KV `quota:degrade`
flag at 95%, which only an ownership-mode deployment honours (it then prefers the KV nonce backend);
`SINGLE_USE=true` ignores the flag, so redemptions never leave the Durable Object. On `paid` it only
warns and clears any flag left from Free. A GraphQL error is logged as a failed check, never read as zero
usage. The live deployment is single-use, so for it the guard is a log-only early warning.

To enable it (operator steps; none of them is in the repository):

1. Create a Cloudflare API token with **Account Analytics: Read** only, for the one account, with an
   expiry; `wrangler secret put CF_ANALYTICS_TOKEN` and `wrangler secret put CF_ACCOUNT_ID`.
2. Optional, ownership mode only: `wrangler kv namespace create NONCE_KV` and uncomment the
   `[[kv_namespaces]]` block with the returned id (single-use never reads the flag).
3. Uncomment the cron trigger in `wrangler.toml` and set `QUOTA_GUARD_ENABLED = "true"`:

   ```toml
   [triggers]
   crons = ["*/15 * * * *"]
   ```

4. Deploy, then read the `quota-guard:` lines in the Worker's logs after the first trigger.

Cloudflare's own usage notifications and budget alerts (dashboard → Notifications) cover the same ground
without a token in the Worker; prefer them where they suffice.

## Switch to Workers Paid

Mainnet launches on **Workers Free**. Switch to **Workers Paid** on funding, or when trailing platform
revenue covers Paid for two consecutive months (the trigger in the infrastructure workspace's
`docs/economics/COST_MODEL.md` §5, tracked in its `OPERATOR_TASKS.md`). Nothing in the code depends on the
plan; the switch is configuration only:

1. **Before:** read the gateway's CPU time from Workers analytics (dashboard → the Worker → Metrics →
   CPU time, or `workersInvocationsAdaptive` `quantiles { cpuTimeP50 cpuTimeP99 }` filtered by
   `scriptName`) and the count of `exceededCpu` outcomes. Note p99.
2. **Dashboard:** Workers & Pages → Plans → purchase Workers Paid (US$5/month minimum) for the account.
   Confirm the Worker route still uses **Fail closed** (Workers Routes), so a limit refusal never bypasses
   the Worker.
3. **`wrangler.toml`:** set `WORKERS_PLAN = "paid"` and uncomment the `[limits]` block
   (`cpu_ms = 50`, the denial-of-wallet ceiling; raise it only if step 1's p99 is close to it).
   `MAX_BODY_BYTES` stays `100000000`: the body limit follows the zone plan, not the Workers plan.
4. **Deploy:** commit, then run the `Deploy Workers` workflow (`production` environment).
5. **Verify:** `GET /v1/challenge` and `GET /v1/tip-config` answer 200; a gated upload succeeds; after a
   day, Workers analytics shows no `exceededCpu` outcomes and CPU p99 well under `cpu_ms`; the
   dashboard's billing page shows the Paid subscription. If the quota guard is enabled, its next log line
   names the Paid monthly allowances.

To go back to Free: reverse steps 2–3 (set `WORKERS_PLAN = "free"` and comment `[limits]` out again;
custom CPU limits are a Paid-plan setting).

### CPU budget on Free

Free allows 10 ms CPU per request. A gated request does one signature verification plus JSON and stream
handling. `test/cpu-bench.test.ts` (workerd) and `test/cpu-bench.node.test.ts` (Node) time
`verifyPersonalMessageSignature` on the shared vectors; on the maintainer's machine (Intel i5-7400,
2026-10-19) a warm verification took about 1.1–1.4 ms (ed25519, secp256k1) and 2.1 ms (secp256r1) of
wall time in local workerd, and the first verification in a fresh isolate (curve set-up and JIT) up to
~36 ms. workerd exposes no CPU clock, so these are wall times of a synchronous loop, not the edge's CPU
accounting; Node's process CPU time for the same code is higher (2.1–4.2 ms warm) because it counts every
thread of the test process. Cloudflare tolerates an occasional request over the limit, so the cold first
verification is a risk to watch, not a measured failure: after each deploy, read CPU p99 and
`exceededCpu` in Workers analytics. A p99 near 10 ms on Free is a launch blocker until the switch above.

## Module layout

> This Worker is being replaced by a Rust Worker (workers-rs) built on `nft-gate-core`, the decision logic that `gateway-rust` already shares
> (status: in progress; see the repository `CLAUDE.md` and `core/README.md`). It stays the live deployment and the rollback until a measured cutover.

| Module | Rust analog (`core/src` is shared; `gateway-rust/src` is the adapter) | Role |
| --- | --- | --- |
| `src/index.ts` | `core/src/gateway.rs` + `gateway-rust/src/main.rs` | Request router (challenge / public / gated paths) |
| `src/config.ts` | `core/src/config.rs` | `env` → typed config (same var names as Rust) |
| `src/wire.ts` | `core/src/proof.rs` | Proof helpers reused from `@meddleware/nft-gate-client` |
| `src/responses.ts` | `core/src/gateway.rs` (`JsonReply`, `denied_reply`) | The gateway's own answers (status + `{ error, code? }`), pinned by the shared `responses` vectors |
| `src/verify.ts` | `core/src/decision.rs`, `sig.rs` | Signature verification + allow/deny decision |
| `src/chain.ts` | `core/src/chain.rs`, `grpc.rs` | Sui gRPC ownership and consume-event queries |
| `src/proxy.ts` | `gateway-rust/src/proxy.rs` + `core/src/forward.rs`, `headers.rs` | Body-capped reverse proxy; strips `Host`/`Authorization` |
| `src/state/` | `core/src/state.rs`, `redemption.rs` | Pluggable nonce store and rate limiter |
| `src/quota.ts` | — | Optional plan-aware quota guard (scheduled cron; `WORKERS_PLAN`) |
