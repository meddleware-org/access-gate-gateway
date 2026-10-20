# worker — the nft-gate gateway as a Cloudflare Worker, in Rust

**Status (0.0.27, 2026-10-19): built and tested; the shadow deploy has not been made.** This crate replaces the
TypeScript Worker ([`../gateway-workers`](../gateway-workers/), still the live deployment and the rollback) 1:1,
under the maintainer's standing rule of no JS/TS backend code. All decisions are the shared
[`nft-gate-core`](../core/); this crate supplies only I/O: Durable Object state, a streamed `fetch` upstream, the
gRPC-web `Transport` over `fetch`, CORS and the `scheduled` quota guard. Nothing is deployed by this repository's CI
except through the manual workflow `deploy-worker-rust.yml` (shadow first, then cutover; the maintainer runs it).

```text
worker/
  Cargo.toml          nft-gate-worker (cdylib + rlib), rust-version 1.91 (this crate only; core and gateway-rust stay at 1.88)
  wrangler.toml       cloned from gateway-workers/wrangler.toml: same name, vars, DO class NonceRateState, migration tag v1, route
  src/
    lib.rs            fetch / scheduled entry points; /healthz, CORS preflight and the 508 guard around the core
    state.rs          StateStore over the region-sharded Durable Object (key prefixes, shard routing)
    do_state.rs       the SQLite Durable Object NonceRateState (the exact schema of the TypeScript one)
    upstream.rs       Upstream: streamed fetch, byte cap, FixedLengthStream, 413/502/504, public edge cache
    transport.rs      gRPC-web Transport over fetch (SUI_RPC_AUTH_HEADER, RPC_TIMEOUT_SECS)
    config.rs         Worker-only variables on top of the core's GatewayConfig
    region.rs cors.rs json.rs out.rs quota_guard.rs     shard tags, CORS, JSON key order, response assembly, the cron guard
    hooks.rs          feature `test-hooks` only: /__test/* routes for the suites (never in the deployed build)
  tests/              black-box suites (Node test runner) against the BUILT wasm under wrangler dev / workerd
  scripts/            build.sh, fetch-build-tools.sh, size-gate.sh, lint-canary.sh, make-shadow-config.sh, coldstart.mjs (+ cpu-node*)
../ci/                nft-gate-ci: UPSTREAM_AUTH_HEADERS check and origin-lock verdicts for the workflows (replaces two TypeScript scripts)
```

## Build and test

```sh
rustup target add wasm32-unknown-unknown
cargo install worker-build --version 0.8.7 --locked     # must match the wasm-bindgen crate (see "Toolchain")
eval "$(worker/scripts/fetch-build-tools.sh)"            # optional: checksummed wasm-bindgen / wasm-opt / esbuild (else worker-build downloads its own)
cd worker && npm ci                                       # wrangler + the test harness (test code only)
bash scripts/build.sh all                                 # build/ (deployed variant) and build-hooks/ (+ test-hooks, for the suites)
bash scripts/size-gate.sh                                 # wrangler deploy --dry-run; fails above 1.5 MiB gzip
npm test                                                  # every workerd suite (the differential run is separate)
npm run test:diff                                         # only the differential run (needs `npm ci` in ../gateway-workers)
cargo test --locked -p nft-gate-worker -p nft-gate-ci     # native unit tests of the glue and the CI helper
bash scripts/lint-canary.sh                               # proves the panic lints are live
```

The suites need Node 26 (CI uses it), no Docker, no network beyond `npm ci`. `wrangler dev` runs the real workerd with the
real SQLite Durable Object; the fullnode and the upstream are local stubs (`tests/lib/stubs.mjs`; the fullnode stub speaks both
binary gRPC-web, which the Rust Worker uses, and grpc-web-text, which `@mysten/sui` uses in the TypeScript Worker). Access proofs
are real: an Ed25519 key signs the audience-bound message with the published protocol client.

## Toolchain (pinned; bump together)

| Piece | Pin | Where |
| --- | --- | --- |
| workers-rs `worker`, `worker-macros`, `worker-sys` | `=0.8.7` | `Cargo.toml` |
| `wasm-bindgen`, `wasm-bindgen-futures`, `js-sys`, `web-sys` | `=0.2.129`, `=0.4.79`, `=0.3.106`, `=0.3.106` | `Cargo.toml` |
| `worker-build` | `0.8.7` (`cargo install --locked`) | CI, `deploy-worker-rust.yml`, this README |
| wasm-bindgen CLI (must equal the crate) | `0.2.129`, SHA-256 `82d12bb9…e8320e` | `scripts/fetch-build-tools.sh` |
| Binaryen `wasm-opt` | `version_132`, SHA-256 `195ddc94…c30572` | `scripts/fetch-build-tools.sh` |
| esbuild (npm `@esbuild/linux-x64`) | `0.28.2`, SHA-256 `9573bb22…4488f6` (its sha512 equals the registry's `dist.integrity`) | `scripts/fetch-build-tools.sh` |
| wrangler | `4.151.0` exactly | `package.json` |
| Rust | stable (1.98.1 when built), `rust-version = "1.91"` for this crate | `Cargo.toml`, workflows |

workers-rs, wasm-bindgen and worker-build are 0.x and move together (workers-rs raised its MSRV in a patch release; the wasm-bindgen CLI
that `worker-build` runs must be exactly the crate's version). Dependabot ignores all of them: bump them by hand in one change,
rebuild, and re-run `npm test` and the size gate. `worker-build` honours `WASM_BINDGEN_BIN`, `WASM_OPT_BIN` and `ESBUILD_BIN`; CI sets
them from the checksummed downloads, so nothing is fetched unverified at build time. `strip = true` breaks the build (workers-rs #1014);
the opt-level is set by `wrangler.toml [build]` (`CARGO_PROFILE_RELEASE_OPT_LEVEL=s`) so the native builds are unaffected.

## Behaviour parity with `gateway-workers`

Same routes (`/healthz`, `/v1/challenge`, public paths with the Cache API edge cache, gated paths), same status codes and JSON bodies (even the key
order: `{"error","code"}`, `{"nonce","expiresAt"}`), same CORS on every response including preflight and every error, the 508 loop guard, the
challenge/public/pre-auth/per-address budgets (IPv6 keyed by /64) with the same variables, the nonce format `<region>.<48 hex>` and the same shard
map, single-use lease/commit/release in the DO, the same SQLite schema (tables `nonces`, `rate`, `redemptions` with the `token` column; the
`ALTER TABLE ADD COLUMN token` upgrade is ported and tested), class `NonceRateState`, migration tag `v1`, the `scheduled` quota guard (off by
default), the streamed proxy with `MAX_BODY_BYTES`/`FixedLengthStream`/413, the header policy, redirect refusal (302 → 502) and the total
deadline (504), `UPSTREAM_AUTH_HEADERS` / `SUI_RPC_AUTH_HEADER` parsing, `ALLOWED_ORIGINS`, `GATEWAY_ORIGIN`/`NETWORK`, every `[vars]` entry.
`tests/differential.diff.mjs` runs the same scenarios against both Workers and fails on any difference in status, body, header or the request the
upstream receives.

### Intended differences

| Difference | Why |
| --- | --- |
| `ALLOW_INSECURE_HTTP=1` is required for an `http://` upstream, RPC URL or origin (the TypeScript Worker allowed loopback implicitly) | one stricter config rule for every platform (core `config`); production values are all https |
| Stricter shared config: the lease must exceed `UPSTREAM_TIMEOUT_SECS + BODY_READ_TIMEOUT_SECS` (the latter is accepted and unused here), empty hosts/whitespace in URLs refused, origin hosts `[a-z0-9.-]` only, normalised request-loop comparison | core `config` table in `core/README.md`; the defaults satisfy all of them |
| Workers KV nonce backend dropped: `NONCE_BACKEND=kv` is a startup error, no `NONCE_KV` binding, no `quota:degrade` flag | decided 2026-10-19; it was refused with `SINGLE_USE` and only eventually consistent otherwise. The quota guard therefore only warns |
| A literal `..` path segment is refused (400) | one rule in the core; the Cloudflare URL parser resolves dot segments first, so never reachable on Workers |
| A missing Durable Object binding answers `500 gateway misconfigured` **with** the CORS allow-list (the config is known by then) | the TypeScript Worker lost the allow-list on any startup failure; no security impact |
| Rate-store failure on a rate check is `503 gateway state unavailable` (core `StateStore::rate_check` is fallible since 0.0.27) | fail closed; the TypeScript Worker did the same through its `StoreError` wrapper |
| `QUOTA_GRAPHQL_URL`, `TEST_FAIL_STATE`, the DO `now=` pin and `/__test/*` exist **only** in the `test-hooks` build, never in `build/` | test seams; `tests/panic.test.mjs` asserts the deployed build has no such routes |
| Cold start: one wasm instantiation (see Measurements) instead of a JS bundle parse | platform; gated by the CPU analytics before cutover |

## Runbook: shadow, CPU gate, cutover, rollback, retire

The maintainer runs these; nothing here deploys by itself.

1. **Shadow deploy.** Actions → "Deploy Worker (Rust)" → `mode=shadow`, `worker_name` (default `nft-gate-gateway-shadow`), `gateway_origin` =
   the shadow's own https origin, e.g. `https://nft-gate-gateway-shadow.<account>.workers.dev` (enable the account's workers.dev subdomain first;
   the origin is signed into proofs, so it must be exactly what clients use). The job re-runs the full Rust CI, builds with `worker-build`, derives a
   config with `scripts/make-shadow-config.sh` (new script name = a new, empty Durable Object namespace; workers.dev instead of the route;
   `GATEWAY_ORIGIN` overridden), deploys it, and sets the secrets: GitHub secret `UPSTREAM_URL` (required for a shadow), and `UPSTREAM_AUTH_HEADERS`
   / `SUI_RPC_AUTH_HEADER` when set. The shadow forwards to the real relay origin with the real service token, so a shadow upload is a real upload.
   *Limits of workers.dev:* the Cache API stores nothing on a workers.dev address, so the public-path edge cache is not exercised by the shadow
   (the differential and `router.test.mjs` cover it); WAF/rate rules of the zone do not apply.
2. **Exercise it.** `cd integrations/paywall && node run.mjs --relay https://nft-gate-gateway-shadow.<account>.workers.dev` (the harness signs
   for that origin, buys a pass, consumes it, uploads through the shadow, checks replay/decoder negatives). One run proves behaviour on the real
   chain; real traffic needs a client pointed at the shadow (the apps' relay host variable) or a mirror, at the maintainer's discretion.
3. **CPU gate.** Workers analytics → the shadow Worker → CPU time: **p99 ≤ 5 ms and p99.9 ≤ 10 ms over a week of real traffic on Free** (the Free
   limit is 10 ms per request; 5 ms leaves headroom). Local numbers cannot answer this: workerd exposes no CPU clock, and whether the platform
   charges wasm instantiation to the first request can only be read from a deployment. If the gate fails: do not cut over; options are
   `opt-level` variants (`scripts/size-variants.sh`), a smaller bundle, or Workers Paid (`[limits] cpu_ms`, see `gateway-workers/README.md`).
4. **Cutover.** Actions → "Deploy Worker (Rust)" → `mode=cutover`, `confirm=cutover`. It deploys over `nft-gate-gateway` with the same name, class
   and migration tag, so nonces, rate windows and the 30-day redemption records are kept; the secret flow is the one of `deploy-workers.yml`
   (versions upload → secret put → versions deploy when `UPSTREAM_AUTH_HEADERS` is a GitHub secret). Run `integrations/paywall` against the live
   origin immediately after.
5. **Rollback.** Re-run `deploy-workers.yml` (TypeScript) at the last TypeScript tag (0.0.26 is the last release that deploys it; 0.0.27 still contains `gateway-workers`). The DO schema is shared, so state
   survives in both directions. Keep the tag until step 6.
6. **Retire `gateway-workers`.** After a clean week on the Rust Worker: delete `gateway-workers/`, `deploy-workers.yml`, `node-ci.yml`'s Workers
   job and the npm publish of `@meddleware/nft-gate-gateway` (decide whether the npm package should live on as a wrangler-template wrapper),
   move `worker/package.json`'s tooling to wherever the maintainer prefers, and drop `spike`/`gateway-workers` mentions from the docs.
   The differential suite goes with it (it needs the TypeScript Worker); the other suites stay.

## Failure modes and risks

| Risk | State |
| --- | --- |
| A panic is a wasm trap and cannot be caught | the request path is linted free of `unwrap`, `expect`, `panic!` and indexing (`[lints.clippy]`, `scripts/lint-canary.sh` proves the lints bite). If one ever happens (recorded by `tests/panic.test.mjs`): the runtime answers its own 500 text (no JSON, no CORS grant), nothing is forwarded (fails closed), and `worker-build`'s trap recovery re-instantiates the module so the next request is served |
| workers-rs / wasm-bindgen / worker-build are 0.x | pinned exactly, bumped by hand together; the TypeScript Worker is the rollback until retirement |
| Build-time downloads (wasm-bindgen CLI, Binaryen, esbuild) | checksummed in CI (`fetch-build-tools.sh`); locally `worker-build` fetches its own |
| Generated JS glue (about 32 KB `index.js`) ships in the bundle | build output, not authored code; the maintainer accepted it |
| Durable Object continuity | same class, tag and schema; the shadow uses a different name on purpose. A cutover under a *different* script name would start with an empty redemption store (a replay window), which the workflow forbids |
| workers-rs Durable Objects speak `fetch` only (no RPC) | internal HTTP to the stub with a JSON body; same atomicity (single-threaded, synchronous SQL sections) |
| CPU time on Free | gate in the runbook; not measurable locally |
| The `test-hooks` variant is a different binary from the deployed one | a build with the feature runs the suites; the size gate, the dry-run and the deploy use the feature-less build, and `panic.test.mjs` asserts it has no test routes. The behavioural suites (router, proxy, redemption, config, limits, chain, differential) run on the feature-less build |

## Measurements (2026-10-19, this machine, workerd 2026-10-12, wrangler 4.151.0)

| | |
| --- | --- |
| wasm (`opt-level=s`, wasm-opt) | 978,002 bytes raw |
| `wrangler deploy --dry-run` | total 1007.59 KiB / gzip 357.51 KiB (the wasm alone: 347,485 B gzip) (TypeScript Worker today: 684.13 KiB / gzip 136.71 KiB; budget 1536 KiB gzip) |
| First request in a fresh workerd (`/healthz`, wall) | 20.1 ms median (17.2-56.9 ms, 12 samples; includes process-level effects: compare only on the same machine) |
| Signature verification, warm mean in workerd (wall) | 0.56 ms ed25519, 0.64 ms secp256k1, 2.06 ms secp256r1 (TypeScript: 0.88 / 1.02 / 1.55 ms) |
| First verification in a fresh isolate | 4 ms median ed25519 (3-5 ms; the P-256 outlier is 17 ms) (TypeScript: 17 ms, up to 40) |
| Streaming | 90 MiB chunked and Content-Length framed through the proxy with wasm linear memory flat (< 8 MiB growth, asserted); 413 at the cap with at most the cap's bytes upstream |

`scripts/coldstart.mjs rust build-hooks N` (fresh workerd per sample) and `scripts/cpu-node.cjs` are the instruments; their method and limits are in
their headers. Wall time is not CPU time: only the deployed CPU analytics decide the gate.

## Test map: every `gateway-workers` test and its Rust-Worker counterpart

TypeScript tests: **251** (248 run, 3 skipped live-chain tests). Nothing is dropped without a reason in the last column.

| TypeScript test file (count) | Counterpart | Ported / removed |
| --- | --- | --- |
| `router.test.ts` (48): routes, challenge shape, 401/403, the shared proof-reject vectors, preflight and CORS cases, nonce round trip; hardening (challenge budget with CORS on the 429, 508 on every path class, foreign Via, `Vary: Origin`, unreachable upstream fails closed, public read-only 405 + `Allow`, gated method refusal, pre-auth budget before verification, upstream CORS never widens); edge-cache query drop | `tests/router.test.mjs` (49: same names, plus a cache-hit CORS case), plus the differential routes scenario | 48 ported |
| `proxy.test.ts` (13): body cap chunked/declared/intact/Content-Length-framed/502, redirect refusal, deadline 504, header policy (request strip, `Via` marker, response filter, method/path refusal), `Via` table, marker on the upstream request | `tests/proxy.test.mjs` through the real gated path; `tests/stream.test.mjs` (90 MiB); core `headers.rs` / `forward.rs` unit tests. The `Connection`-named half of the strip test cannot be observed black-box (workerd consumes `Connection` before the Worker runs, in the TypeScript Worker too) and is pinned by core's `headers` tests | 13 ported (1 narrowed, see left) |
| `redemption.test.ts` (7): lease/forward/commit/redeemed, concurrent duplicate, failure releases, stale holder, lapsed lease before commit → 502, failed commit → 502, lease store error | `tests/redemption.test.mjs` for 5 (fault injection through `TEST_FAIL_STATE` in the test build); stale holder and lapsed-before-commit need a lease that expires **mid-request**, which the config forbids (lease > upload deadline), so they are pinned at the store (`tests/state.test.mjs`, scenario "an expired lease is reclaimable and the old holder loses") and in the core (`gateway.rs`: `a_lease_lost_before_the_commit_is_a_502_not_a_success`) | 7 mapped, 5 as flow tests, 2 at their layer |
| `state.test.ts` (19): DO nonce once/unknown/expired, **KV** nonce once/unknown/expired, redemption store (6), rate limiter (4), shard tags (3) | `tests/state.test.mjs` (scenario.json against the SQL DO, 100-way atomicity, the store cases, schema and token-column upgrade, forged shard, region shard accepted); `region.rs` unit tests | 16 ported; **3 removed**: the KV nonce backend is not carried over |
| `gateway-state.test.ts` (6): degrade flag ignored in single-use, public budget, IPv6 /64, gated never cached, degrade flag moves ownership nonces to KV, store outage → JSON 503 + CORS | `tests/limits.test.mjs` (public budget, /64, unknown bucket, per-address), `tests/proxy.test.mjs` (never cached), `tests/redemption.test.mjs` (store outage, rate-store outage, take outage) | 4 ported; **2 removed**: the `quota:degrade` KV flag no longer exists (a config test pins `NONCE_BACKEND=kv` as a startup error) |
| `quota.test.ts` (14): allowances (2), plan parsing, window start (2), assessment (4), guard runs (5) | `core/src/quota.rs` unit tests (11) for the maths and parsing; `tests/quota.test.mjs` (6) for the scheduled handler in workerd | 14 ported; the KV-flag assertions inside two of them are dropped with the flag (the guard only warns) |
| `origin-lock.test.ts` (7): verdict cases (5), `check-origin-locked.mjs` fails closed without a URL / refuses non-https (2) | `ci/src/lib.rs` tests (the 5 verdict cases, with more), `tests/origin-lock.test.mjs` (the 2 script cases plus locked/open/challenged/unreachable paths) against `scripts/check-origin-locked.sh`; `origin-lock.yml` now runs the Rust helper | 7 ported |
| `config.test.ts` (24): auth headers, allowed origins, audience, strict values, single-use invariants, RPC auth header, NFT type / gate id, challenge rate default | core `config.rs` tests, `worker/src/config.rs` tests (Worker-only variables), `ci` tests (auth-header parser and shapes), `tests/config.test.mjs` (12 misconfigurations fail closed with the JSON + CORS shape) | 23 ported; **1 removed**: "config.ts has no imports" (a constraint of the TypeScript deploy script) |
| `chain.test.ts` (17): helpers, event matching and recency, gate strictness, `SuiGrpc` against a fake client incl. retries and cache | core `chain.rs`, `grpc.rs` and `tests/transport_stub.rs` (incl. the two new ownership-cache tests), `tests/chain.test.mjs` (retry only on not-found, late-indexed, no amplification, hung node bounded, digest checks, cache TTL, RPC auth header) | 14 ported; **3 removed**: `packageOf`, `cacheKey` and `withDeadline` are TypeScript client internals with no Rust counterpart (the deadline is the transport's `AbortSignal.timeout`, tested in `chain.test.mjs`) |
| `verify.test.ts` (22): signature schemes, the decision, audience binding, malformed digest | core `tests/decision.rs` (17) and `proof.rs`; workerd: `tests/conformance.test.mjs`, `tests/chain.test.mjs` (malformed digest) | 22 ported |
| `conformance.test.ts` (69): token grammar, personal-message vectors, golden signatures, audience mismatch, negative signatures, ZIP-215 | core `tests/conformance.rs` (every vector, native), `tests/conformance.test.mjs` (golden signatures verified as wasm in workerd, golden tokens accepted end to end, audience mismatches refused), `tests/router.test.mjs` (proof reject vectors through the door) | 69 ported (the vector file is shared; "repository copy equals the published package" stays in `sync-vectors.mjs --check`) |
| `cpu-bench.test.ts`, `cpu-bench.node.test.ts` (2) | `scripts/coldstart.mjs`, `scripts/cpu-node.cjs`, and the CPU gate on a real deployment | 2 replaced by instruments (they asserted nothing that a CPU analytics read does not answer better) |
| `integration/grpc-chain.integration.test.ts` (3, skipped) | `core/tests/transport_stub.rs`; the live probe is the `--ignored live_` tests of `gateway-rust` and `integrations/paywall` | skipped before and after |

Totals: of 251 TypeScript tests, **237 ported** (one-to-one, or into the layer that owns the logic; 2 of them, the stale-holder and
lapsed-lease cases, live at the store and in the core because they cannot happen mid-request under a valid config), **2 replaced** by measurement
instruments, **3 skipped** before and after, and **9 removed with a reason** (3 KV nonce backend, 2 KV degrade flag, 1 TypeScript-only import constraint, 3 TypeScript
client internals: `packageOf`, `cacheKey`, `withDeadline`). The Rust Worker's own suites are larger than the ports: 177 workerd/Node tests,
218 (+3 ignored) native tests across the workspace, the differential scenarios, and the cases the port needed that the TypeScript Worker never had (fault
injection, schema upgrade, panic behaviour, shadow config, the origin-lock script).
