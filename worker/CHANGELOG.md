# Changelog

All notable changes to the Rust Cloudflare Worker (`nft-gate-worker`, not published to crates.io; built with `worker-build`) are documented here. It is versioned with the
repository (one version for every artifact).

## [0.0.33] - 2026-10-30

### Changed

- Dependency patch: the yanked `crypto-bigint` 0.7.6 is replaced by 0.7.10; wrangler 4.155.0. No behaviour change. The live Worker is redeployed from this version after a shadow check (see the runbook).
- The relay route and gateway origin live on the machine zone (ADR-0005; deployed 2026-10-27 from 0.0.32).

## [0.0.32] - 2026-10-24

### Changed

- **Breaking (wire protocol, ADR-0004):** access proofs are verified against the `access-gate-gateway:access:v3` message (the audience lines are unchanged); a `nft-gate:access:v2` proof is refused (`BadSignature`). Needs `@meddleware/access-gate-gateway-client` 0.0.21 on the client side.
- The loop marker is `Via: 1.1 access-gate-gateway` (was `1.1 nft-gate`); a request carrying it is refused `508`.
- Conformance vectors re-synced from `@meddleware/access-gate-gateway-client` 0.0.21.

## [0.0.31] - 2026-10-24

### Security

- `k256` and `p256` 0.14 (ECDSA verification for secp256k1 and secp256r1): they move to `crypto-bigint` 0.7.6, which fixes
  RUSTSEC-2026-0387 (timing variability in constant-time operations). The low-S rule and the golden signature vectors are unchanged
  (all 218 native tests and the workerd suites pass). `getrandom` 0.4 on `wasm32-unknown-unknown` needs the `wasm_js` backend
  (`.cargo/config.toml`); it is never called on the verify path.

### Added

- `access-gate-gateway-core` and `access-gate-gateway` are published on crates.io (0.0.31 is the first version released by CI through trusted
  publishing; 0.0.30 was uploaded by hand).

## [0.0.30] - 2026-10-24

### Changed

- Renamed from `nft-gate` to `access-gate-gateway` (workspace naming convention, `docs/architecture/ADR-0003-naming.md`). No code change beyond names, paths, hostnames and dependency names; the history below keeps the old names.

## [0.0.29] - 2026-10-22

Not deployed. The version moves with the workspace. The core gains a bounded in-memory rate table (`RateTable::check_capped`, `prune`) that the native adapter uses; the Worker keeps its Durable Object windows and its code is unchanged.

## [0.0.28] - 2026-10-22

Not deployed. Picks up the core's exact-32-byte consume-digest rule (`nft-gate-core` 0.0.28) with no change to the Worker's own code.

### Added

- `tests/conformance.test.mjs`: the shared `responses` vectors, black box (15 of the 16 outcomes: missing and malformed proof, bad signature, replayed nonce, no pass, no consume, paused gate, chain down, store outage, rate limit, 405, 508, redeemed, leased, failed commit; a lease that lapses mid-request cannot be reached from outside and is pinned in the core).

### Changed

- The harness pins `@meddleware/nft-gate-client` 0.0.18; the stub fullnode's `txDigest()` counts leading zero bytes (a random digest with a zero first byte decoded to 31 bytes under the exact-length rule).

## [0.0.27] - 2026-10-19

First version. **Built and tested; not deployed** (the maintainer shadow-deploys it with `deploy-worker-rust.yml`, reads the CPU-time p99/p99.9 in Workers analytics, then cuts over;
`README.md` "Runbook"). Promoted from the feasibility spike (`docs/SPIKE-FINDINGS.md`).

### Added

- The Worker: an I/O adapter on `nft-gate-core` replacing `gateway-workers` 1:1: routes, CORS on every response, the 508 loop guard, the Cache API edge cache for public paths, per-IP and per-address
  budgets (IPv6 /64), the region-sharded SQLite Durable Object `NonceRateState` (same class, migration tag `v1`, schema and `token` column upgrade as the TypeScript one, so a deploy over the live script keeps its data),
  single-use lease/commit/release, the streamed upstream proxy (byte cap, `FixedLengthStream`, 413/502/504, header policy, redirect refusal), the gRPC-web `Transport` over `fetch`, the `scheduled` quota guard (off by default).
- Black-box suites under `tests/` (Node test runner against the built wasm under `wrangler dev`): router, proxy, redemption, state (scenario.json against the SQL DO, atomicity, schema upgrade), limits, chain, quota, conformance (golden vectors as wasm in
  workerd), config, stream (90 MiB), panic, origin-lock, and a differential run against the TypeScript Worker (identical status, body, headers and upstream requests). `README.md` maps every TypeScript test to its counterpart.
- CI (`rust-ci.yml` `worker` job): clippy with the panic lints (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`) natively and for wasm32, a lint canary, pinned and checksummed build tools, the wasm build, a 1.5 MiB gzip size gate on `wrangler deploy --dry-run`, the suites and the differential run.
- `deploy-worker-rust.yml` (manual, `production` environment): `shadow` (a different Worker name with its own empty Durable Object namespace, workers.dev) and `cutover` (over `nft-gate-gateway`, `confirm=cutover`).
- `../ci` (`nft-gate-ci`): the `UPSTREAM_AUTH_HEADERS` check (the core's own parser) and the origin-lock verdicts; `scripts/check-origin-locked.sh` and `origin-lock.yml` now use it instead of the TypeScript scripts.
- `integrations/paywall` (workspace): `--relay <https origin>` to exercise a shadow deployment.

### Differences from the TypeScript Worker (intended)

`ALLOW_INSECURE_HTTP=1` is required for `http://` URLs, the core's stricter configuration rules, no Workers KV nonce backend (`NONCE_BACKEND=kv` is a startup error) and therefore no `quota:degrade` flag, a literal `..` path segment is refused,
a missing Durable Object binding keeps the CORS allow-list. See `README.md`.
