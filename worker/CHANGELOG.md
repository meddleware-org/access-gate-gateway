# Changelog

All notable changes to the Rust Cloudflare Worker (`nft-gate-worker`, not published to crates.io; built with `worker-build`) are documented here. It is versioned with the
repository (one version for every artifact).

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
