# Findings — access-gate Worker in Rust (workers-rs), 2026-10-19

> **Historical (kept for the measurements).** The spike was promoted to the production crate [`../worker`](../worker/) in 0.0.27 and the spike directory was removed; the decisions asked for
> below were taken (generated wasm-bindgen glue accepted, KV backend dropped, black-box Node/TS test harnesses allowed as test code, CPU-p99 cutover gate kept). Current numbers are in [`../worker/README.md`](../worker/README.md).

Verdict: **GO**. Measured on this machine with pinned versions (worker/worker-build 0.8.7, wasm-bindgen 0.2.129,
Rust 1.98.1, wrangler 4.151.0, workerd 2026-08-15, Node 26.12.0). Nothing was deployed.

## Decision gate

| Gate | Result |
| --- | --- |
| Size | wasm 0.29 MiB gzip (0.23 MiB brotli); `wrangler deploy --dry-run` total 305.96 KiB gzip (TS Worker today: 136.71 KiB). Cloudflare's limits page (2026-10-19): 64 MiB uncompressed on both plans, no compressed limit. |
| Cold first request CPU | First ed25519 in a fresh isolate: 4 ms wall in workerd (TS 17 ms, up to 40); Node request-thread CPU 7.0 ms (TS 26.8). Module load + instantiate costs about 5.9 ms thread CPU (TS 19.6). Whether the platform charges instantiate time to the first request's 10 ms cannot be measured locally; the analytics p99 after a real deploy must gate the cutover. |
| Durable Object (SQLite) | Works. 100 concurrent takes of one nonce: exactly 1 winner. 100 concurrent leases: 1 `ok`, 99 `leased`. |
| Streaming | 90 MiB through the proxy with wasm linear memory flat at 1.44 MiB; the 413 cap holds; upstream never sees more than the cap. |

## Signature verification (warm mean / first in fresh isolate)

| Scheme | Rust workerd wall | TS workerd wall | Rust Node thread CPU | TS Node thread CPU |
| --- | --- | --- | --- | --- |
| ed25519 | 0.55 ms | 0.88 ms | 0.44 ms | 1.97 ms |
| secp256k1 | 0.62 ms | 1.02 ms | 0.43 ms | 2.14 ms |
| secp256r1 | 1.92 ms | 1.55 ms | 1.54 ms | 3.42 ms |

Method limits: workerd has no CPU clock (`performance.now()` is wall time at about 1 ms); the Node numbers use
`process.threadCpuUsage()` (request thread) and are not comparable across the two methods. First request to a
fresh workerd (`/healthz`): Rust 8.7 ms median wall vs TS 1.5 ms (instantiate), but TS pays 17 ms or more of lazy
set-up inside the first verification request. Rust crates: ed25519-consensus (ZIP-215), k256 0.13.4, p256 0.13.2,
blake2 0.11 (same as gateway-rust).

## Shared core

`core/` (`access-gate-gateway-core`) is pure (no hyper, tokio, clock, RNG or logging), compiles for the host and wasm32
(87 normal dependency crates, one target-gated `getrandom/js` line) and holds proof, signature, decision, gRPC-web
codec + `Transport` trait, chain reads, redemption/nonce/rate tables, header policy and origin check. 42 tests pass.
`gateway-rust-on-core.patch` (−1,639 / +104 lines) applied to a scratch copy of gateway-rust: 99 passed, 3 ignored
(the 18 missing tests moved to core: proof.rs 5, grpc.rs 13). Still to move: `config.rs` behind an `Env` trait,
the in-memory redemption/nonce logic, `headers.rs`, and the `handle`/`redeem_and_forward` orchestration.

`scenario.json` (7 sections, 39 steps, explicit clock) passes against the pure `core::redemption` state machines
and against the real SQLite DO under workerd, so the DO SQL and the core rules cannot drift.

## Risks

- 0.x churn: worker, wasm-bindgen, worker-build move together (MSRV bumped in a patch release). Pin exactly; keep the TS rollback.
- Build-time downloads (wasm-bindgen, Binaryen, esbuild): pin and checksum in CI.
- Generated JS glue (about 30 KB `index.js` + a 4-line shim) ships in the bundle; it is build output, not authored code.
- A panic returns the runtime's generic 500 without JSON/CORS (fails closed): lint panics out of the request path.
- DO continuity: deploy under the same Worker name, class `NonceRateState` and migration tag `v1`, and port the `ALTER TABLE ADD COLUMN token` upgrade; a new script name would start with an empty redemption store (replay window).
- workers-rs Durable Objects speak `fetch` only (no RPC): internal HTTP to the stub.
- Known issues reproduced: workers-rs #1014 (`strip = true` breaks the build), #736 (`getrandom 0.2` needs `js` on wasm32).
- `Closure::forget` leaks one small closure per proxied request in the spike; store the closure in the port.
- Pre-existing divergence found: `is_safe_path` rejects a literal `..` segment in Rust but not in TS (not exploitable on Workers, where the URL parser normalises dot segments).
- Not tested: full-port request CPU, real edge and DO latency, many concurrent uploads on one isolate, `wrangler deploy` itself, a positive live-chain consume.

## Follow-up (0.0.26, 2026-10-19): the "still to move" list is done

`config.rs` (behind an `Env` trait, the stricter rule where Rust and TypeScript disagreed), the in-memory nonce / rate /
redemption state (`core::state` over `core::redemption`), `headers.rs`, the origin check, `is_safe_path` (a literal `..`
segment is now refused in the one implementation) and the `handle` / `redeem_and_forward` orchestration
(`core::gateway`, a state machine over `StateStore`, `ChainQuery`, `Upstream`, `Clock`, `Rng`) now live in
[`../core`](../core). `gateway-rust` is an I/O adapter on it: the 117 + 3 ignored tests are unchanged or moved to the core
(176 + 3 ignored across the workspace). This directory keeps the Worker prototype and the measurement scripts.
