# spike-workers-rs — feasibility spike: nft-gate Worker in Rust (workers-rs / wasm32)

**Status: experiment, not shipped, not part of any release. Nothing here is deployed.**

**Update 2026-10-19 (0.0.26): the spike's `core/` was promoted to [`../core`](../core) and is now THE shared
implementation** (the repository root is a Cargo workspace; `gateway-rust` runs on it; the config, header policy,
state machines and the request flow `Gateway::handle` moved into it too). What stays here is the Worker prototype
(`worker/`, built against `../../core`) and the measurement harnesses (`scripts/`), the starting point and the
cutover instrument for the Rust Worker port. The shared `scenario.json` now lives in `../core/tests/`.

## Result in one table (2026-10-19; details and method in the spike report returned to the maintainer)

| Question | Result |
| --- | --- |
| Size vs limits | wasm 808,471 B raw / 297,308 B gzip / 240,682 B brotli; `wrangler deploy --dry-run`: 839.83 KiB, gzip 305.96 KiB (TS Worker today: 684.13 KiB / 136.71 KiB). Docs (2026-10-19): no compressed limit, 64 MiB uncompressed |
| Verification | warm ed25519 / secp256k1 / secp256r1 = 0.55 / 0.62 / 1.9 ms (workerd wall; TS 0.88 / 1.02 / 1.55). First in a fresh isolate: 4 ms (TS 17 ms, up to 40); Node request-thread CPU 7.0 ms (TS 26.8) |
| Instantiate | +~7 ms wall on the first request vs the trivial TS Worker; Node load+compile CPU 5.9 ms (TS bundle load 19.6 ms) |
| Durable Object | SQLite DO: 39-step scenario identical to the pure model; 100 concurrent takes/leases -> exactly one winner |
| Streaming | 90 MiB through, wasm memory constant 1.44 MiB; 413 at the cap with <= cap bytes upstream |
| Chain / shared core | `Transport` trait; same gRPC-web + parsers run natively and on `fetch`; testnet read-only probe ok; gateway-rust on core: 99 + 18 moved = 117 tests, 3 ignored |
| Verdict | **GO**, conditional on maintainer decisions: generated wasm-bindgen JS glue in the bundle, KV backend, TS black-box tests, CPU-p99 cutover gate |


The question: can the live Cloudflare Worker (`../gateway-workers`, TypeScript) be rebuilt in Rust with
**one** implementation of the decision logic shared with `../gateway-rust`, within the Workers Free limits
(10 ms CPU per request, 100 MB bodies streamed through, Durable Objects for state)?

## Layout

```text
spike-workers-rs/
  Cargo.toml            workspace (worker only), release profile, exact pins
  rust-toolchain.toml   Rust 1.98.1 + wasm32-unknown-unknown (workers-rs 0.8.7 needs >= 1.91)
  worker/               the Worker (cdylib, workers-rs): bench / DO / streaming proxy / chain / verify; depends on ../../core
    wrangler.toml       production-shaped build          wrangler.bench.toml  adds --features bench
  scripts/              measurement + integration harnesses (Node; run against workerd)
../core/                nft-gate-core (was spike-workers-rs/core): the shared implementation, native AND wasm32
../core/tests/scenario.json   the 39-step scenario run against the pure state machines AND the Durable Object
```

## Build

```sh
rustup target add wasm32-unknown-unknown            # rust-toolchain.toml does it for 1.98.1
cargo install worker-build --version 0.8.7 --locked
cd worker
worker-build --release                              # -> build/index.js + build/index_bg.wasm
worker-build --release -d build-bench --features bench   # + embedded conformance vectors for /bench
../../gateway-workers/node_modules/.bin/wrangler deploy --dry-run --outdir /tmp/out   # size Cloudflare sees; never deploys
```

Gotchas found: `[profile.release] strip = true` breaks `wasm-bindgen` 0.2.129 ("externref table required
for catch wrappers", workers-rs issue #1014) — leave stripping to `wasm-opt`; `rand_core 0.6` pulls
`getrandom 0.2` which needs its `js` feature on wasm32-unknown-unknown (set in `core/Cargo.toml`, target-gated).

## Tests

```sh
(cd .. && cargo test -p nft-gate-core)   # the core's tests: unit, conformance vectors, scripted Transport, scenario.json
cd worker && wrangler dev -c wrangler.bench.toml --port 8799 --persist-to <tmp> &
node scripts/differential.mjs  http://127.0.0.1:8799   # ../core/tests/scenario.json against the real SQLite DO (39 steps)
node scripts/concurrency.mjs   http://127.0.0.1:8799   # atomicity: 100 concurrent takes / leases
node scripts/stream.mjs        http://127.0.0.1:8799 90   # 90 MiB streamed through the proxy; 413 behaviour
# end-to-end decision with a stub fullnode (restart wrangler dev with --var SUI_RPC_URL:http://127.0.0.1:18081):
node scripts/e2e-verify.mjs    http://127.0.0.1:8799
```

Needs `UPSTREAM_URL` (default `http://127.0.0.1:18080`; `stream.mjs` starts that upstream itself).

## Measurement harnesses (method and limits are stated in each script header)

| Script | What it measures |
| --- | --- |
| `scripts/coldstart.mjs rust\|ts <bundle>` | fresh `workerd` process per sample: first-request wall, first verification per scheme, warm mean (in-Worker `performance.now`) |
| `scripts/cpu-node.cjs <glue.js>` / `scripts/cpu-node-ts.mjs <bundle>` | the same code under Node/V8 with `process.threadCpuUsage()` (request thread) and `process.cpuUsage()` (all threads): module load, first verification, warm mean |
| `scripts/size-variants.sh <dir>` | wasm size per `opt-level` (raw / gzip / brotli) |

For the Node harness, build the glue from the raw cargo output:
`wasm-bindgen target/wasm32-unknown-unknown/release/nft_gate_spike_worker.wasm --target nodejs --out-dir <dir>`
then `wasm-opt -O` with the same feature flags worker-build passes. The TypeScript comparison bundle is a
scratch Worker (kept outside the repo) that imports `gateway-workers/src/verify.ts` and
`conformance/vectors.json` and is bundled with `wrangler deploy --dry-run --outdir`.

Delete `target/`, `worker/build*` and `.wrangler` when done; all are git-ignored.
