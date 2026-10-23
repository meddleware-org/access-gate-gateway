# CLAUDE.md — access-gate-gateway

## What this repo is

A generic NFT-gated reverse proxy for the `access_gate` on-chain primitive. Any HTTP upstream —
upload relay, website, game API — can be placed behind this gateway to restrict access to holders
of an on-chain Meddleware access NFT.

## Architecture: one core, two adapters

The decision logic exists **once**: `core/` (crate `access-gate-gateway-core`, Rust, no hyper / tokio / clock / RNG / logging, builds
natively and for `wasm32-unknown-unknown`). It holds the proof, the signature schemes, the decision, the Sui reads, the nonce /
rate / redemption state machines, the header / path / CORS / config policy and the request flow (`Gateway::handle`,
`redeem_and_forward`) as a state machine over the ports `StateStore`, `ChainQuery`, `Upstream`, `Clock`, `Rng`, `Env`.
A gateway is an adapter that supplies only I/O: `gateway-rust/` (hyper / axum / Redis) and the Cloudflare Worker.

The maintainer's standing rule is **no JS/TS backend code**. The live Worker `gateway-workers/` (TypeScript) is therefore
being replaced by the Rust Worker `worker/` (workers-rs) on the same core. Status (0.0.29): **built and tested, shadow not yet
deployed**. `gateway-workers/` is marked superseded-pending-cutover and is NOT deleted: it is the live deployment and the rollback until
the maintainer has shadow-deployed the Rust Worker (`deploy-worker-rust.yml`, mode `shadow`), read the CPU-time p99 ≤ 5 ms and p99.9 ≤ 10 ms in
Workers analytics over a week on Free, cut over (same Worker name, Durable Object class `NonceRateState`, migration tag `v1`, so the live DO data is kept), and
retired the TypeScript source (runbook: `worker/README.md`). The Workers KV nonce backend is not carried over. The spike's findings are `docs/SPIKE-FINDINGS.md`.

**The Worker adapter** (`worker/`): `lib.rs` routes around the core (`/healthz`, CORS preflight, 508) and builds `Gateway`; `state.rs` + `do_state.rs` are the
`StateStore` over the SQLite Durable Object (exact schema of the TypeScript one); `upstream.rs` is the streamed `fetch` proxy (byte cap,
`FixedLengthStream`, public edge cache); `transport.rs` the gRPC-web `Transport`; `quota_guard.rs` the `scheduled` guard (logic in `core/src/quota.rs`).
The request path must not panic (a wasm trap cannot be caught): `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` are denied in `worker/Cargo.toml`, and
`worker/scripts/lint-canary.sh` proves it in CI. The `test-hooks` cargo feature (test routes, a pinned DO clock, fault injection) must never reach the deployed build; `worker/tests/panic.test.mjs` asserts it
does not. workers-rs / wasm-bindgen / worker-build are pinned exactly and move together (Dependabot ignores them). Tests are black-box Node scripts against the built wasm under `wrangler dev` (test code only; no Worker logic in JS).

**Where a change goes:** decision logic, policy or request flow → `core/`, once. I/O → the adapter. Never fix a rule in only one gateway.

## Architectural invariants

- **Fail closed.** Any ambiguous state (bad signature, missing nonce, chain error) must deny.
  Never grant access on error.
- **Single-use nonce.** Once a nonce passes signature verification, it is consumed immediately —
  before the chain call — so a replay with a valid signature still fails `NonceInvalid`.
- **Address normalization.** Sui addresses are case-insensitive and may lack leading zeros.
  Always normalize with `normalize_address` / `normalizeAddress` before comparing. Both impls
  implement the same rule: lower-case, 0x-prefix, zero-padded to 64 hex digits.
- **multisig / zkLogin fail closed.** Flags 0x03 and 0x05 are recognised but not supported by
  the bundled verifier (requires the official Sui verifier; see gateway audit F1). They always
  return false — the same posture in both impls.
- **Public paths bypass auth.** Configured in `PUBLIC_PATHS` (Workers) / the same env var (Rust).
  The default is `/v1/tip-config` so relay tip-config endpoints are publicly readable.
- **Loop marker.** Every upstream request carries `Via: 1.1 nft-gate` (the client's own `Via` is
  dropped); a request that arrives already carrying that received-by name is refused `508 loop
  detected` before any nonce, rate-limit or redemption work. Foreign `Via` values (a CDN hop) pass.
  `/healthz` and CORS preflights are answered first. Identical in both impls (audit F43).
- **A paid use is never lost to a commit failure.** If the upstream answered 2xx but the redemption
  commit fails (or the lease was lost), the client gets `502` and the lease is released, so the same
  consume can be retried. The cost is at most one extra upload, bounded by the lease TTL and the
  per-upload limits; the alternative (keep the lease, retry the commit later) could lose the use.
  Decided 2026-10-19 (OQ6), identical in both impls.

## Versioning

One version for every artifact (D16): the npm package `@meddleware/access-gate-gateway`
(`gateway-workers/package.json`), the Cargo workspace (`[workspace.package]` version in the root `Cargo.toml`, inherited by
the crates `access-gate-gateway-core`, `access-gate-gateway`, `access-gate-gateway-worker` and `access-gate-gateway-ci`; each crate that uses the core pins `access-gate-gateway-core` at exactly that version),
the test harness package `worker/package.json` and the image. Bump `gateway-workers/package.json` (+ lockfile), `worker/package.json` (+ lockfile), the workspace version and those
pins together, then tag `v<version>`.
`scripts/check-versions.sh` runs in Node CI, Rust CI and every publish workflow. It fails when the npm and Cargo versions
differ, when a crate does not inherit the workspace version, when a pin differs, or when a tag does not match. The tag's
`crates-publish.yml` publishes `access-gate-gateway-core` first, then `access-gate-gateway`.

## Wire protocol coupling

Both gateways MUST produce identical decisions for any given proof token. For the Rust side this is by construction (the
decision is `core/`); until the TypeScript Worker is retired the coupling is also enforced by the shared
`conformance/vectors.json` golden vectors, which the core's tests and the TypeScript tests both consume.

If you change any of the following, update the core AND (until it is retired) the TypeScript Worker (the differential run `worker/tests/differential.diff.mjs` fails when the two diverge), and regenerate the vectors:
- The signed message (`nft-gate:access:v2` and its audience lines: origin, gate, network, nonce, consume)
- The proof token format (`base64(JSON { address, nonce, signature, consumeDigest? })`)
- The `Authorization: Bearer` / `X-Access-Proof` header preference logic
- The Sui signature wire format (flag || sig || pubkey)
- Address normalization rules

The vectors are generated and published by `@meddleware/access-gate-gateway-client` (`scripts/gen-vectors.mjs`,
`@meddleware/access-gate-gateway-client/vectors.json`). After a wire-format change: release the client, bump it
in `gateway-workers` (and `worker/package.json`, which pins it exactly), then `node scripts/sync-vectors.mjs` (CI runs it with `--check` against
the PUBLISHED package). Before the client is published, produce the copy from a local checkout with
`ACCESS_GATE_GATEWAY_CLIENT_VECTORS=../access-gate-gateway-client/vectors.json node scripts/sync-vectors.mjs`; the override is refused when `CI` is set.

## Conformance vectors (`conformance/vectors.json`)

Covers:
- `personalMessage` — the exact bytes the wallet signs for a context (origin, gate, network, nonce,
  consume), plus the contexts no implementation may sign
- `audienceMismatch` — valid signatures whose verifier-side context differs in one bound field
- `proofDecode` — base64(JSON) proof token → decoded fields
- `signatures[]` — one entry per signature scheme (ed25519, secp256k1, secp256r1) with a real
  Sui personal-message signature and the corresponding proof token
- `txDigest` — the consume-digest rule: base58 (Bitcoin alphabet) that decodes to **exactly 32 bytes** (not just 32–44
  base58 characters; a leading `1` is a zero byte). `is_tx_digest` in the core and `isTransactionDigest` in the client
  (which the TypeScript Worker imports) apply it.
- `responses` — the answer for each gateway outcome (status and `{ error, code? }` body): missing / malformed proof,
  every denial, rate limit, loop, `redeemed` / `leased` conflict, commit failure, lost lease, store outage. Each
  implementation maps every outcome name to a stimulus of its own and fails on a name it cannot drive: core
  `gateway.rs` (`the_shared_response_vectors_are_what_the_gateway_answers`), `gateway-workers/test/conformance.test.ts`
  (+ `router.test.ts` through the real router) and `worker/tests/conformance.test.mjs` (black box; only a lease that
  lapses mid-request is unreachable). A new outcome therefore needs all three.

The `gateway-workers` tests (vitest) and the core's tests (`cargo test -p access-gate-gateway-core`, `core/tests/conformance.rs`) load and
verify the vectors. A test failure here means the implementations have diverged on the wire format.

## Commission and access-gate economics

The gateway enforces NFT ownership — it does not collect commission directly. Commission (20 bps
per access NFT purchase) is collected on-chain via the `access_gate` Move package's
`PlatformConfig` object. The gateway is the enforcement layer; the `access_gate` Move package
is the economic layer. See [`access-gate-sui`](https://github.com/meddleware-org/access-gate-sui)
for the on-chain side.

## Gateway selection guide

| Use `worker/` (Rust) / `gateway-workers/` (TypeScript, superseded pending cutover) if | Use `gateway-rust/` if |
| --- | --- |
| Zero-infra Wrangler deploy | Docker / k8s / bare metal |
| Cloudflare edge distribution | Redis for horizontal scale-out |
| Already on Cloudflare | Lowest latency on own hardware |

Same endpoints, same env vars, identical verification decisions. Caveat: `gateway-rust/` buffers bodies
(`MAX_BODY_BYTES` 256 KiB default), so it is scoped to small-body upstreams and is not a drop-in for the
100 MiB relay (audit F6). It is not deployed, by decision (Rust audit OQ9, 2026-10-19): no small-body
upstream exists, the Worker on Workers Free costs nothing, and self-hosting the relay path would need
streaming bodies plus an HA Redis. Revisit on a small-body upstream, a white-label customer who must
self-host, or Workers Free proving insufficient while Paid is unaffordable.

> **Transport (2026-09):** both gateways query the chain over **gRPC** (public Sui fullnodes
> deprecated JSON-RPC). `gateway-workers/` uses `@mysten/sui`'s `SuiGrpcClient`; `gateway-rust/`
> uses the core's hand-rolled gRPC-web client (`core/src/grpc.rs`, no `tonic`/`prost`) to keep its lightweight build.
> Both are digest-first for single-use and implement consumeDigest **redemption** (a consumed use is
> never lost). The client-facing wire contract (routes, proof format, status codes) is unchanged.

## Trust boundaries

The gateway trusts:
- The on-chain Sui state (NFT ownership, consume events) — verified live via RPC
- The client's signature (cryptographically verified against the claimed address)
- The configured Sui RPC endpoint (`SUI_RPC_URL`)

The gateway does NOT trust:
- Any header value the client sends beyond the proof token
- The claimed address in the proof token before signature verification
- The claimed `consumeDigest` before on-chain event verification

## Deferred / post-testnet

- **gateway-rust gRPC migration + redemption — DONE (2026-09):** `gateway-rust/` now queries the
  chain over hand-rolled gRPC-web (now `core/src/grpc.rs`) with digest-first single-use verification and the
  consumeDigest **redemption** store (the `StateStore` lease/commit/release, orchestrated by `core/src/gateway.rs`),
  at parity with `gateway-workers/`. Validated by `cargo test` + a live testnet check
  (hermetic fixtures in `sui_rpc.rs`; the optional `--ignored live_` tests take a fresh consume from `ACCESS_GATE_GATEWAY_LIVE_*`). It is buildable/deployable but not
  currently deployed — the live paywall still runs on the Workers gateway.
- **multisig / zkLogin support (audit F1):** Requires the official Sui verifier. Until then, both
  fail closed with a log warning.
- **Redis horizontal scale-out for Workers (F2):** The KV fallback has an eventual-consistency
  replay window in `SINGLE_USE=false` mode; the Durable Object backend is strongly consistent.
  The Rust gateway uses Redis for fleet-wide replay protection.

## What NOT to do

- Do not move commission logic into the gateway — the on-chain contract handles economics.
- Do not add custom auth flows — the whole point is the wire protocol is canonical.
- Do not skip conformance vector tests when changing signature verification.
- Do not put decision logic, policy or request flow in an adapter, and do not fix a rule in one gateway only: it belongs in `core/`.
- Do not add JS/TS backend code (the standing rule); the TypeScript Worker is superseded and retires after the cutover. `worker/tests` is test code, `worker/package.json` carries wrangler and the harness only.
- Do not hardcode secrets — all config is env-var / wrangler secrets.

---

## Deferred documentation — NOT for the `docs.` website (planned here per Part 0.4)

> The gateway is inherently developer/operator infrastructure, so most of this repo's docs are
> already `dev.`-scoped. None of it belongs on the user-facing `docs.` site — an end user buying a
> gate pass never sees the gateway. The material below is the `dev.`/self-host outline to formalise
> later; it is largely already captured above (gateway selection, wire protocol, conformance,
> trust boundaries) and should be transcribed rather than rediscovered.

### `dev.` / self-host (to formalise later)

- **Deploy guides** for both impls (Workers via Wrangler; Rust via Docker/k8s + Redis), the shared
  env-var/secrets surface, `PUBLIC_PATHS`, and the gRPC `SUI_RPC_URL` requirement.
- **Wire-protocol spec + conformance vectors** as the canonical integration contract (shared with
  `@meddleware/access-gate-gateway-client`).

### White-label

- Placing an operator's **own upstream** (relay, website, game API) behind the gateway; how gate
  ownership maps to access, with commission fixed on-chain by `access_gate` (never in the gateway).
