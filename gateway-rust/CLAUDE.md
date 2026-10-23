# CLAUDE.md — gateway-rust

## What this crate is

The Rust/Axum **adapter** of the access-gate gateway. Wire-identical to `gateway-workers/` on the
client-facing contract — same routes, status codes, proof format, and env-var config. Deployed as
a Docker container or a Cargo binary; state backed by an in-memory store (single replica) or
Redis/Dragonfly (horizontal scale-out).

**One core, two adapters (0.0.26).** What the gateway decides and does is `access-gate-gateway-core` (`../core`), shared with the
Cloudflare Worker: `proof`, `sig`, `decision`, `grpc`/`chain`, `redemption`/`state`, `headers`, `forward`, `net`,
`origin`, `config` and `gateway` (the request flow as a state machine over the ports `StateStore`, `ChainQuery`,
`Upstream`, `Clock`, `Rng`, `Env`). **Change decision logic, header/path/config policy or the request flow in
`../core`, once — never here.** This crate supplies I/O only: the hyper server and its limits (`main.rs`), the
buffered `Upstream` (`proxy.rs`, `headers.rs`, `http_client.rs`), `HyperTransport` (`grpc.rs`, `sui_rpc.rs`),
the nonce / redemption backends (`challenge.rs`: core's in-memory state machine or Redis), the system clock and
OS entropy (`state.rs`), and `ServerConfig` (`config.rs`: the core's `GatewayConfig` plus the native-only
variables). The build is the Cargo workspace at the repository root; the Docker build context is the root
(`docker build -f gateway-rust/Dockerfile .`).

## Chain access: hand-rolled gRPC-web (no JSON-RPC, no tonic/prost)

Public Sui full nodes deprecated JSON-RPC and the GraphQL endpoints are unavailable, so the core
(`../core/src/chain.rs`) queries the chain over **gRPC-web** (`application/grpc-web+proto`, HTTP/1.1) via a minimal
hand-rolled client in `../core/src/grpc.rs` — deliberately **without** `tonic`/`prost`/`sui-rpc`, to keep the
lightweight build (same rationale as avoiding `reqwest`; see the HTTP-client note). `grpc.rs` is a
tiny protobuf writer/reader + gRPC-web framing over the platform's `Transport` (here `HyperTransport` over the
shared `HttpClient`); only the fields the gateway reads are decoded. Field numbers are pinned from
`MystenLabs/sui-apis` and pinned by hermetic gRPC-web fixtures in `sui_rpc.rs` (literal field numbers, no network) and checked against a real node by
the optional `--ignored live_` tests, which take a fresh consume from `ACCESS_GATE_GATEWAY_LIVE_*` env vars
(public fullnodes prune old transactions, so no digest is fixed in the source).

- `consume_tx_valid` (single-use) is **digest-first**, mirroring the Workers gateway:
  `LedgerService/GetTransaction` (retried 4× at 500 ms) → a transaction whose effects status is success, with an event of **exactly**
  `<NFT_TYPE package>::access_gate::AccessConsumedEvent` (never a suffix match — any package can
  declare an `access_gate` module) for this **sender + gate** (gate read via
  a recursive lookup of the event's `google.protobuf.Value` json, so no BCS field-order assumption).
  It is NOT bound to the challenge nonce — single-use is enforced by the redemption store below.
- `owns_nft` (non-single-use) uses `StateService/ListOwnedObjects`, matching `gate_id` via the same
  json lookup. It reads every page (50 per page, at most `MAX_OWNED_PAGES` = 100, as in the Workers
  gateway) and errors past the bound.

## Single-use redemption (a consumed use is never lost)

The permanent on-chain `consumeDigest` is the one-time token, exactly as in the Workers gateway.
`verify_access_request` (core) returns `Verified { address, redemption_key }`; for single-use the core's
`Gateway::redeem_and_forward` leases the digest (`StateStore::try_lease_redemption`, which returns an owner token), proxies, then `commit`s with
the token on a 2xx upstream response or `release`s with it on failure (Lua compare-and-set in Redis) — so an interrupted upload leaves the consume redeemable
while a duplicate can't double-spend it. Redis keys use the `nftgate:redeem:` prefix; the in-memory
store mirrors the semantics (and `SINGLE_USE=true` requires Redis unless `ALLOW_VOLATILE_REDEMPTIONS`).
`REDEMPTION_LEASE_TTL_SECS` (900, above `UPSTREAM_TIMEOUT_SECS`) / `REDEMPTION_RETENTION_SECS` (30d)
tune the lease/retention windows. `redeemed`/`leased` → `409` with a machine-readable `code`; a store error → `503`; a lost lease → `502`.
A commit failure after a 2xx upstream is `502 redemption commit failed` with the lease released
(decided 2026-10-19, OQ6): the user may upload twice (bounded by the lease TTL and per-upload limits)
but never loses a paid use. Same in `gateway-workers`.

Loop marker (F43): `headers::upstream_request_headers` sets `Via: 1.1 nft-gate` after dropping the
client's; the core's `Gateway::handle` answers `508 loop detected` to a request whose `Via` already names `access-gate-gateway`
(after `/healthz` and the CORS preflight, before any state work). Foreign values pass. Parity table:
`via_loop_table` in `../core/src/headers.rs` = `VIA_TABLE` in `gateway-workers/test/proxy.test.ts`.

## Hardening invariants

- ed25519 is verified under ZIP-215 (`ed25519-consensus`); secp256k1/r1 reject high-S explicitly.
  The shared conformance vectors (`negativeSignatures`, `zip215`) pin both gateways to Sui's rules.
- gRPC-web responses must carry a `grpc-status` (header for trailers-only, else trailer frame);
  anything else is an error. Messages are capped at 4 MiB; JSON lookups stop at depth 32.
- Every outbound call has connect and whole-request timeouts and a response-size cap.
- `MAX_CONCURRENT_REQUESTS` sheds load with `503`; `/healthz` is routed outside the cap.
- CORS mirrors the Workers gateway (`cors.ts`): exact `ALLOWED_ORIGINS` match only, the same grants, `Vary: Origin`, preflight before auth, headers on error responses too.
- The rate-limit client IP is the TCP peer unless `TRUSTED_PROXY_HOPS` says how many proxies to
  trust; never the leftmost `X-Forwarded-For` entry (client-controlled).
- `GatewayConfig`'s (core) and `ServerConfig`'s `Debug` are hand-written to redact secrets — keep it that way when adding fields.

## Axum architecture

`AppState` is the single shared object (`Arc<AppState>`) threaded through every request handler:
- `cfg: ServerConfig` — loaded from env vars at startup; immutable for the process lifetime. `cfg.gateway` is the core's shared `GatewayConfig`.
- `store: NonceStore` — in-memory (the core's `MemoryStore` on the system clock) or Redis, depending on `REDIS_URL`.
- `rates: MemoryRates<SystemClock>` — the core's fixed 60 s windows: per client IP for the challenge and public paths, per client IP for gated requests before verification, and per verified address (post-auth). Each table holds at most 100,000 windows (`DEFAULT_RATE_MAX_KEYS`; a full table drops ended windows, then the soonest-ending one) and `AppState::sweep` (the `NONCE_PRUNE_INTERVAL_SECS` task) drops ended windows.
- `chain: SuiRpc` — the core's Sui gRPC-web client over `HyperTransport`; optional in-memory ownership cache.
- `http: HttpClient` — shared `hyper` client used by both the proxy and the RPC client.

All routes are dispatched through a single `fallback` handler (`handle`), which derives a `RequestHead`, builds a
core `Gateway` over `NativeState` (the `StateStore`), `SuiRpc` and `AppState` (the `Upstream`) and renders the
`Reply`. The router does not enumerate paths — the core checks them in order: `/healthz` (adapter) → loop guard →
`/v1/challenge` → public paths → gated paths.

## Nonce store options

**In-memory** (default; `REDIS_URL` unset)
- The core's `NonceTable` / `RedemptionTable` behind a `Mutex` (`access_gate_gateway_core::state::MemoryStore`) — correct at `replicas: 1`.
- Hard entry cap (`NONCE_MAX_ENTRIES`, default 1,000,000): when full, evict the soonest-to-expire
  entry before inserting (audit F3 — bounds memory independent of issue rate).
- Background prune task (`NONCE_PRUNE_INTERVAL_SECS`, default 60s) drops expired entries.
- **Not safe at replicas > 1** — different replicas have independent maps; a nonce issued by
  replica A can be replayed on replica B. Set `REDIS_URL` for scale-out.

**Redis / Dragonfly** (`REDIS_URL` set)
- `GETDEL` is atomic: a nonce is consumed exactly once fleet-wide (no replay across replicas).
- Expiry is the Redis key TTL; no background prune needed.
- Requires Redis ≥ 6.2 or Dragonfly for `GETDEL`. Older Redis needs `GET` + `DEL` (non-atomic —
  upgrade or use Dragonfly).
- `RedisNonceStore::insert` returns an error on a failed write; the challenge endpoint answers
  `503` instead of issuing a nonce that could never verify.
- Redemption release is a Lua compare-and-delete (only a `leased` value is removed), so it can
  never erase a concurrent commit.

## HTTP client

Uses `hyper 1.x + hyper-rustls` directly (not reqwest) to avoid the `url → idna → icu_normalizer`
compile-time dep chain (~10 min on GHA). All URLs are operator-configured ASCII domains —
`hyper::Uri` parses them without IDNA processing.

## Deployment targets

- **Docker:** Dockerfile uses a multi-stage build (notices → builder → distroless); the image carries `/app/THIRD_PARTY_LICENSES.txt` (`cargo-about`, `about.toml`; an unaccepted licence fails the build and the `notices` CI job). Published to quay.io and Docker Hub
  (signed, with an SBOM attestation) by `docker-publish.yml` on a `v*` tag.
- **Kubernetes:** no manifests live in this repo, and the gateway is not deployed (the paywall runs on
  `gateway-workers/`; audit F32, OQ9). Deploy by image digest with a non-root, read-only-root pod.
- **Decision (OQ9, 2026-10-19): stay undeployed.** No Meddleware small-body upstream exists; the Workers gateway on Workers Free costs nothing, while self-hosting the relay path would need streaming bodies (audit F6) and a persistent, highly available Redis for the 30-day redemption records, which is more operations for a sole maintainer and weaker consistency than Durable Objects. It stays CI-green at parity as the self-host / white-label artefact. Revisit when a small-body upstream appears, a white-label customer must self-host, or Workers Free proves insufficient while Workers Paid is unaffordable (then streaming, F6, comes first).
- **Bare metal / VM:** `cargo install access-gate-gateway` or `cargo build --release`.

## Ownership cache

`OWNERSHIP_CACHE_TTL_MS` defaults to `0` (disabled — every gated check is live on-chain).
A small positive value collapses duplicate RPC lookups under load at the cost of a brief
staleness window on NFT transfer/burn. Never applied to single-use consume-event checks (always
live). Use with care on mainnet — a stolen/transferred NFT can still gate during the TTL window.

## Invariants

- Every gateway-generated answer is JSON `{"error": reason}` (`JsonReply` in the core). Do not return plain-text error bodies.
- `access_gate_gateway_core::headers::extract_proof_token` prefers `Authorization: Bearer` over `X-Access-Proof`. This order is
  canonical — do not flip it without updating both impls and the client.
- The verification logic is `../core/src/decision.rs` (and `sig.rs`), shared with the Rust Worker; the TypeScript
  Workers `verify.ts` is the retiring twin. Any behavioural change is made in the core once and, until the
  TypeScript Worker is retired, mirrored there; run the conformance vectors on both.
- `decode_access_proof` normalises `consumeDigest` (camelCase from JS) to `consume_digest`
  (snake_case for serde) before deserialising. If the JSON key ever changes on the client side,
  this must change too.

## What NOT to do

- Do not put decision logic, policy or request flow in this crate: it belongs in `../core` (the Worker needs it too).
- Do not use `tokio::sync::Mutex` where `std::sync::Mutex` suffices — the nonce map and rate
  limiter only hold the lock for in-memory ops (no `.await` inside the critical section).
- Do not add per-path routing in the router — the single `fallback` handler keeps the logic
  co-located and mirrors the Workers structure.
- Do not change the Redis key prefix (`nftgate:nonce:`) without a migration plan — live nonces
  in Redis would be orphaned.
- Do not remove the hard entry cap from the in-memory store — unbounded growth under high issue
  rates is a DoS vector.
