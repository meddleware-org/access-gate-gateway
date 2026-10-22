# nft-gate-core

The one implementation of what an [nft-gate](../README.md) gateway decides and does. A request is
admitted when it carries a Sui personal-message signature over an audience-bound message plus either live
ownership of an `access_gate` pass (ownership mode) or the digest of a recent successful on-chain consume
(single-use mode). Everything in that sentence lives here, once.

The crate has **no hyper, no tokio, no clock, no RNG and no logging**. It compiles natively and for
`wasm32-unknown-unknown`, so the same code runs in the hyper/axum gateway ([`../gateway-rust`](../gateway-rust))
and in the Cloudflare Worker (workers-rs). A platform is an adapter that supplies I/O only.

```text
            ┌──────────────── nft-gate-core ────────────────┐
 request ──▶│ RequestHead ─▶ Gateway::handle ─▶ Reply        │──▶ response
            │   loop guard · challenge · public paths ·      │
            │   proof → decision → redemption lease/commit   │
            └──┬───────────┬────────────┬───────────┬────────┘
               │           │            │           │
          StateStore   ChainQuery    Upstream   Clock · Rng
   memory | Redis | DO   SuiRpc<Transport>   hyper | fetch   system | crypto
```

## Modules

| Module | What it holds |
| --- | --- |
| `proof` | the access-proof token and the signed message (`nft-gate:access:v2`); strict decoding |
| `sig` | Sui signature schemes: ed25519 (ZIP-215), secp256k1, secp256r1 (low-S); address helpers; multisig / zkLogin fail closed |
| `decision` | `verify_access_request`: the allow / deny decision over `ChainQuery` and `NonceTake` |
| `grpc`, `chain` | the hand-rolled protobuf and gRPC-web codec, the `Transport` port, and the Sui reads (`GetTransaction`, `ListOwnedObjects`, `GetObject`) |
| `redemption` | the nonce, rate-window and lease / commit / release tables as pure state machines over an explicit clock |
| `state` | the `StateStore`, `Clock` and `Rng` ports and the in-memory implementation built on `redemption` |
| `headers` | header lists and predicates (hop-by-hop, request / response strip, `Via` loop marker), the safe-path rule, proof-token extraction, CORS grants |
| `forward` | forwarding policy: methods, preflight (405 / 400 / 413), redirect and fault answers |
| `net` | client-IP keying (`X-Forwarded-For` by trusted hops; IPv6 by /64) |
| `origin` | canonical-origin rule and origin normalisation for the request-loop guard |
| `config` | the `Env` port and the validated `GatewayConfig` |
| `gateway` | `Gateway::handle` and `redeem_and_forward`: the request flow as a state machine over the ports |

## Ports a platform supplies

| Port | Meaning | gateway-rust | Cloudflare Worker |
| --- | --- | --- | --- |
| `StateStore` | issue / take nonces, charge rate windows, lease / commit / release a redemption | `MemoryStore` or Redis (Lua compare-and-set), in-memory rates | SQLite Durable Object running the same rules (`core/tests/scenario.json` pins both) |
| `ChainQuery` | the Sui reads | `SuiRpc<HyperTransport>` | `SuiRpc<FetchTransport>` |
| `Upstream` | move the request to the protected origin, apply the header policy, answer faults with the shared refusals | buffered hyper client | streamed `fetch` |
| `Clock`, `Rng` | time and entropy | monotonic-anchored system clock, `OsRng` | `Date.now()`, `crypto.getRandomValues` |
| `Env` | configuration | process environment | Worker `vars` and secrets |

`Gateway::handle(&RequestHead, U::Request) -> Reply<U::Response>` returns either a gateway-generated
`JsonReply` (`status`, JSON `body`, an optional `Allow`, and an operator-only `diag` for the log that is
never sent to the client) or the upstream's own response. `/healthz`, CORS and a platform's connection
limits stay in the adapter.

## Configuration rules (one set)

`config::GatewayConfig::from_env(&dyn Env)` validates every shared variable once. The two earlier
implementations (Rust `config.rs`, TypeScript `config.ts`) disagreed in a few places; the **stricter rule
won** in each:

| Variable / rule | Rust (before) | TypeScript (before) | Now |
| --- | --- | --- | --- |
| lease vs deadlines | `REDEMPTION_LEASE_TTL_SECS > UPSTREAM_TIMEOUT_SECS + BODY_READ_TIMEOUT_SECS` | `> UPSTREAM_TIMEOUT_SECS` only | the Rust rule (a lease must outlive the whole request, audit F46) |
| `http://` for `GATEWAY_ORIGIN`, `UPSTREAM_URL`, `SUI_RPC_URL`, `ALLOWED_ORIGINS` | only with `ALLOW_INSECURE_HTTP=1` | loopback hosts always allowed, no flag | the Rust rule: an explicit opt-in everywhere (a Worker run against a local upstream sets the flag) |
| request-loop guard | raw `scheme://host[:port]` text compare | `URL.origin` compare (case and default port folded) | normalised compare: scheme and host lower-cased, default port dropped |
| URL shape | prefix and userinfo checks only (`https://` passed) | `new URL(..)` rejected an empty host, whitespace | empty host, whitespace, control characters and backslashes are refused |
| `ALLOWED_ORIGINS` host | lower-case ASCII `[a-z0-9.-]` only | any host `URL` accepts (IPv6 literals, `_`) | the Rust rule |
| `..` path segment (`is_safe_path`) | refused | not checked (the Cloudflare URL parser normalises dot segments first, so not exploitable there) | refused, in the one implementation |
| numbers and booleans | strict integers in range; exactly `true` / `false` | the same | unchanged (identical) |
| `NFT_TYPE`, `GATE_ID`, `PUBLIC_PATHS`, auth-header formats | identical | identical | unchanged |

Platform-only variables are parsed by the platform with the same helpers (`config::int`, `boolean`,
`required`): the native `BIND_ADDR`, `REDIS_URL`, `TRUSTED_PROXY_HOPS` and connection limits
(`gateway-rust/src/config.rs`), and the Worker's `NONCE_SHARD`, `WORKERS_PLAN` and `PUBLIC_*`. The Workers
KV nonce backend is not carried over to the Rust Worker (it was refused with `SINGLE_USE=true` and offered
only eventual consistency in ownership mode).

## Build and test

```sh
cargo test -p nft-gate-core                              # native, the core alone (its own minimal feature set)
cargo build -p nft-gate-core --target wasm32-unknown-unknown   # the Worker's target (CI job `core`)
```

`tests/conformance.rs` runs the shared golden vectors (`../conformance/vectors.json`, including the `txDigest` rule: `is_tx_digest` is base58 that decodes to exactly 32 bytes); the `gateway` unit test `the_shared_response_vectors_are_what_the_gateway_answers` drives every `responses` outcome and compares the status and body; `tests/decision.rs`
builds real ed25519 / secp256k1 / secp256r1 proofs and judges them; `tests/scenario.rs` runs
`tests/scenario.json` (39 steps, explicit clock) against the state machines, and the same file runs against
the Worker's Durable Object so the SQL and the Rust rules cannot drift; `tests/transport_stub.rs` runs the
chain reads over a scripted `Transport`. The `gateway` and `state` modules carry unit tests with scripted
ports (loop guard, challenge, public paths, 401 / 403 / 429 / 502 / 503 mapping, the whole lease / commit /
release flow including a lost lease and a failing commit).

The tests (and the `gateway` unit tests) read the shared vectors at `../conformance/vectors.json`, so they run from the repository checkout, not from the published package.

## Rust version

`rust-version = "1.88"` (checked in CI for this crate and `gateway-rust`). The Worker crate `../worker` is a workspace member
with its own `rust-version = "1.91"` (workers-rs needs it) and is built and tested by the `worker` CI job.

## Licence

[0BSD](../LICENSE)
