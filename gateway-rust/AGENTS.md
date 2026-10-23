# AGENTS.md — gateway-rust

## Crate

`access-gate-gateway` — the Rust/Axum adapter of the access-gate gateway. The decision logic is the sibling crate
`access-gate-gateway-core` (`../core`), shared with the Cloudflare Worker; this crate supplies I/O only.

## Key files

| File | Purpose |
| --- | --- |
| `src/main.rs` | Binary entry point; `AppState`; `RequestHead` ⇄ axum mapping; `handle` (builds the core `Gateway`); CORS; router; hyper accept loop |
| `src/config.rs` | `ServerConfig` = core `GatewayConfig` + native-only variables; `ProcessEnv` |
| `src/state.rs` | `SystemClock`, `OsRngSource`, `NativeState` (the `StateStore` the core uses) |
| `src/challenge.rs` | `NonceStore` enum (core in-memory state machine / Redis); `RedisNonceStore` |
| `src/proxy.rs` | `forward` — the buffered reverse proxy; `impl Upstream for AppState` |
| `src/headers.rs` | applies the core's header policy to `http::HeaderMap` |
| `src/grpc.rs`, `src/sui_rpc.rs` | `HyperTransport`; `new_sui_rpc`; hermetic gRPC-web fixtures |
| `src/http_client.rs` | `HttpClient` — shared hyper/rustls async client |
| `Dockerfile` | Multi-stage Docker build (notices → builder → distroless); build context is the repository root |
| `about.toml`, `about.hbs` | `cargo-about` configuration (accepted licences) and template for `/app/THIRD_PARTY_LICENSES.txt` |
| `Cargo.toml` | Crate manifest (version, edition and MSRV inherited from the workspace) |

Decision logic lives in `../core/src`: `decision.rs` (verify_access_request, `Denied`), `sig.rs`, `proof.rs`, `chain.rs`,
`grpc.rs`, `gateway.rs` (the request flow), `state.rs`, `redemption.rs`, `headers.rs`, `forward.rs`, `config.rs`, `net.rs`, `origin.rs`.

## Build and test commands

```bash
# from the repository root (the Cargo workspace)
cargo build -p access-gate-gateway            # debug build
cargo build --release -p access-gate-gateway  # release build
cargo test --workspace                     # core + gateway-rust (unit, router, shared vectors)
cargo test -p access-gate-gateway-core                # the core alone
cargo test --workspace -- --nocapture      # with test output
```

## Docker build and run

```bash
# Build image (from the repository root: the build context is the Cargo workspace)
docker build -f gateway-rust/Dockerfile -t access-gate-gateway .

# Run (minimum required env vars)
docker run \
  -e UPSTREAM_URL=https://your-relay.example.com \
  -e SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
  -e NFT_TYPE=0x<pkg>::access_gate::AccessNFT \
  -p 8080:8080 access-gate-gateway

# With Redis for horizontal scale-out
docker run \
  -e UPSTREAM_URL=https://your-relay.example.com \
  -e SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
  -e NFT_TYPE=0x<pkg>::access_gate::AccessNFT \
  -e REDIS_URL=redis://dragonfly:6379 \
  -p 8080:8080 access-gate-gateway
```

## Install from crates.io

```bash
cargo install access-gate-gateway
UPSTREAM_URL=https://relay.example.com SUI_RPC_URL=https://... NFT_TYPE=0x... access-gate-gateway
```

## Version

One version for every artifact (D16): the `[workspace.package]` version in the root `Cargo.toml`, inherited by
`access-gate-gateway-core` and `access-gate-gateway`, equals `gateway-workers/package.json`; the gateway pins `access-gate-gateway-core`
at exactly that version. `scripts/check-versions.sh` enforces it. The tag's `crates-publish.yml` publishes the
core first, then the gateway.

## Conformance vectors

`../core/tests/conformance.rs` loads `../../conformance/vectors.json` via `include_str!`. Run `node scripts/sync-vectors.mjs` (the vectors are generated and published by `@meddleware/access-gate-gateway-client`)
(from the `access-gate-gateway` repo root) to regenerate after any wire-format change.

## Relation to gateway-workers

The two gateways are wire-identical: same endpoints, same env var names (where applicable),
same proof format, same Sui RPC call shapes. The Rust side is one implementation (`../core`); until the
TypeScript Worker is retired, a wire-format change is applied to the core and to `gateway-workers`, and the
conformance vectors regenerated. See `../CLAUDE.md` for the coupling invariants.
