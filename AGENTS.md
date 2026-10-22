# AGENTS.md — nft-gate

## Repo layout

One core (the decision logic, Rust, native + wasm32), two adapters.

```
nft-gate/
├── Cargo.toml, Cargo.lock      # Cargo workspace: core + gateway-rust (one version, D16)
├── deny.toml                   # cargo-deny policy for the workspace (incl. the wasm32 target)
├── conformance/
│   └── vectors.json            # Shared golden wire-format test vectors (core + TypeScript consume this)
├── core/                       # nft-gate-core: ALL the decision logic (no hyper/tokio/clock/RNG/logging)
│   ├── src/
│   │   ├── gateway.rs          # Gateway::handle / redeem_and_forward over the ports (the request flow)
│   │   ├── decision.rs         # verify_access_request, ChainQuery, Denied
│   │   ├── sig.rs, proof.rs    # signature schemes, proof token + signed message
│   │   ├── grpc.rs, chain.rs   # gRPC-web codec + Transport port; Sui reads
│   │   ├── redemption.rs       # nonce / rate / lease-commit-release state machines (explicit clock)
│   │   ├── state.rs            # StateStore, Clock, Rng ports + in-memory implementation
│   │   ├── headers.rs, forward.rs, net.rs, origin.rs   # header / path / CORS / forwarding / client-IP / origin policy
│   │   └── config.rs           # Env port + the validated GatewayConfig
│   └── tests/                  # conformance vectors, real-signature decisions, scenario.json, scripted Transport
├── worker/                     # the Rust Cloudflare Worker (workers-rs) on the core: built, shadow not yet deployed; replaces gateway-workers 1:1
│   ├── src/                    # lib.rs, state.rs + do_state.rs (Durable Object), upstream.rs (streamed proxy), transport.rs, config.rs, quota_guard.rs ...
│   ├── tests/                  # black-box workerd suites + the differential run against gateway-workers (Node, test code only)
│   └── scripts/                # build, checksummed tool download, size gate, lint canary, shadow config, cold-start instruments
├── ci/                         # nft-gate-ci: UPSTREAM_AUTH_HEADERS check and origin-lock verdicts for the workflows
├── gateway-workers/            # Cloudflare Workers gateway (TypeScript; LIVE; superseded pending cutover, not deleted: it is the rollback)
│   ├── src/                    # index.ts, config.ts, verify.ts, chain.ts, proxy.ts, quota.ts, state/ (DO + KV) ...
│   ├── test/                   # vitest unit + cloudflare-integration tests
│   ├── wrangler.toml           # Cloudflare Workers config (edit routes here)
│   └── package.json            # @meddleware/nft-gate-gateway
├── gateway-rust/               # Rust / Axum adapter (I/O only: hyper server, hyper client, Redis, clock, entropy)
│   ├── src/                    # main.rs, config.rs, state.rs, challenge.rs, proxy.rs, headers.rs, grpc.rs, sui_rpc.rs, http_client.rs
│   ├── Dockerfile              # build context = the repository root
│   └── Cargo.toml              # nft-gate-gateway (version from the workspace)
└── README.md                   # Top-level quickstart + wire protocol docs
```

## Common tasks

### Run all tests

```bash
# Workers (unit + conformance vectors)
cd gateway-workers && npm test

# Workers (all: unit + cloudflare integration)
cd gateway-workers && npm run test:all

# Rust: core + gateway-rust (unit, router, scripted ports, conformance vectors)
cargo test --locked --workspace

# The Rust Worker: build both variants, size gate, every workerd suite, the differential run (needs `npm ci` in gateway-workers too)
cd worker && npm ci && bash scripts/build.sh all && bash scripts/size-gate.sh && npm test

# The core alone, and its wasm32 build (the Worker's target)
cargo test --locked -p nft-gate-core
cargo build --locked -p nft-gate-core --target wasm32-unknown-unknown
```

### Type-check (Workers)

```bash
cd gateway-workers && npm run type-check
```

### Regenerate conformance vectors

```bash
node scripts/sync-vectors.mjs   # vectors come from @meddleware/nft-gate-client
# before a client release is published (refused when CI is set):
NFT_GATE_CLIENT_VECTORS=../nft-gate-client/vectors.json node scripts/sync-vectors.mjs
```

Both test suites will pick up the new vectors automatically.

### Deploy to Cloudflare Workers

```bash
cd gateway-workers && npm run deploy

# Set the required secret after first deploy; NFT_TYPE, GATE_ID and SUI_RPC_URL are wrangler.toml [vars]
wrangler secret put UPSTREAM_URL
```

### Build and run Rust Docker image

```bash
# from the repository root (the Cargo workspace is the build context)
docker build -f gateway-rust/Dockerfile -t nft-gate-gateway .
docker run -e UPSTREAM_URL=http://relay:8080 \
           -e SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
           -e NFT_TYPE=0x<pkg>::access_gate::AccessNFT \
           -p 8080:8080 nft-gate-gateway
```

### Build Rust binary locally

```bash
cargo build --release -p nft-gate-gateway
UPSTREAM_URL=http://relay:8080 SUI_RPC_URL=https://... NFT_TYPE=0x... ./target/release/nft-gate-gateway
```

## Key environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `UPSTREAM_URL` | Yes | — | Base URL of the upstream to protect |
| `GATEWAY_ORIGIN` | Yes | — | This gateway's canonical public origin (signed into every proof) |
| `NETWORK` | Yes | — | `localnet` \| `devnet` \| `testnet` \| `mainnet` (signed into every proof) |
| `SUI_RPC_URL` | Yes | — | Sui fullnode (gRPC-web) |
| `NFT_TYPE` | Yes | — | `<pkg>::access_gate::AccessNFT` or `SoulboundAccessNFT` |
| `GATE_ID` | Yes | — | The gate whose passes are accepted |
| `SINGLE_USE` | No | `false` | Require on-chain single-use consume |
| `PUBLIC_PATHS` | No | `/v1/tip-config` | Comma-separated public paths (no auth) |
| `RATE_LIMIT_PER_MIN` | No | `30` | Per-address request budget per minute |
| `CHALLENGE_TTL_SECS` | No | `300` | Nonce lifetime in seconds |

Workers-only extras: `NONCE_BACKEND`, `NONCE_KV` binding, `NONCE_STATE` binding, `QUOTA_GUARD_ENABLED`, `WORKERS_PLAN`.  
Rust-only extras: `REDIS_URL`, `BIND_ADDR`, `TRUSTED_PROXY_HOPS`, the connection limits.

## CI

Each side has its own GitHub Actions CI:
- `gateway-workers` (`node-ci.yml`): type-check + lint + vitest unit and workerd tests
- Rust (`rust-ci.yml`): fmt, clippy `-D warnings`, `cargo test --workspace`, the Redis round trip, coverage, `cargo deny`; a `core`
  job (native tests of the core alone + `cargo build -p nft-gate-core --target wasm32-unknown-unknown`); an MSRV job (1.88); a Trivy
  scan of the Dockerfile

The conformance vector tests run in the core's suite and in the TypeScript suite.
