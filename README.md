# nft-gate

[![npm](https://img.shields.io/npm/v/%40meddleware%2Fnft-gate-gateway)](https://www.npmjs.com/package/@meddleware/nft-gate-gateway)
[![Crates.io](https://img.shields.io/crates/v/nft-gate-gateway)](https://crates.io/crates/nft-gate-gateway)
[![License: 0BSD](https://img.shields.io/badge/license-0BSD-blue)](LICENSE)

A generic NFT-gated reverse proxy for the [access_gate](https://github.com/meddleware-org/access-gate-sui) primitive on Sui. Put it in front of any HTTP upstream — an upload relay, a website, a game API — to restrict access to holders of an on-chain access NFT.

The decision logic exists **once**, in [`core/`](core/) (`nft-gate-core`, Rust): proof decoding, Sui signature
verification, the allow / deny decision, the Sui reads, the nonce / rate / redemption state machines, the
header, path and configuration policy, and the request flow itself. A gateway is a thin adapter around it that
supplies only I/O (HTTP, state storage, clock, entropy). Two adapters exist; choose one based on your
deployment target:

| Implementation | Directory | Distributed as | Deploy target | State backend |
| --- | --- | --- | --- | --- |
| Cloudflare Workers (live, TypeScript; superseded pending cutover) | [`gateway-workers/`](gateway-workers/) | [npm package](https://www.npmjs.com/package/@meddleware/nft-gate-gateway) | Wrangler deploy | Durable Objects or KV |
| Cloudflare Workers (Rust; built, shadow not yet deployed) | [`worker/`](worker/) | built from source (`worker-build`) | `deploy-worker-rust.yml` (shadow, then cutover) | Durable Objects |
| Rust / Axum | [`gateway-rust/`](gateway-rust/) | [crates.io](https://crates.io/crates/nft-gate-gateway) / Docker | Docker / k8s | In-memory or Redis |

The live Workers gateway is still TypeScript (`gateway-workers/`) and is **superseded, pending cutover, by a Rust
Worker (workers-rs) built on the same core**: [`worker/`](worker/) (0.0.27) is built and tested (workerd suites that
port every behavioural case of the TypeScript tests, plus a differential run against it), but not yet deployed. The
maintainer deploys it as a shadow first and cuts over after reading the CPU-time p99 in Workers analytics; the
TypeScript gateway stays as the rollback until then and is retired afterwards, leaving one implementation of the
logic on both platforms. See [worker/README.md](worker/README.md) (build, test map, runbook).

Both gateways serve the same wire protocol and verify the same [conformance vectors](conformance/).

The client-side counterparts are on npm: the wire protocol (challenge fetching, proof construction) in
[`@meddleware/nft-gate-client`](https://github.com/meddleware-org/nft-gate-client), and the `access_gate`
reads and transaction builders in [`@meddleware/access-gate-client`](https://github.com/meddleware-org/access-gate-client).

## Quickstart (Cloudflare Workers)

> Prerequisites: Node.js ≥ 22, Wrangler 4.x, a Cloudflare account.

```bash
# 1. Clone or fork this repo
git clone https://github.com/meddleware-org/nft-gate.git
cd nft-gate/gateway-workers

# 2. Install dependencies
npm install

# 3. Create the Worker in your Cloudflare account (first deploy only)
npm run deploy

# 4. Set the required secrets (run once after the Worker exists)
wrangler secret put UPSTREAM_URL        # e.g. https://your-relay.example.com
# …and set NFT_TYPE = "0x<pkg>::access_gate::SoulboundAccessNFT" and GATE_ID = "0x<gate id>"
# in wrangler.toml [vars] (both are public on-chain values)
wrangler secret put UPSTREAM_AUTH_HEADERS  # JSON: [{"name":"CF-Access-Client-Id","value":"<id>"},{"name":"CF-Access-Client-Secret","value":"<secret>"}]

# 5. Configure the route (edit wrangler.toml, then redeploy)
npm run deploy
```

See [gateway-workers/README.md](gateway-workers/README.md) for the full configuration reference.

## Quickstart (Rust / Docker)

> Prerequisites: Docker, or Rust stable + Cargo.

```bash
# Docker
docker pull meddleware/nft-gate-gateway:latest
docker run -e UPSTREAM_URL=http://relay:8080 \
           -e SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
           -e NFT_TYPE=0x<pkg>::access_gate::AccessNFT \
           -e GATE_ID=0x<gate id> \
           -p 8080:8080 meddleware/nft-gate-gateway

# From source (the image is built from the repository root, which is the Cargo workspace)
docker build -f gateway-rust/Dockerfile -t nft-gate-gateway .

# Or from crates.io (requires Rust stable)
cargo install nft-gate-gateway
UPSTREAM_URL=http://relay:8080 SUI_RPC_URL=https://fullnode.mainnet.sui.io:443 \
  NFT_TYPE=0x<pkg>::access_gate::AccessNFT GATE_ID=0x<gate id> nft-gate-gateway
```

(`GATEWAY_ORIGIN=https://<this gateway's public origin>` and `NETWORK=<localnet|devnet|testnet|mainnet>` are also required: they are signed into every proof.)

See [gateway-rust/README.md](gateway-rust/README.md) for the full configuration reference.

## Wire protocol

**Challenge** — `GET /v1/challenge` returns `{ nonce, expiresAt }`.

**Signed message** — the client signs an audience-bound, human-readable message as a Sui personal message (ed25519, secp256k1, or secp256r1):

```text
nft-gate:access:v2
origin:<this gateway's canonical origin>
gate:<0x + 64 lower-case hex>
network:<localnet|devnet|testnet|mainnet>
nonce:<nonce>
consume:<base58 digest>        (single-use gateways only)
```

The gateway rebuilds it from its own `GATEWAY_ORIGIN`, `GATE_ID` and `NETWORK`, so a proof made for another gateway, gate, network or consume cannot be replayed here.

**Proof token** — `base64(JSON { address, nonce, signature, consumeDigest? })`, sent as `Authorization: Bearer <token>` or `X-Access-Proof`.

**Verification** — the gateway checks the signature recovers the claimed address, the nonce is fresh and unused, and the address owns the required NFT (or, in single-use mode, has submitted a matching on-chain consume transaction). Then it proxies to the upstream.

**Scope** — the gateway gates only on `access_gate` passes of one gate (`NFT_TYPE` must be an
`access_gate` pass type and `GATE_ID` is required), so every admitted user holds a pass that gate
sold or granted. If the gate's immutable policy has `pause_blocks_access`, pausing the gate denies
all holders (`403`) until it is unpaused; in single-use mode the check runs before the consume is
redeemed, so no use is lost.

## Conformance

`conformance/vectors.json` contains golden wire-format vectors signed with real Sui keypairs for all three signature schemes, plus audience-mismatch, negative-signature, ZIP-215 and token-grammar cases. They are generated and published by [`@meddleware/nft-gate-client`](https://github.com/meddleware-org/nft-gate-client) (the protocol's home); this repository keeps a copy so the Rust gateway can read it, and CI checks the copy against the installed package. Both gateway implementations test against it. After a protocol change, release the client, bump it here, then:

```bash
node scripts/sync-vectors.mjs          # copy the installed package's vectors
node scripts/sync-vectors.mjs --check  # CI: fail if the copy differs
```

## Choosing an implementation

**Use `gateway-workers/` if:**

- You want zero-infrastructure deployment via Wrangler
- Cloudflare's global edge distribution suits your topology
- You are already using Cloudflare for DNS / CDN

**Use `gateway-rust/` if:**

- You are deploying to Kubernetes or any container-based infrastructure
- You need Redis-backed nonce state for horizontal scale-out
- You want the lowest possible latency on your own hardware

Both expose the same endpoints, accept the same environment variables, and produce identical verification decisions for any given proof token (for the Rust gateway this is by construction: the decision is the shared core). The Rust gateway buffers request bodies, so it is scoped to small-body upstreams (see its README, "Request body limit"); it is not a drop-in for a 100 MiB upload relay.

Meddleware's own deployment decision (audit OQ9, 2026-10-19): the Rust gateway **stays undeployed**. No Meddleware small-body upstream exists; the Workers gateway on Workers Free costs nothing, while self-hosting the relay path would need streaming bodies (audit F6) and a persistent, highly available Redis for the 30-day redemption records, which is more operations for a sole maintainer and weaker consistency than Durable Objects. It stays CI-green at parity as the self-host / white-label artefact. Revisit when a small-body upstream appears, a white-label customer must self-host, or Workers Free proves insufficient while Workers Paid is unaffordable (then streaming, F6, comes first).

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --locked --workspace -- -D warnings
cargo test --locked --workspace                      # core + gateway-rust + worker (glue) + ci
cargo build -p nft-gate-core --target wasm32-unknown-unknown   # the Worker's target
(cd worker && npm ci && bash scripts/build.sh all && npm test)  # the Rust Worker: wasm build, workerd suites, differential
(cd gateway-workers && npm ci && npm run test:all)   # the TypeScript Workers gateway (until it is retired)
bash scripts/check-versions.sh                       # one version for every artifact
```

The Rust crates form one Cargo workspace at the repository root (`Cargo.toml`, `Cargo.lock`, `deny.toml`):
`core/`, `gateway-rust/`, `worker/` (the Cloudflare Worker; rust-version 1.91 for this crate only) and `ci/` (the
helper the deploy and origin-lock workflows call). The feasibility spike's findings are kept in
[docs/SPIKE-FINDINGS.md](docs/SPIKE-FINDINGS.md).

## License

[0BSD](LICENSE)
