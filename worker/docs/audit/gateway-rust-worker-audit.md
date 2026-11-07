# access-gate-gateway — Rust Worker (`worker/`) Security Audit

**Classification:** Internal security review
**Project:** access-gate-gateway/worker  (the live Cloudflare Worker that admits only holders of an on-chain `access_gate` pass to the
  operator's Walrus upload relay: an I/O adapter in Rust (workers-rs, wasm32) on the shared `access-gate-gateway-core` crate in `../core`,
  with the region-sharded SQLite Durable Object `NonceRateState` as its state; it replaced the TypeScript Worker `gateway-workers` 1:1)
**Project type:** Cloudflare Worker (Rust, wasm32-unknown-unknown) + shared Rust crate (`core/`, published to crates.io)
**Template:** AUDIT_TEMPLATE.md (2026-11-01) + AUDIT_TEMPLATE_RUST.md (2026-10-08) + AUDIT_TEMPLATE_WORKERS.md (2026-10-02) +
  AUDIT_TEMPLATE_SUI_CLIENT.md (2026-10-08) + AUDIT_TEMPLATE_WALRUS.md (2026-09-30) + AUDIT_TEMPLATE_AUTH.md (2026-10-08) +
  AUDIT_TEMPLATE_PROXY.md (2026-10-08)
**Deployment status:**

- **Live on testnet** under the Worker name `access-gate-gateway` (route `sui-walrus-storage-relay-testnet.meddleware.dev/*`, zone `meddleware.dev`
  per `worker/wrangler.toml`). Cutover from the TypeScript Worker on 2026-10-20 (`Deploy Worker (Rust)` run 39418735654, from the audit history of
  `gateway-workers`). Read this pass with `gh run list` (2026-11-07): the last successful `Deploy Worker (Rust)` run is 40489741990
  (`workflow_dispatch`, 2026-10-27T10:36Z, head `4c167ac86902505fd74ba0351467932b1adc471c`); the run before it (40488874691, 2026-10-27T10:29Z) failed.
  `main` is at `875220d` (0.0.33 plus Dependabot merges); **the fixes of this pass (F58, F59, F60, F61, F62) are not deployed** (FU-0031).
  What is deployed cannot be read from the repository: the `Deploy Worker (Rust)` run's head SHA is the evidence, not the live script.
- Version 0.0.33 (tag `v0.0.33`, 2026-10-30; one version for every artifact, D16). The crate `access-gate-gateway-core` is on crates.io; the Worker crate is
  `publish = false` and built from source.
- Consumes the testnet `access_gate` `0xd7ddaa94…388c9` (original-id) and the relay gate `0x316f1bf9…faddc` through `[vars]` in `worker/wrangler.toml`
  (`NFT_TYPE`, `GATE_ID`); `SINGLE_USE = "true"`, `NETWORK = "testnet"`. Not re-read on chain here.
- The Origin lock workflow: 32 of 32 runs succeeded (28 scheduled, 3 pull request, 1 manual), 2026-10-10 to 2026-11-07 (`gh run list`).
- Ids are local to this audit. F51–F57 are the ids they had in `gateway-workers-audit.md` (moved here, ids preserved); F58 and later are new here and are not
  the `gateway-workers` F58.

**Review date:** 2026-11-07 (first pass of this audit; the Rust Worker's own findings F51–F57 date from 2026-10-19/22 and were re-verified in this pass)
**Reviewer:** Internal review
**Severity ceiling:** High — the Worker is the only paywall in front of the operator's Walrus relay: a verification bypass gives unpaid uploads at the operator's
  cost, and a redemption flaw lets one paid consume buy many uploads. It holds no user funds and signs nothing on-chain, so nothing reaches Critical.
**Status:** first pass 2026-11-07 — 14 findings dispositioned (**3 RESOLVED**: F58, F60, F62; **6 MITIGATED**: F51, F53, F54, F55, F57, F59; **1 ACCEPTED-RISK**: F52;
  **4 DEFERRED**: F61, F63, F64, F65) plus **2 Positive** (F56, F66) — 16 findings, F51–F66. Items that need Cloudflare or the maintainer are follow-ups FU-0029 to FU-0037.

**Toolchain:** `rust-version = "1.91"` for the Worker crate (workers-rs needs it); core and gateway-rust stay at 1.88 (the `msrv` job checks those two)
  **Edition:** 2021
**Crates published:** no (Worker, `publish = false`); `access-gate-gateway-core` yes, crates.io trusted publishing (`crates-publish.yml`, OIDC)
**Runtime:** workerd, single-threaded wasm32 isolate; no tokio. workers-rs `worker` 0.8.7, wasm-bindgen 0.2.129, worker-build 0.8.7 (pinned exactly, F52)

**Sui SDK:** none — hand-rolled gRPC-web + protobuf client in `core/src/{grpc,chain}.rs`, `fetch` transport in `worker/src/transport.rs`; crypto
  `ed25519-consensus` 2.1.0, `k256` 0.14.0, `p256` 0.14.0, `blake2` 0.11.0 (lockfile read 2026-11-07)
**Transport:** gRPC-web (`application/grpc-web+proto`) — no JSON-RPC
**Networks:** testnet deployed; any network by configuration (`NETWORK`, `SUI_RPC_URL`, `NFT_TYPE`, `GATE_ID`)
**On-chain packages consumed:** `access_gate` original-id = published-at `0xd7ddaa94…388c9` (v1, 2026-10-09), sourced from `wrangler.toml` `[vars]`; gate
  `0x316f1bf9…faddc`; no call targets (the Worker never builds a PTB)

**Wrangler / compatibility:** wrangler 4.156.1 and workerd 1.20261101.1 (harness lockfile, `worker/package-lock.json`); `compatibility_date = "2026-06-01"`; no
  `compatibility_flags`; `workers_dev = false`, `preview_urls = false`
**Cloudflare plan:** **Workers Free** at launch (`WORKERS_PLAN = "free"`, decided 2026-10-19 in the TypeScript audit's OQ3); not re-read from the account here
**Bindings:** Durable Object `NONCE_STATE` → class `NonceRateState`, migration tag `v1` (`new_sqlite_classes`); no KV; secrets (names only):
  `UPSTREAM_URL`, `UPSTREAM_AUTH_HEADERS`; optional `SUI_RPC_AUTH_HEADER`, `CF_ANALYTICS_TOKEN`, `CF_ACCOUNT_ID`; no `[triggers]` (the quota guard's cron is commented out)
**Routes / zones:** `sui-walrus-storage-relay-testnet.meddleware.dev/*` on zone `meddleware.dev`
**Deploy mechanism:** `.github/workflows/deploy-worker-rust.yml` (`workflow_dispatch`, `main` only, environment `production`, the full `rust-ci.yml` first); credential
  `CLOUDFLARE_API_TOKEN` (GitHub secret)

**Walrus SDK:** none — the Worker fronts the operator's upload relay (`UPSTREAM_URL`, a secret)
**Package config source:** n/a   **Upload relays:** the operator relay behind Cloudflare Access   **Aggregator / publisher hosts:** n/a
**Tip ceiling:** n/a (client SDK; the relay enforces)   **Epoch default / maximum:** n/a   **Deletable default:** n/a

**Auth role(s):** credential-injecting proxy (Cloudflare Access service token to the upstream; optional RPC auth header); verifier of signed access proofs
**Identity provider:** none (Cloudflare Access protects the upstream; the Worker is a client of it, not an IdP client)
**Token formats:** inbound `access-gate-gateway:access:v3` proof (base64 JSON + Sui signature over an audience-bound message); outbound static headers
**Signing / client credentials:** `UPSTREAM_AUTH_HEADERS`, `SUI_RPC_AUTH_HEADER`, `CF_ANALYTICS_TOKEN` (Worker secrets); `CLOUDFLARE_API_TOKEN`,
  `UPSTREAM_AUTH_HEADERS`, `UPSTREAM_URL`, `SUI_RPC_AUTH_HEADER` (GitHub secrets); inventory B.AUTH-1
**Authorization model:** on-chain — a successful, recent, single-use `consume` by the signer for the configured gate, redeemed once (deployed), or ownership of a
  usable pass (supported, not deployed)

**Upstreams:** one, `UPSTREAM_URL` (Worker secret; `https://` unless `ALLOW_INSECURE_HTTP=1`; refused when its origin equals `GATEWAY_ORIGIN`); locked to this hop
  by a Cloudflare Access service-token policy
**Public paths:** `PUBLIC_PATHS = /v1/tip-config`, `GET`/`HEAD` only (else 405 + `Allow`), rate-limited per client IP, `GET` cached 60 s at the edge
**Body cap / timeouts:** `MAX_BODY_BYTES` 100,000,000 B (declared length, and the streamed bytes); upstream total deadline 600 s (504); Sui RPC 15 s per call;
  header-read and idle timeouts are the Cloudflare edge's (B.PX-2)
**Trusted forwarding hops:** Cloudflare only; the client key is `CF-Connecting-IP`, IPv6 keyed by /64

---

## Executive summary

The Rust Worker is the live NFT-gated front of the Meddleware Walrus upload relay on testnet. It is about 1.8 kLOC of adapter (`worker/src`) on the ~6.1 kLOC shared
core (`core/src`, tests included), which holds the whole decision once and is also what `gateway-rust` runs. A request is admitted only with a Sui personal-message
signature over the audience-bound `access-gate-gateway:access:v3` message (origin, gate, network, nonce, consume digest), plus a successful, recent on-chain
`access_gate::consume` by the signer; the consume digest is leased under an owner token in a Durable Object, the upload is streamed to the Access-locked origin with
a counted byte cap, and the redemption is committed on a 2xx or released on any other outcome.

**Why this audit exists.** The Worker's findings F51–F57 lived in the superseded TypeScript Worker's audit, which has no Rust lens and is about to close with
`gateway-workers`. They are moved here with their ids and dispositions, each re-verified against the current code (below), and this audit applies the Rust, Workers,
Sui-client, Walrus, Auth and Proxy lenses to the Worker as it is.

**What this pass found (read in code, then fuzzed and tested):**

- **A panic in the shared core on hostile input (F58, Low, RESOLVED).** The first run of the new `grpc` fuzz target crashed after 184 inputs: a gRPC-web trailer line
  whose byte 12 falls inside a multi-byte character made `line[..12]` panic. On the Worker that is a wasm trap (the runtime's generic 500, fail closed, instance
  re-instantiated); in `gateway-rust` (`panic = "abort"`) it ends the process. Reachable only from the configured fullnode's response. Fixed in `core/src/grpc.rs` with
  regression tests and a `clippy::string_slice` deny (F61); the same target then ran 1,276,933 inputs in 111 s without a crash.
- **A narrower claim than F51 made (F61, Low, DEFERRED).** The panic lints of F51 cover the adapter crate only; the core, which holds the request path, is not under them.
  `clippy` with the lints on shows 32 sites in non-test core code; one was F58, the rest are bounds-guarded (listed), and `string_slice` is now denied.
- **A gap in F57 (F59, Low, MITIGATED).** Nothing inspected the bundle that is deployed for the test-hooks code (the route test covers only `/__test/*`, not the
  fault-injection and analytics-endpoint seams). `worker/scripts/assert-prod-build.sh` now does, in CI (with a self-test on the hooks variant) and in the deploy job.
- **A wasm32-only truncation (F60, Info, RESOLVED)** in the protobuf length (`as usize` on a 32-bit target), fixed with `usize::try_from`.
- **Stale status text (F62, Info, RESOLVED):** `SECURITY.md`, `README.md`, `AGENTS.md`, `CLAUDE.md` and the `gateway-workers` documents still described the TypeScript
  Worker as live and the Rust Worker as not deployed.
- **Open, Low:** the Sui RPC response is buffered before its size check (F63), a `304` from the relay becomes a `502` (F65, not shown to occur), and grants and denials are
  not logged (F64, a decision).

**What holds (Section A):** one decision implementation for both platforms; ZIP-215 ed25519 and explicit low-S on both ECDSA curves; proofs bound to audience; atomic,
owner-bound redemption in the Durable Object with a startup-checked lease; streamed byte cap with abort; redirects never followed; fail-closed errors; strict
configuration; no secret in logs. The daily negative origin-lock check has passed 32 of 32 runs.

**Not verified here (follow-ups):** edge CPU on real traffic (FU-0029), the live deploy token's scope and the zone it needs (FU-0030), that the origin-lock URL is the
Worker's secret origin (FU-0035), the workerd suites and the differential run (CI-only; not run here), mainnet readiness (FU-0036).

## Threat model / trust boundaries

**Primary trust anchor:** Sui chain state (the `AccessConsumedEvent` of a successful `consume`; pass ownership) as reported by the operator-configured fullnode, and the Sui
signature scheme that binds a proof to an address. **Second anchor:** the Cloudflare platform (execution, `CF-Connecting-IP`, `cf.continent`, Durable Object atomicity, Access).

| Actor / authority | Holds / proves | Can do | Bounded by |
| --- | --- | --- | --- |
| End user (pass holder) | wallet key; a pass; consume digests | sign proofs; call gated paths | single-use nonce; per-address and per-IP limits; owner-bound redemption |
| Network client (anyone) | request line, headers, body, timing | hit `/v1/challenge`, public paths, gated paths with garbage | per-IP budgets before signature work; byte cap; edge timeouts (B.PX-2) |
| Phishing site | the ability to show a victim a sign request | obtain a proof for a real nonce | audience-bound v3 message: a proof for another origin, gate, network or consume is refused |
| Sui fullnode (`SUI_RPC_URL`) | chain reads | lie about ownership or events, withhold them, send hostile frames | trusted (operator-chosen); fail closed; decoder bounds (I12, F58); response size F63 |
| Upstream relay | responses | large or slow responses, redirects, arbitrary headers | streamed (no buffering), 600 s deadline, 3xx → 502, header denylist (B.PX-1) |
| Durable Object | nonce, rate, redemption state | be unavailable or error | single-threaded synchronous SQL; any error → 503 (fail closed) |
| Holder of the deploy token | code and secrets in production | replace the Worker | B.CF-1; FU-0030 |
| Anyone reading `wrangler.toml` | the non-secret configuration | learn the gate, package, origin, allowed origins | only public values are committed (I-config) |
| Crates and build pipeline | the compiled code | ship altered code | `Cargo.lock`, cargo-deny, pinned actions, checksummed build tools (F53) |

### Service actor matrix (RUST lens)

| Actor | Controls | Bounded by |
| --- | --- | --- |
| Network client | request line, headers, body size and framing, timing | §A I9, I14, I19; the platform (isolate memory, edge timeouts) |
| Upstream service | response size, status, timing | streamed body, `AbortSignal.timeout` 600 s (I9, I11) |
| Sui fullnode (gRPC-web) | frames and payloads the decoder parses | `grpc.rs` caps, varint bound, depth 32, required `grpc-status` (I12); F58, F60, F63 |
| Shared state store | nonce, rate and redemption state; availability | one Durable Object operation = one synchronous section; fail closed (I2, I6, I13) |
| Ingress in front | which header is the client address | `CF-Connecting-IP` only (I14) |
| Crate registry and build pipeline | the compiled code | B.1 advisories and bans; B.RS-1; F53 |

### Edge actor matrix (WORKERS lens)

| Actor | Controls | Bounded by |
| --- | --- | --- |
| Client | every header (incl. forwarding headers), body and its framing, nonce and token strings, query strings | §A I9, I14, I17, the proof decoder |
| Cloudflare platform | execution, limits, `CF-Connecting-IP`, cache, Access | stated trust anchor |
| Upstream origin | responses; whether it is reachable without the gateway | origin lock (I25) |
| Sui RPC | chain reads | Sui client rows |
| Holder of the deploy token | code and secrets in production | B.CF-1 |
| Anyone reading the committed wrangler config | non-secret configuration | config disclosure (I18, I20) |

### Forwarding matrix (PROXY lens)

| Actor | Controls | Bounded by |
| --- | --- | --- |
| Client | method, path, query, every header, body bytes and timing | §A I9, I15, I16, I23, I24 |
| Upstream relay | status, headers, body, redirects, timing | I11, I16, I26, I27; F65 for `304` |
| A party on the path to the upstream | the same, if unencrypted | `UPSTREAM_URL` must be `https://` unless `ALLOW_INSECURE_HTTP=1` (config) |
| State store behind the gate | admission and single-use state | I6, I13, I28 |
| Whoever can reach the upstream directly | bypass of the gate | I25 (Access service token; negative check daily) |

### On-chain dependency matrix (SUI_CLIENT lens)

| Object / package | ID (original-id · published-at) | Sourced from | Used as | If stale, wrong or attacker-supplied | Fails open / closed |
| --- | --- | --- | --- | --- | --- |
| `access_gate` package | `0xd7ddaa94…388c9` · same (v1) | `NFT_TYPE` prefix in `wrangler.toml` | type filter; event-type prefix | stale ⇒ no pass or consume matches | closed |
| `…::access_gate::SoulboundAccessNFT` | original-id | `NFT_TYPE` (checked by `is_access_gate_pass_type` at load) | `ListOwnedObjects` `object_type` | a look-alike type is rejected at load | closed |
| `…::access_gate::AccessConsumedEvent` | original-id, derived (`consumed_event_type`) | `NFT_TYPE` | exact-type event match | a look-alike package's event does not match | closed |
| `Gate` shared object | `0x316f1bf9…faddc` | `GATE_ID` | pause/policy read; event `gate_id` match | wrong gate ⇒ no matches; unrecognised JSON ⇒ error ⇒ deny | closed |
| Consume transaction | caller-supplied digest | proof `consumeDigest` | `GetTransaction` | base58 that decodes to exactly 32 bytes before any call; unknown ⇒ 403 | closed (502 on RPC error) |

### Walrus trust matrix (WALRUS lens — gateway-in-front row)

| Party | Power | Consequence / bound |
| --- | --- | --- |
| Gateway in front of a relay (this project) | admits requests carrying an access proof | bypass if the relay is reachable without it — the origin lock (I25) |
| Upload relay operator | receives the plaintext blob | out of scope (relay and client audits) |
| User wallet | pays and signs the consume | the digest is the redemption token (I6); the message is bound to this Worker's origin (I22) |

### Identity & credential matrix (AUTH lens)

| Authority / credential | Holder | What it confers | Misuse / compromise impact | Rotation / revocation plan |
| --- | --- | --- | --- | --- |
| `UPSTREAM_AUTH_HEADERS` (Access service token id + secret) | Worker secret; GitHub secret | passes the upstream origin lock | anyone holding it reaches the relay ungated | rotation procedure and expiry (2027-09-09) recorded in the workspace `docs/networking/CLOUDFLARE.md` §2.4, as quoted in the TypeScript audit's F31; not re-read here |
| `SUI_RPC_AUTH_HEADER` | Worker secret (optional) | credentialed RPC quota | quota abuse | not set in the committed config; plain-RPC today |
| `CF_ANALYTICS_TOKEN` / `CF_ACCOUNT_ID` | Worker secrets (optional) | read-only Analytics GraphQL | usage data read | quota guard disabled (`QUOTA_GUARD_ENABLED = "false"`), cron commented out; token sent only to the fixed endpoint in the deployed build (F57, F59) |
| `CLOUDFLARE_API_TOKEN` | GitHub `production` environment secret | deploy code and secrets | replace the paywall | scope and expiry unverified (FU-0030) |
| Access proof (bearer) | client, in transit | one gated request per nonce | replay prevented by nonce single-use; audience-bound | nonce TTL 300 s |

The AUTH lens's IdP, OAuth-client, BFF, JWT and user-token categories are N/A (no IdP; no token is issued or verified other than the Sui-signature proof, whose mechanics
are the Sui client rows). The signed-challenge category is I22/I23 below and AUTH-M11.

---

## Severity scale

Critical / High / Medium / Low / Info / Positive (unchanged across the corpus).

---

## Scope

**In scope (`main` at `875220d` plus this pass's uncommitted working tree, 2026-11-07):**

- `worker/`: `src/{lib,config,state,do_state,upstream,transport,cors,out,json,region,quota_guard,hooks}.rs`, `Cargo.toml`, `wrangler.toml`, `scripts/*`, `tests/*`,
  `README.md`, `CHANGELOG.md`
- `core/`: `src/{lib,proof,sig,decision,gateway,grpc,chain,config,headers,forward,origin,net,state,redemption,quota}.rs`, `tests/*`, the new `fuzz/`
- repo level: `.github/workflows/{rust-ci,deploy-worker-rust,origin-lock,crates-publish,fuzz}.yml`, `.github/dependabot.yml`, `deny.toml`, `.cargo/config.toml`,
  `scripts/check-origin-locked.sh`, `ci/`, `conformance/vectors.json`, `SECURITY.md`
- the moved findings F51–F57 (from `gateway-workers/docs/audit/gateway-workers-audit.md`)

**Out of scope:** `gateway-workers/` (its own audit, closing with it), `gateway-rust/` (its own audit; the shared core is audited in both, from the Worker's side here), the
Cloudflare Access application and zone settings, the relay, the Move package and the clients (their audits). Cross-repo reads: none. Live reads: GitHub Actions run
history through `gh` (read-only). No Cloudflare, cluster or secret reads.

**Environment / commands (2026-11-07; `stable` rustc 1.98.1, nightly 1.100.0 for fuzzing):**

| Command | Result |
| --- | --- |
| `cargo +stable test --workspace --locked -j 2` | first run: **230 passed, 0 failed, 3 ignored**; after the fixes of this pass: **233 passed, 0 failed, 3 ignored** (core 138: 113 unit + 1 conformance + 17 decision + 1 scenario + 6 transport stub; gateway-rust 67; ci 16; worker 12 native unit tests); the 3 ignored are the env-gated live tests |
| `cargo +stable fmt --check` | clean |
| `cargo +stable clippy --workspace --all-targets --locked -j 2 -- -D warnings` | clean (before and after the fixes) |
| `cargo +stable deny check` | `advisories ok, bans ok, licenses ok, sources ok` (warnings only: 7 duplicate-version notes, 2 unused licence allowances) |
| `cargo fuzz build` (core/fuzz, nightly) | builds all three targets (also after the fixes) |
| `cargo +stable build -p access-gate-gateway-core --target wasm32-unknown-unknown --locked` | builds (after the fixes) |
| `cargo fuzz run grpc / proof / sig` | Section C.1 (iterations and the F58 crash) |
| `cargo +stable clippy -p access-gate-gateway-core --lib -- -W clippy::unwrap_used -W clippy::expect_used -W clippy::panic -W clippy::indexing_slicing -W clippy::string_slice` | experiment for F61: 2 `unwrap`, 15 indexing, 12 slicing, 3 string-slice sites in non-test core code before the fixes |
| `bash worker/scripts/assert-prod-build.sh build / build-hooks / --self-test` | `build/` passes, `build-hooks/` fails with all four markers, the self-test passes — **on the artifacts already on disk (built 2026-10-24, not rebuilt here)** |
| a scratch `url` 2.5.8 program | `%2e%2e`, `.%2e`, `%2e.` and `\` are normalised in the path before the Worker sees it; `%2f` is kept (so `is_safe_path` must refuse it, and does) |
| `gh run list` / `gh run view` | deploy and origin-lock history (Deployment status) |
| **Not run here** | the workerd suites (`npm test` in `worker/`), the differential run (needs the TypeScript Worker's dependencies), `cargo llvm-cov` (no new figure), the wasm32 build of the Worker, any live Cloudflare read |

---

## Findings

### F51 — Rust Worker: a panic is an uncatchable wasm trap (moved from `gateway-workers` F51; re-verified 2026-11-07)

**Severity:** Low   **Disposition:** MITIGATED (0.0.27; live since the 2026-10-20 cutover)
**Where:** `worker/Cargo.toml` (`[lints.clippy]`), `worker/scripts/lint-canary.sh`, `worker/tests/panic.test.mjs`, `.github/workflows/rust-ci.yml` (`worker` job).

**Issue:** On wasm32 a Rust panic is a trap: it cannot be caught and turned into the JSON + CORS answer every other failure gets.

**Impact:** A panic returns the runtime's generic 500 with no CORS grant and forwards nothing (fails closed); `worker-build`'s trap recovery re-instantiates the module.

**Remediation / evidence:** Re-verified in code: `unwrap_used`, `expect_used`, `panic` and `indexing_slicing` are `deny` for the **Worker crate** (`worker/Cargo.toml`), the CI
`worker` job runs clippy `-D warnings` natively and for wasm32 with and without `test-hooks` plus the lint canary (`rust-ci.yml`); `cargo clippy --workspace` is clean
this pass. **Correction of scope found in this pass:** the lints cover the adapter, not `core/`, which is compiled into the same wasm and holds the request path;
the original wording ("the request path is linted free of the constructs that panic") overstated it. The core's own panic risk is F58 (found and fixed) and F61 (the remaining
guarded sites). Residual unchanged: arithmetic overflow aborts (`overflow-checks = true`), and a dependency panic fails closed as above.

### F52 — Rust Worker: workers-rs, wasm-bindgen and worker-build are 0.x and move together (moved from `gateway-workers` F52; re-verified 2026-11-07)

**Severity:** Low   **Disposition:** ACCEPTED-RISK (accepted by the maintainer: generated glue is acceptable)
**Where:** `worker/Cargo.toml`, `worker/README.md` ("Toolchain"), `.github/dependabot.yml`.

**Issue:** workers-rs is 0.x, the `wasm-bindgen` CLI that `worker-build` runs must equal the crate exactly, and about 32 KB of generated JS glue ships in the bundle.

**Impact:** A careless bump breaks the build or the deployed glue; an upstream regression reaches the paywall only through a deploy the maintainer chooses.

**Remediation / evidence:** Re-verified: `worker =0.8.7`, `wasm-bindgen =0.2.129`, `wasm-bindgen-futures =0.4.79`, `js-sys =0.3.106`, `web-sys =0.3.106` in `worker/Cargo.toml`;
`Cargo.lock` agrees (worker 0.8.7, wasm-bindgen 0.2.129, js-sys and web-sys 0.3.106); `cargo install worker-build --version 0.8.7 --locked` in both workflows; Dependabot `ignore`
rules for `worker`, `worker-*`, `wasm-bindgen*`, `js-sys`, `web-sys`; `rust-version = "1.91"` for this crate only.

### F53 — Rust Worker: build-time downloads of wasm-bindgen, Binaryen and esbuild (moved from `gateway-workers` F53; re-verified 2026-11-07)

**Severity:** Low   **Disposition:** MITIGATED (checksums pinned; trust-on-first-use of the release assets remains)
**Where:** `worker/scripts/fetch-build-tools.sh`, `rust-ci.yml`, `deploy-worker-rust.yml`.

**Issue:** `worker-build` downloads three binaries at build time without verifying them.

**Impact:** A compromised download would put attacker code into the Worker that gates the paywall.

**Remediation / evidence:** Re-verified: the script downloads wasm-bindgen 0.2.129, Binaryen 132 and esbuild 0.28.2, checks a pinned SHA-256 for each (failing and deleting on mismatch),
and exports `WASM_BINDGEN_BIN`, `WASM_OPT_BIN`, `ESBUILD_BIN`; both workflows run it before building. The versions agree with the crate pin (wasm-bindgen 0.2.129) and the harness
lockfile (esbuild 0.28.2). Residual: the checksums were taken when first fetched; locally `worker-build` still fetches its own unless the script is used.

### F54 — Rust Worker: Durable Object continuity across the cutover (moved from `gateway-workers` F54; re-verified 2026-11-07)

**Severity:** Medium   **Disposition:** MITIGATED (cutover done 2026-10-20; the pre-cutover rows were not read back)
**Where:** `worker/src/do_state.rs`, `worker/src/region.rs`, `worker/wrangler.toml`, `worker/tests/state.test.mjs`, `deploy-worker-rust.yml`.

**Issue:** A deploy under a different script name, class or migration tag starts with empty Durable Object storage: the 30-day redemption record is lost and every spent
consume is redeemable once more (bounded by the 5-day consume age).

**Impact:** Paid uses could be redeemed twice within the window.

**Remediation / evidence:** Re-verified in code: `name = "access-gate-gateway"`, class `NonceRateState`, migration `v1` / `new_sqlite_classes`, instance names `nonce:<shard>` and
`nonce:redeem`, and the table schema including the `ALTER TABLE … ADD COLUMN token` upgrade (`do_state.rs::migrate`). The `inputs` job of `deploy-worker-rust.yml` hard-wires the live
name for `cutover` (needs `confirm=cutover`) and refuses it for `shadow`. Residual: nobody read the pre-cutover redemption rows after the 2026-10-20 deploy; the shared-table design and the
`state.test.mjs` upgrade test (not run here) are the evidence. Rollback to the TypeScript Worker works while it exists.

### F55 — Rust Worker: CPU time of the wasm Worker on Free is not measurable locally (moved from `gateway-workers` F55; re-verified 2026-11-07)

**Severity:** Medium   **Disposition:** MITIGATED (read at the edge on 2026-10-20; not re-read in this pass: FU-0029)
**Where:** `worker/README.md` ("Runbook", "Measurements"), `worker/scripts/coldstart.mjs`.

**Issue:** The Free plan allows 10 ms of CPU per request; workerd exposes no CPU clock, so the platform's accounting can only be read from a deployment.

**Impact:** A p99 near 10 ms would fail requests on Free (fail closed).

**Remediation / evidence:** The original gate (p99 ≤ 5 ms, p99.9 ≤ 10 ms over a week) was found unachievable by either implementation on 2026-10-20 and revised to "no `exceededCpu`, and Rust p99 no worse than the
TypeScript Worker's at comparable load" (figures: Rust shadow n=119 p50 2.4 ms, p99 28–31 ms, p99.9 35.5 ms; TypeScript busy hours p50 1.1–1.3 ms, p99 32–38 ms; as recorded in the TypeScript audit,
**not re-read here**). The post-cutover re-read on real traffic is open (FU-0029). The commented `[limits] cpu_ms = 50` in `wrangler.toml` applies only on Workers Paid.

### F56 — Positive: the Rust Worker is held to the TypeScript Worker's behaviour by a differential run and ports of its tests (moved from `gateway-workers` F56; re-verified 2026-11-07)

**Severity:** Positive

- `worker/tests/differential.diff.mjs` (8 scenario groups by source count; not run here) runs the same scenarios against both Workers under workerd and fails on any difference in status, body,
  headers or upstream requests. It needs the TypeScript Worker, so it **goes with `gateway-workers`** at retirement (`worker/README.md` runbook step 6).
- After retirement the parity guarantee rests on the shared conformance vectors (core tests and the workerd suite `worker/tests/conformance.test.mjs`, 10 cases by source count), the 39-step
  `core/tests/scenario.json` run against the pure tables and against the real SQL, and the other workerd suites. The `gateway-rust` audit's B.SC-3 table stays the parity record between the two Rust
  adapters; the TypeScript column of the old home table (B.SC-3 in the `gateway-workers` audit) disappears with that audit — see Normative requirement 15.

### F57 — Rust Worker: the test-hooks build is a different binary from the deployed one (moved from `gateway-workers` F57; re-verified 2026-11-07)

**Severity:** Low   **Disposition:** MITIGATED (see F59 for the artifact guard added in this pass)
**Where:** `worker/src/hooks.rs`, `worker/Cargo.toml` (`[features] test-hooks`), `worker/tests/panic.test.mjs`, `worker/src/quota_guard.rs`, `worker/src/state.rs`, `worker/src/do_state.rs`.

**Issue:** Seams the suites need (a pinned DO clock, `TEST_FAIL_STATE` fault injection, `QUOTA_GRAPHQL_URL`, `/__test/*` routes, raw SQL and migrate ops in the DO) exist only under the cargo feature
`test-hooks`, so part of the suites runs on a build that is not the deployed one.

**Impact:** A seam that leaked into the deployed build would be a backdoor (a clock override in the redemption store, a redirect for the analytics token, raw SQL).

**Remediation / evidence:** Re-verified in code that every seam is behind `#[cfg(feature = "test-hooks")]`: the `hooks` module and its `fetch` pre-route (`lib.rs`), `TEST_FAIL_STATE` (`state.rs`,
`lib.rs`), the `now=` clock override and the `sql`/`migrate` ops (`do_state.rs`), and the `QUOTA_GRAPHQL_URL` override (`quota_guard.rs`; the production `endpoint()` returns the constant). The
prior builds on disk show the cfg-gating works: none of the four marker strings is in `worker/build/` and each is in `worker/build-hooks/` (F59). `panic.test.mjs` asserts the deployed build serves no
`/__test/*` route (not run here). The behavioural suites run on the feature-less build; the DO-direct, fault-injection, quota, benchmark and streaming-memory cases use the hooks build.

### F58 — gRPC-web trailer parsing panics when byte 12 of a trailer line is inside a multi-byte character (found by fuzzing, 2026-11-07)

**Severity:** Low   **Disposition:** RESOLVED (this pass; uncommitted until the commit that carries this audit)
**Where:** `core/src/grpc.rs::unframe` (the trailer-frame loop), reached from `chain.rs` for every Sui read; shared by the Rust Worker and `gateway-rust`.

**Issue:** `unframe` decodes a trailer frame with `String::from_utf8_lossy`, then tested `line.len() > 12 && line[..12].eq_ignore_ascii_case("grpc-status:")`. A `str` slice at a non-boundary
panics: any trailer line whose bytes 10–12 or 11–13 hold one multi-byte character (a lossy-decoding replacement character is three bytes) aborts the request. The `grpc` fuzz target found it after
184 inputs; minimised input `[99, 128, 0,0,0,15, 255, 0, 231×7, 0, 231×4, 255]` (selector byte 99 picks "header status garbage", then one trailer frame of 15 invalid UTF-8 bytes); panic message:
"end byte index 12 is not a char boundary; it is inside '�' (bytes 10..13 of string)". The existing proptest (`unframe_never_panics_and_respects_the_cap`) draws random bytes and does not reach a trailer frame.

**Impact:** Reachable only from the configured fullnode's response (TLS, operator-chosen), so not an attacker-from-the-internet path. On the Worker the panic is a wasm trap: the runtime's generic 500
(no CORS), nothing forwarded, instance re-instantiated, the request fails closed. In `gateway-rust` (`panic = "abort"`) it ends the process until the supervisor restarts it, repeatedly if the fullnode
keeps sending the frame.

**Remediation / evidence:** `core/src/grpc.rs`: the prefix test uses `get(..12)` / `get(12..)` (no slicing), and `lib.rs` now carries `#![cfg_attr(not(test), deny(clippy::string_slice))]`, which flags this class (F61).
Tests: `a_trailer_line_with_a_multibyte_character_at_byte_12_is_not_a_panic` (the minimised input, valid multi-byte variants, case-insensitive prefix, last status wins) and the proptest
`trailer_frames_never_panic`; the minimised input is committed as `core/fuzz/seeds/grpc/regression-f58-trailer-multibyte`. After the fix the crash input replays clean and the `grpc` target ran
1,276,933 inputs in 111 s without a finding. `cargo test --workspace` 233 passed. Not deployed (FU-0031).

### F59 — Nothing asserted the absence of the test-hooks code in the bundle that is deployed

**Severity:** Low   **Disposition:** MITIGATED (guard added this pass; one residual below)
**Where:** `.github/workflows/rust-ci.yml` (`worker` job), `.github/workflows/deploy-worker-rust.yml` (`deploy` job), `worker/scripts/assert-prod-build.sh` (new).

**Issue:** The base template requires a test-only mode's absence to be asserted on the production artifact. CI tested the production build's behaviour for four `/__test/*` paths (`panic.test.mjs`)
but not the other seams (`TEST_FAIL_STATE`, `QUOTA_GRAPHQL_URL`, the DO `sql`/`migrate` ops), and the deploy job rebuilds on its own runner without inspecting what it builds.

**Impact:** A mistake in feature wiring (a `cfg` dropped in a refactor) would reach the deployed Worker unnoticed by the route test: a fault-injection switch or an analytics-token redirect.

**Remediation / evidence:** `assert-prod-build.sh` greps every `.wasm`/`.js`/`.mjs` file under a directory for four markers that exist only in the hooks variant; CI runs it on `build/` and runs `--self-test`
(which must FAIL on `build-hooks/`), and the deploy job runs it right after `build.sh prod`. Run here against the existing local artifacts: `build/` passes, `build-hooks/` reports all four markers, the self-test
passes (those artifacts date from 2026-10-24 and were not rebuilt; the CI step itself has not run yet). **Residual:** `wrangler deploy` runs the `[build]` command from `wrangler.toml` again, so the guard checks
the bundle built just before it, not the final upload; the same command, tools and sources make them identical, but a wrangler `--dry-run --outdir` inspection of the final bundle was not added because it
could not be run here.

### F60 — The protobuf length varint was truncated with `as usize`, which differs on wasm32

**Severity:** Info   **Disposition:** RESOLVED (this pass)
**Where:** `core/src/grpc.rs::ProtoReader::next` (wire type 2).

**Issue:** `let len = self.read_varint()? as usize;` — on `wasm32` `usize` is 32 bits, so a length of 2³² + n is read as n. By the Rust reference this is the semantics of `as`; **not executed on wasm32 here**. On a 64-bit target the same bytes are refused
(the length exceeds the buffer), so the Worker and `gateway-rust` could parse one hostile message differently.

**Impact:** Only a fullnode that already lies can exploit it, and a lying fullnode can say anything; the issue is native/wasm divergence of a decoder that is meant to be one implementation.

**Remediation / evidence:** `usize::try_from(…).ok()?`; test `a_field_length_above_u32_max_is_never_truncated` (passes on 64-bit before and after, so it pins the behaviour but does not by itself show the wasm bug: FU-0037 tracks running core tests on wasm32).

### F61 — The panic lints of F51 do not cover the shared core

**Severity:** Low   **Disposition:** DEFERRED (`string_slice` is denied now; the remaining sites are guarded and listed)
**Where:** `core/src/` (no `[lints]` in `core/Cargo.toml`); `worker/Cargo.toml` has them.

**Issue:** Running clippy with `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and `string_slice` as warnings on non-test core code gave 32 sites: `chain.rs` 2 × `cache.lock().unwrap()`
(a poisoned lock cannot be observed under `panic = "abort"` / wasm); `config.rs` 4 indexings of a `split("::")` vector checked by `len() == 3` and one `url[after..]` (now `get`); `grpc.rs` the reader and `unframe`
indexings (each behind an explicit bounds check) plus `unframe_request_for_test` (a `#[doc(hidden)]` test helper that asserts and indexes); `net.rs` `entries[i]` (`i < len` since `hops ≥ 1`); `sig.rs` the `raw[1..]`
(after `first()` matched) and fixed-length slices (after `body.len()` checks). I read each; none is reachable with a bad index except F58's string slice, now fixed.

**Impact:** The class F58 belongs to is not machine-checked for the code that matters most; a future edit could add an unguarded index.

**Remediation / evidence:** Done: `deny(clippy::string_slice)` for non-test core code (the class that bit). Deferred: denying `indexing_slicing`/`unwrap_used` in core needs ~30 call-site rewrites (`get`, `split_first`, `chunks_exact`) with tests; do it
together with moving `unframe_request_for_test` behind a `test-support` feature.

### F62 — Documentation described the TypeScript Worker as live and the Rust Worker as not deployed

**Severity:** Info   **Disposition:** RESOLVED (this pass)
**Where:** `SECURITY.md` (scope), `README.md`, `AGENTS.md`, `CLAUDE.md`, `gateway-workers/{README,CLAUDE,AGENTS}.md`.

**Issue:** After the 2026-10-20 cutover these still said "TypeScript; live; superseded pending cutover" and "Rust Worker built, shadow not yet deployed". The security policy named the wrong implementation as live.

**Impact:** A reporter or reader would aim at the wrong deployment and misjudge which code protects the paywall.

**Remediation / evidence:** The status lines are corrected (Rust Worker live since 2026-10-20; TypeScript superseded, the rollback until retired). `grep` for the old phrases outside the audits and changelogs finds none. The audits'
own history sections are unchanged. The npm package page of `@meddleware/access-gate-gateway` shows the old text until the next publish.

### F63 — The Sui RPC response is buffered whole before its size is checked

**Severity:** Low   **Disposition:** DEFERRED (FU-0032)
**Where:** `worker/src/transport.rs::post_grpc_web` (`resp.array_buffer()` then `arr.length() > MAX_GRPC_MESSAGE_BYTES`).

**Issue:** The 4 MiB limit is compared after the whole body is in isolate memory; there is no `content-length` pre-check and no counting reader. The RUST lens requires response bodies to be size-bounded and the
`Transport` contract says a body over the limit "must be an Err".

**Impact:** A hostile or faulty fullnode can make the isolate buffer up to the platform limit (128 MB) within the 15 s call deadline; the runtime then kills the request (fail closed). Bounded by the deadline and by trusting the fullnode.

**Remediation / evidence:** Exact fix in FU-0032 (content-length check, then a reader that stops at the limit + 1, with a workerd case). Not changed here because the workerd suite that would cover it could not be run in this pass.

### F64 — Grants and denials are not logged, and `wrangler.toml` has no `[observability]` block

**Severity:** Low   **Disposition:** DEFERRED (decision: OQ3, FU-0034)
**Where:** `worker/src/lib.rs`, `worker/src/upstream.rs`, `worker/wrangler.toml`; `grep console_` in `worker/src`: only store, commit, misconfiguration, upstream-failure and quota diagnostics.

**Issue:** The AUTH lens's *Audit trail* row wants grants, denials and administrative changes logged with subject, action and outcome (never the credential). The Worker logs none of the decisions, and no `[observability]` setting is committed, so whether
even the diagnostics are retained depends on a dashboard setting that was not read.

**Impact:** After an incident the operator can see status counts in Cloudflare analytics but not which address was denied for which reason.

**Remediation / evidence:** A decision, not a fix: what to log (a reason code and a truncated address hash, never proofs) and retention. Recorded as OQ3 and FU-0034.

### F65 — A `304 Not Modified` from the relay is treated as a redirect and becomes a `502`

**Severity:** Low   **Disposition:** DEFERRED (live probe needed: FU-0033)
**Where:** `core/src/forward.rs::is_redirect` (`(300..400)`), used by `worker/src/upstream.rs` after the fetch; request validators (`if-none-match`, `if-modified-since`) are not in `REQUEST_STRIP`.

**Issue:** A client revalidating the cached public path `GET /v1/tip-config` sends validators, which are forwarded; if the relay answers `304`, the Worker answers `502 upstream error`. The core test `redirects_are_the_3xx_range` pins `399` as a redirect.
Whether the relay emits `ETag`/`Last-Modified` for that path was **not verified here**, so the failure is plausible, not shown.

**Impact:** If it occurs: a browser that revalidates after the 60 s edge TTL gets a `502` instead of the tip configuration.

**Remediation / evidence:** Probe the relay's headers; then either strip validators on the upstream request for public paths, or restrict `is_redirect` to 301/302/303/307/308 and pass a `304` through, with a core test and a workerd case (FU-0033).

### F66 — Positive: the hand-rolled decoders and the signature entry point are fuzzed

**Severity:** Positive

- `core/fuzz` (own Cargo workspace; nightly; libFuzzer) has three targets: `grpc` (framing, protobuf reader, `Value` lookups, `chain` parsers; properties: size bounds, `unframe(frame(x)) == x`), `proof`
  (`decode_access_proof` raw, base64-wrapped and as generated JSON; a successful decode satisfies the grammar and always yields a signable message) and `sig` (all flag bytes; multisig, zkLogin and unknown flags never verify;
  the ZIP-215 conformance signature verifies for every message and for no other address).
- Runs of this pass (Section C.1): `grpc` 184 inputs to the F58 crash, then 1,276,933 inputs / 111 s clean; `proof` 617,523 / 101 s clean; `sig` 57,921 / 101 s clean (each ECDSA verification is slow).
- The manual workflow `fuzz.yml` (`workflow_dispatch` only) reruns them; nothing in the default CI depends on the fuzz crate.

---

## Section A — Invariant verification matrix

| # | Invariant | Enforced / asserted at | Proven by | Status |
| --- | --- | --- | --- | --- |
| I1 | Any decode, signature, nonce, chain or store error denies | `core/src/decision.rs::verify_access_request`; `gateway.rs::handle` | `core/tests/decision.rs` (17), `gateway.rs` tests, `rejects_everything_outside_the_field_grammar` | HOLDS |
| I2 | A nonce is consumed exactly once, before any chain call; forged shard tags are refused without touching a shard | `decision.rs` (`take_if_valid` before the gate read); `worker/src/do_state.rs::take_if_valid` (select + delete in one synchronous section); `region.rs::shard_of_nonce`; `state.rs::take_nonce` | `region.rs` tests, `core/tests/scenario.json` run against the tables (`scenario.rs`) and against the SQL (`worker/tests/state.test.mjs`, not run here) | HOLDS (code; workerd suite not run here) |
| I3 | Signatures verify as Sui accepts them: intent `[3,0,0]` + BCS length, Blake2b-256, ed25519 under ZIP-215 (`ed25519-consensus`), secp256k1 and secp256r1 with explicit low-S, address = Blake2b-256(flag ‖ pk); `0x03`, `0x05`, unknown flags fail closed | `core/src/sig.rs` | `core/tests/conformance.rs` (golden, negative, `zip215`), `sig` fuzz target; the secp256k1 low-S check is defence in depth and untested by a vector (`gateway-rust` audit F59) | HOLDS |
| I4 | The address is normalised before every comparison | `sig.rs::normalize_address`; `chain.rs::same_address` | vectors `addressNormalization`; chain tests | HOLDS |
| I5 | Consume binding: exact `<pkg>::access_gate::AccessConsumedEvent` from `NFT_TYPE`, sender = signer, `gate_id` = `GATE_ID`, age ≤ `CONSUME_MAX_AGE_SECS`, success from `effects.status` | `chain.rs::response_has_consume`, `event_is_recent`, `effects_succeeded` | `chain.rs` tests (look-alike package, wrong sender/gate, old consume, failed transaction) | HOLDS |
| I6 | Single use: a digest redeems once; lease, commit and release compare-and-set on a random owner token; a commit is never cleared; a lapsed holder cannot touch a newer lease | `do_state.rs::{lease,commit,release}`; `redemption.rs`; `gateway.rs::redeem_and_forward` | `scenario.json`, `redemption.rs` tests, `worker/tests/redemption.test.mjs` (not run here) | HOLDS (code; workerd not run here) |
| I7 | Ownership mode admits only a usable pass for the gate, across all pages up to 100 | `chain.rs::pass_is_usable`, `scan_owned` | chain tests | HOLDS (mode supported, not deployed) |
| I8 | A paused gate with `pause_blocks_access` admits no one; unrecognised gate JSON denies | `chain.rs::gate_blocks_access` | chain tests | HOLDS |
| I9 | The body cap is enforced on the declared length (413 before any read) **and** on the streamed bytes (counting transform stream that aborts the upstream request), and the body is never buffered | `forward.rs::preflight`; `upstream.rs::limit_body`, `fixed_length` | `worker/tests/limits.test.mjs`, `stream.test.mjs` (not run here); `forward.rs` tests | HOLDS (code; workerd not run here) |
| I10 | Memory is not a function of the body size: chunks stay in JS (`byteLength` read, same `Uint8Array` re-enqueued) | `upstream.rs::limit_body` | `stream.test.mjs` + the `/__test/mem` probe (hooks build; not run here) | HOLDS (code-only here) |
| I11 | Every outbound call has a timeout; every response read is bounded | upstream: `AbortSignal.timeout` (600 s) + `any_signal`; RPC: `AbortSignal.timeout` (15 s); RPC response size is checked **after** buffering | `proxy.test.mjs` (stalled upstream → 504; not run here) | GAP — the RPC size bound is post-hoc: F63 |
| I12 | The hand-rolled decoders are bounded (frame length, 4 MiB message, varint ≤ 10 bytes, depth 32, required `grpc-status`, no compression) and never panic | `core/src/grpc.rs` | proptests in `grpc.rs`, `grpc` fuzz target (F66), regression tests (F58, F60) | HOLDS (F58, F60 fixed this pass) |
| I13 | State-store operations are atomic; a Durable Object failure is `503`, never a conflict or an implicit success | `do_state.rs` (single-threaded, no `.await` between read and write); `state.rs::call` (non-200 → `Err`); `gateway.rs::unavailable` | `worker/tests/state.test.mjs`, `router.test.mjs` fault-injection cases (hooks build; not run here) | HOLDS (code; workerd not run here) |
| I14 | Rate limits are keyed on `CF-Connecting-IP` (IPv6 by /64) or a verified address, never on a client-supplied header; every state-allocating public endpoint (`/v1/challenge`, public paths) is limited; gated requests are limited before signature work | `lib.rs::client_ip`; `net.rs::rate_key`; `gateway.rs::handle`; `do_state.rs::rate_check` | `net.rs`, `gateway.rs` tests; `limits.test.mjs` (not run here). Note: rate windows live in the request's continent shard, so one address can have up to 8 budgets (documented parity with the TypeScript Worker) | HOLDS |
| I15 | Inbound `Authorization`, `X-Access-Proof`, `Cookie`, spoofable forwarding fields and `cf-access-*` are stripped; configured upstream headers replace any client header of the same name (`Headers.set`) | `headers.rs::drop_request_header`; `upstream.rs::exchange` | `headers.rs` tests; `proxy.test.mjs` | HOLDS |
| I16 | Hop-by-hop fields and every `Connection`-named field are removed both ways; upstream cookies, `alt-svc` and every `access-control-*` are removed from the response | `headers.rs`; `upstream.rs::from_upstream` | `headers.rs` tests | HOLDS (denylist; see B.PX-1) |
| I17 | CORS: an exact `ALLOWED_ORIGINS` match only, `Vary: Origin` on every response (errors included), preflight answered before config and auth; no credentials grant | `headers.rs::cors_allowed_origin`; `out.rs::finish`; `lib.rs::route` | `headers.rs`, `cors.rs` tests; `router.test.mjs` | HOLDS |
| I18 | No secret in logs or `Debug` output; error bodies never name configuration | `config.rs` hand-written `Debug` (URLs redacted, header values omitted); `lib.rs` (`500 gateway misconfigured`, detail to the log only); I read every `console_*` call | `config.rs` tests | HOLDS (live log retention not read: F64) |
| I19 | No attacker-reachable panic | `worker/Cargo.toml` lints (adapter); core: F58 fixed, F61 sites reviewed; `core/src/lib.rs` `#![forbid(unsafe_code)]` (the Worker crate cannot forbid it: the wasm-bindgen macros expand to `unsafe`; it contains no `unsafe` block of its own, `grep unsafe`) | proptests; fuzz (F66); `lint-canary.sh` | HOLDS after this pass (F58 RESOLVED; F61 DEFERRED for the guarded sites) |
| I20 | Misconfiguration fails closed and is never reported in detail: an invalid or missing variable answers `500 gateway misconfigured`; defaults are the strict ones (`ALLOWED_ORIGINS` empty, `SINGLE_USE` false, no insecure http) | `core/src/config.rs::from_env`; `worker/src/config.rs`; `lib.rs` | `config.rs` tests (core and worker), `worker/tests/config.test.mjs` | HOLDS |
| I21 | Wire parity with the clients and with `gateway-rust` | `conformance/vectors.json` | `core/tests/conformance.rs`, `worker/tests/conformance.test.mjs` | HOLDS |
| I22 | The proof is bound to this gateway's origin, the gate, the network, the nonce and (single-use) the digest, and the message is rebuilt from the Worker's own configuration | `proof.rs::personal_message`; `decision.rs` | vectors `audienceMismatch` (8), `personalMessageRejects` (15) | HOLDS |
| I23 | Only listed methods and safe paths are forwarded; public paths are `GET`/`HEAD`; the upstream URL is `UPSTREAM_URL` + the validated path | `gateway.rs::handle`; `forward.rs::preflight`; `headers.rs::is_safe_path` | `headers.rs::unsafe_paths_are_refused`; a `url` 2.5.8 probe shows `%2e` dot segments and `\` are normalised before `url.path()`, and `%2f` survives for `is_safe_path` to refuse | HOLDS |
| I24 | A request already carrying `Via: … access-gate-gateway` is refused `508` before any work; `UPSTREAM_URL` may not resolve to this gateway's origin; the Worker adds `Via: 1.1 access-gate-gateway` | `lib.rs::route`; `gateway.rs::handle`; `config.rs`; `upstream.rs` | `headers.rs::via_loop_table`; router tests | HOLDS |
| I25 | The upstream is reachable only with the Worker's Access service token, verified positively on deploy and negatively every day | `deploy-worker-rust.yml` "Check UPSTREAM_AUTH_HEADERS"; `origin-lock.yml` + `scripts/check-origin-locked.sh` + `ci` `classify-origin` | `ci/src/lib.rs` tests (12) and `tests/cli.rs` (4) green this pass; `worker/tests/origin-lock.test.mjs` (7, stub origin; not run here); 32 of 32 scheduled and manual runs green 2026-10-10 to 2026-11-07 | HOLDS (code and run history); that `UPSTREAM_CHECK_URL` names the secret `UPSTREAM_URL`'s origin and the Access policy itself are **not verified here** (FU-0035) |
| I26 | Upstream redirects are never followed (`redirect: manual`); any 3xx is a `502` and its body is cancelled | `upstream.rs::exchange`; `forward.rs::is_redirect` | `proxy.test.mjs` (not run here); `forward.rs::redirects_are_the_3xx_range` | HOLDS — but `304` is swept in: F65 |
| I27 | Upstream and store failures map to fixed `502`/`503`/`504` answers; a store outage is never a conflict; upstream error statuses and bodies from the first-party relay pass through by decision | `forward.rs` refusals; `gateway.rs::{unavailable,redeem_and_forward}`; `upstream.rs` | `router.test.mjs`, `proxy.test.mjs` (not run here) | HOLDS (decision: `gateway-rust` audit F44) |
| I28 | The redemption lease outlives the longest request (checked at startup): `REDEMPTION_LEASE_TTL_SECS` (900) > `UPSTREAM_TIMEOUT_SECS` (600) + `BODY_READ_TIMEOUT_SECS` (30); retention (30 d) ≥ consume age (5 d) | `core/src/config.rs::from_env` | core config tests | HOLDS |
| I29 | The Durable Object class, migration tag, instance names and schema are unchanged across deploys | `wrangler.toml`; `do_state.rs`; `region.rs` | `state.test.mjs` upgrade test (not run here) | HOLDS (code-only here) — F54 |
| I30 | The deployed bundle contains no `test-hooks` code | `#[cfg(feature = "test-hooks")]` gates; `assert-prod-build.sh` | the guard on the local artifacts (Section: Environment); CI step added | HOLDS (guard added this pass, first CI run pending) — F57, F59 |
| I31 | The Worker's CPU per request fits the plan's budget | wasm size, `opt-level = "s"`; commented `[limits] cpu_ms` for Paid | edge percentiles of 2026-10-20 only | GAP (not verifiable locally; not re-read) — F55, FU-0029 |

---

## Section B — Supply-chain, publish-authority & capability matrix

### B.1 Dependency & CVE risk

`Cargo.lock` is committed. `deny.toml`: `yanked = "deny"`, `unmaintained = "all"`, a licence allowlist, crates.io-only sources, targets include `wasm32-unknown-unknown`. `cargo deny check` was run this pass (`advisories ok, bans ok, licenses ok, sources ok`).
`cargo audit` is not run as a second tool: the `advisories` check reads the same RustSec database. The fuzz crate (`core/fuzz`) is outside the workspace and not covered by `cargo deny` or Dependabot (FU-0037).

| Dependency | Pinned version (lockfile 2026-11-07) | Liveness dependency? | CVE / audit status | Notes |
| --- | --- | --- | --- | --- |
| `worker` (workers-rs) / `worker-sys` | 0.8.7 | every request (fetch, DO, cache) | cargo-deny clean | pinned exactly (F52) |
| `wasm-bindgen` / `js-sys` / `web-sys` | 0.2.129 / 0.3.106 / 0.3.106 | glue | cargo-deny clean | pinned together with `worker-build` 0.8.7 |
| `ed25519-consensus` | 2.1.0 | ed25519 verify path | cargo-deny clean | ZIP-215 |
| `k256` / `p256` / `ecdsa` | 0.14.0 / 0.14.0 / 0.17.0 | ECDSA verify path | cargo-deny clean | `crypto-bigint` 0.7.10 (the yanked 0.7.6 was replaced in 0.0.33); `getrandom` 0.4.3 `wasm_js` backend via `.cargo/config.toml` (never called on the verify path) |
| `blake2` | 0.11.0 | intent hash, address | cargo-deny clean | |
| `serde_json` / `base64` | 1.0.154 / 0.22.1 | proof decode | cargo-deny clean | token capped at 4096 bytes before decode |
| `getrandom` (0.2 `js`) | 0.2.17 | nonce and lease-token bytes in the Worker | cargo-deny clean | `getrandom::getrandom` errors rather than returning predictable bytes (`state.rs`, `do_state.rs`) |
| `console_error_panic_hook` | 0.1.7 | panic message to the log | cargo-deny clean | |
| wrangler / workerd / esbuild (harness) | 4.156.1 / 1.20261101.1 / 0.28.2 | tests and deploy only | Dependabot group `npm-worker-harness` | not part of the Worker bundle |
| Sui fullnode (`SUI_RPC_URL`) | public `fullnode.testnet.sui.io:443` | every gated request — fails **closed** (502) | n/a | prunes old transactions (5-day consume age sized to it) |
| Upstream relay | operator origin behind Access | gated and public paths — 502/504 | n/a | origin lock I25 |
| Durable Object | Cloudflare | every request that needs state — fails **closed** (503) | n/a | |
| Cloudflare Access | application, policy and service token (ids in the workspace `CLOUDFLARE.md`; not read) | the upstream hop — expiry 2027-09-09 per the TypeScript audit F31 | n/a | expiry ⇒ the relay rejects the Worker ⇒ outage, fail closed |
| `libfuzzer-sys` / `arbitrary` | `core/fuzz` only (own `Cargo.lock` committed) | none (tooling) | not covered (FU-0037) | |

**Sui client lens rows:** SDK none (hand-rolled); transport gRPC-web only; conformance vectors `conformance/vectors.json` (published by `@meddleware/access-gate-gateway-client`, harness dev-dependency 0.0.22) asserted by `core/tests/conformance.rs` and `worker/tests/conformance.test.mjs`.
**Walrus lens rows:** the relay is the upstream; the Worker's fail mode for uploads is closed (no proof, no upload).

### B.2 Publish authority, capabilities & secret custody

| Authority / capability / secret | Where minted / held | Custody | Gates | Immutability / rotation plan |
| --- | --- | --- | --- | --- |
| Worker deploy (`wrangler deploy` / `versions deploy`) | `deploy-worker-rust.yml` | GitHub `production` environment; `CLOUDFLARE_API_TOKEN` secret, `CLOUDFLARE_ACCOUNT_ID` variable | the live Worker and its secrets | scope, zone and expiry unverified (FU-0030) |
| `UPSTREAM_URL`, `UPSTREAM_AUTH_HEADERS`, `SUI_RPC_AUTH_HEADER` | GitHub secrets → `wrangler secret put` / `versions secret put` | Worker secret store | the upstream origin and its lock | Access token rotation procedure recorded outside this repo; expiry 2027-09-09 (as recorded in the TypeScript audit) |
| crates.io publish (`access-gate-gateway-core`) | `crates-publish.yml` (tag `v*`) | GitHub OIDC → crates.io trusted publishing | core releases | n/a (no token) |
| Registry pushes (quay.io, Docker Hub, private) | `docker-publish.yml` | GitHub secrets | the `gateway-rust` image only (not the Worker) | inventory belongs to the `gateway-rust` audit F30 |
| `CF_ANALYTICS_TOKEN` | optional Worker secret | Worker secret store | read-only Analytics | unset while the guard is off |

On-chain capabilities: none (the Worker holds no `AdminCap`, signs nothing).

#### CI & release integrity

| Item | Holds? | Evidence |
| --- | --- | --- |
| Actions pinned | Yes | every `uses:` in the workflows (including the new `fuzz.yml`) is a 40-character SHA with a version comment; the Rust toolchain comes from `rustup` on the runner |
| Least privilege | Yes | `permissions: contents: read` at the top of `rust-ci.yml`, `deploy-worker-rust.yml`, `origin-lock.yml`, `fuzz.yml`; `id-token: write` only on the crates publish job |
| OIDC trusted publishing | Yes for crates; the Worker itself is deployed with an API token (FU-0030) | `crates-publish.yml` |
| Tag-gated, idempotent publish | Yes for crates (tag `v*`, existing version skipped); the Worker deploy is a manual dispatch from `main` | `crates-publish.yml`; `deploy-worker-rust.yml` `if: github.ref == 'refs/heads/main'` |
| Release gate equals CI | Yes | `deploy-worker-rust.yml` `ci` job calls `rust-ci.yml`; `crates-publish.yml` `verify` likewise |
| Automated dependency updates | Partly | `.github/dependabot.yml`: cargo (`/`), npm (`/worker`, `/gateway-workers`), docker, github-actions; weekly, grouped; `core/fuzz` not covered (FU-0037) |
| Container images | N/A for the Worker | the Worker is a wasm bundle; the `gateway-rust` image is that audit's |
| Secrets never echoed | Yes | secrets are passed via `env:` and piped to `wrangler secret put`; the curl header file is mode 0600 under `RUNNER_TEMP` and removed; no `set -x` |
| Real funds are manual | N/A | no job spends funds or signs on a chain |
| Test-only modes | Yes after this pass | `test-hooks` is off in the deployed build; `assert-prod-build.sh` (CI and deploy) checks it, with a self-test (F57, F59) |

### B.CF-1 Deploy authority

`wrangler deploy` and `wrangler secret put` run only from `deploy-worker-rust.yml`: `workflow_dispatch`, `github.ref == refs/heads/main`, after the full `rust-ci.yml`, in the `production` environment. `shadow` mode refuses the live name; `cutover` needs `confirm=cutover`.
Reviewers on the environment and the token's scopes were **not read here**; the single-maintainer decision (no required reviewer) is recorded in the TypeScript audit (F16, OQ4). The token needs Workers Scripts:Edit and Workers Routes:Edit on the zone in `wrangler.toml` (`meddleware.dev`); the recorded target scope names `meddleware.co.uk` (FU-0030).
The workflow shares the concurrency group `deploy-workers` with the TypeScript deploy so the two never run at once.

### B.RS-1 Build & release

| Requirement | Holds? | Evidence |
| --- | --- | --- |
| `cargo fmt --check` and `cargo clippy --all-targets -D warnings` in CI | Yes | `rust-ci.yml`; run this pass, clean |
| `cargo audit` and `cargo deny` in CI | Yes — deny, whose advisories check uses the RustSec database | `rust-ci.yml` (`cargo-deny-action`); run this pass |
| MSRV job | Yes for core and gateway-rust (1.88); the Worker crate declares 1.91 and is built with `stable` | `rust-ci.yml` `msrv` job |
| Panic lints and canary | Yes (adapter only: F51, F61) | `worker` job |
| Crates trusted publishing, no `--allow-dirty` | Yes | `crates-publish.yml` |
| Build tools checksummed | Yes | `fetch-build-tools.sh` (F53) |
| Size gate | Yes | `size-gate.sh` (1.5 MiB gzip budget) |

### B.SC-1 ID-constant trace

| Location | Network | Value | original-id or published-at | Matches the latest on-chain version |
| --- | --- | --- | --- | --- |
| `worker/wrangler.toml` `NFT_TYPE` | testnet | `0xd7ddaa94…388c9::access_gate::SoulboundAccessNFT` | original-id (v1, so equal to published-at) | recorded as current in the TypeScript audit (2026-10-09); **not re-read on chain here** |
| `worker/wrangler.toml` `GATE_ID` | testnet | `0x316f1bf9…faddc` | object id | as above |

### B.SC-2 Coupling table

N/A: the Worker builds no PTB and calls no Move function. Its reads are `GetTransaction`, `ListOwnedObjects` and `GetObject`, with field numbers pinned in `core/src/chain.rs` and literal-field-number fixtures in `core/tests/transport_stub.rs`; the live ABI-drift checks are `gateway-rust`'s `--ignored` tests (its F45).

### B.SC-3 Cross-implementation parity (Rust adapters; the TypeScript column goes with `gateway-workers`)

| Behaviour | Rust Worker | `gateway-rust` | Shared vector / test |
| --- | --- | --- | --- |
| Decision (`verify_access_request`) | `core` | `core` | one implementation; `core/tests/decision.rs` |
| Signature schemes, low-S, ZIP-215 | `core/src/sig.rs` | same | vectors `signatures`, `negativeSignatures`, `zip215` |
| Digest rule (exactly 32 bytes), answers per outcome | `core` | `core` | vectors `txDigest`, `responses` |
| Bearer parsing, header lists, path rule, CORS grants | `core/src/headers.rs` | same | `headers.rs` tests |
| Body handling | streamed, counted, 100 MB | buffered, 256 KiB | different by design (`gateway-rust` F6) |
| State | Durable Object SQL | memory / Redis | `core/tests/scenario.json` (39 steps) against all three |
| Retry / pagination / effects status | `core/src/chain.rs` | same | chain tests |

### B.PX-1 Route & header policy

| Route / path | Methods | Auth | Forwarded request fields | Stripped (both ways) | Response fields kept | Cache |
| --- | --- | --- | --- | --- | --- | --- |
| `/healthz` | any (answered locally, before everything) | none | not forwarded | n/a | `200 ok` | none |
| any path with `OPTIONS` | `OPTIONS` | none | answered locally, before config and auth | n/a | CORS grants, `Vary: Origin` | none |
| any path with a `Via` naming this gateway | any | refused `508` | not forwarded | n/a | `{ error }` + CORS | none |
| `GET /v1/challenge` | `GET` | none; per-IP budget (30/min, `chal:<ip>`) | answered locally | n/a | `{ nonce, expiresAt }` (`503` if the DO fails) | none |
| `PUBLIC_PATHS` (`/v1/tip-config`) | `GET`, `HEAD` (else 405 + `Allow`) | none; per-IP budget (120/min, `ip:<ip>`) | client fields minus the strip list; plus the configured upstream headers; the query is dropped for the cached `GET` | request: hop-by-hop, `Connection`-named, `host`, `authorization`, `x-access-proof`, `content-length`, `cookie`, `forwarded`, `via`, `x-forwarded-for/host/proto`, `x-real-ip`, `cf-access-*`; response: hop-by-hop, `Connection`-named, `content-length`, `set-cookie(2)`, `alt-svc`, `access-control-*` | 2xx; `cache-control: public, max-age=60` added | edge Cache API, key = URL without query, `GET` only, 2xx only |
| every other path (gated) | `GET`, `HEAD`, `POST`, `PUT` (else 405 before verification) | proof v3 + live chain read + redemption lease; per-IP pre-auth budget (120/min) before verification, per-address budget (30/min) after | as above, query included; `Content-Length` re-attached through `FixedLengthStream` | as above | status and body pass through (decision); 3xx → 502 (F65 for 304) | never cached |
| unsafe path (`%2f`, `%5c`, `%00`, `%2e%2e`, `\`, control characters, `//`, `..`) | any | — | refused `400 invalid path` before the upstream URL is built | n/a | n/a | none |

The response policy is a denylist. It is sufficient for a first-party relay whose headers carry no secret (`gateway-rust` audit F44, decided); `server` and, on an Access refusal, `cf-access-*` pass through (not verified which headers the Access refusal carries; the origin-lock classifier relies on `cf-access-domain`). Revisit if a third-party upstream is ever fronted.

### B.PX-2 Limits

| Limit | Value | Where enforced | Test |
| --- | --- | --- | --- |
| header-read timeout · body-read deadline · idle timeout | Cloudflare edge (not configurable by the Worker); `BODY_READ_TIMEOUT_SECS` (30) is validated and counted into the lease check, but the Worker has no 408 path of its own | platform | none in this repo: a stalled client body ends at the upstream deadline (600 s) or the platform's limit |
| request body cap (declared / streamed) | 100,000,000 B (the Free/Pro zone limit); declared → 413 before reading; streamed → counted, abort + 413 | `forward.rs::preflight`; `upstream.rs::limit_body` | `limits.test.mjs`, `stream.test.mjs` (not run here) |
| concurrent connections / in-flight forwards | platform (isolate memory 128 MB; chunks stay in JS) | platform | `/__test/mem` probe |
| upstream connect · response · total deadline | one total deadline, 600 s (`UPSTREAM_TIMEOUT_SECS`, 1–3600) → 504 | `upstream.rs::exchange` | `proxy.test.mjs` (not run here) |
| Sui RPC per call | 15 s (`RPC_TIMEOUT_SECS`, 1–120); size 4 MiB checked after buffering (F63) | `transport.rs` | `chain.test.mjs` (not run here) |
| admission-state lifetime (must exceed the total deadline) | lease 900 s > 600 + 30 (startup-checked); retention 30 d ≥ consume age 5 d | `core/src/config.rs` | core config tests |
| rate limits | challenge 30/min/IP; public 120/min/IP; gated pre-auth 120/min/IP; per address 30/min | Durable Object | `limits.test.mjs` |

### B.WAL-1 Coupling

| Format | Producer | Consumer | Test / vector |
| --- | --- | --- | --- |
| Access proof header for a gated relay | `@meddleware/access-gate-gateway-client` | this Worker | `conformance/vectors.json` (`proofDecode`, `signatures`, `audienceMismatch`) |
| Relay tip transaction | client SDK | the relay | not the Worker's; it forwards bytes |

### B.AUTH-1 Key & credential inventory

| Key / credential (name only) | Type / algorithm | Where held | Who can read it | Rotation cadence · last rotated | Compromise procedure |
| --- | --- | --- | --- | --- | --- |
| `UPSTREAM_AUTH_HEADERS` (CF-Access-Client-Id / -Secret) | Access service token | Worker secret; GitHub secret | deploy workflow; Worker | expires 2027-09-09, rotated 2026-10-01 (as recorded in the TypeScript audit; not re-read) | new token → add to policy → update the GitHub secret → deploy → revoke the old one (procedure in the workspace `CLOUDFLARE.md` §2.4) |
| `UPSTREAM_URL` | origin URL (secret so the private origin is not public) | Worker secret; GitHub secret | same | on origin change | change the secret; the origin lock still holds |
| `SUI_RPC_AUTH_HEADER` | static header | Worker secret (unset) | — | n/a | — |
| `CF_ANALYTICS_TOKEN`, `CF_ACCOUNT_ID` | read-only API token | Worker secret (unset; guard off) | — | n/a | — |
| `CLOUDFLARE_API_TOKEN` | API token | GitHub `production` environment secret | deploy job | unverified (FU-0030) | revoke in Cloudflare, replace the secret |

### B.AUTH-2 Client & authorization inventory

N/A: the Worker registers no OAuth client and checks no Keto relation. Its authorization is on-chain (Section A I5–I8).

### B.AUTH-3 Protocol conformance

The signed-challenge protocol is `access-gate-gateway:access:v3` (ADR-0004): versioned, domain-separated prefix; origin, gate, network, nonce and (single-use) digest bound; rebuilt from configuration; canonical ASCII lines; negative vectors for every bound field in `conformance/vectors.json` consumed by core and the Worker harness. Deviations: none known.

---

## Section C — Test-coverage & hermetic/live split

### C.1 Coverage grade

`cargo +stable test --workspace --locked` this pass: **233 passed, 0 failed, 3 ignored** (230 before this pass's three new core tests). Layers: core unit tests, shared conformance vectors, real-signature decision tests, the 39-step scenario against the pure tables and a scripted transport (all native); the Worker crate's 12 native unit tests (config, region, rate keys, CORS, JSON order);
and the black-box workerd suites in `worker/tests/*.test.mjs` (**118 test cases by a source count of `it(`/`test(`; not run here**: chain 12, config 4, conformance 10, limits 4, origin-lock 7, panic 2, proxy 16, quota 6, redemption 11, router 23, state 20, stream 3) plus the differential run (8 groups, needs the TypeScript Worker; not run here). CI runs all of them (`rust-ci.yml` `worker` job).
Coverage tool: `cargo llvm-cov` runs in CI and prints the figure to the job summary; **no new figure was measured here** (the last recorded workspace figure is 92.0 % of lines, 2026-10-19, in the `gateway-rust` audit).

| Dimension | Assessment |
| --- | --- |
| Happy-path coverage | covered: proof decode, every scheme, single-use allow, challenge round trip, CORS, public paths, streamed upload |
| Error-path / failure-mode coverage | covered: bad/tampered/wrong-address signature, replay, expired nonce, forged shard tag, missing consume, paused gate, unrecognised gate JSON, gRPC status/truncation/compression, DO failures per operation (hooks build), lease lapse and lost commit, upstream timeout and redirect, misconfiguration. **Missing:** an oversize RPC response (F63); a `304` (F65); trailer text with multi-byte characters was missing until F58 |
| Boundary / edge-case coverage | covered: token size cap, field grammar, depth limit, nonce hard cap, declared length = cap, chunked over-cap, consume age and skew, lease/deadline checks, IPv6 /64. **Added this pass:** length varint ≥ 2³², multi-byte trailer lines |
| Security-relevant coverage | strong: vectors with negatives (high-S both curves, non-canonical `s`, wrong intent, truncated, unsupported flags, audience mismatch per field), ZIP-215, look-alike event type. **Gap noted upstream:** only the secp256r1 low-S rejection is pinned by a vector (`gateway-rust` audit F59) |

**Fuzzing (RUST lens §C; nightly 1.100.0, cargo-fuzz 0.13.2, libFuzzer with ASan; 4 cores shared with other work, so rates are low):**

| Target | Run | Inputs | Result |
| --- | --- | --- | --- |
| `grpc` | 1 (seeds + dictionary) | 184 | **crash** at `core/src/grpc.rs:306` (F58); minimised to 21 bytes |
| `grpc` | 2, after the fix | 1,276,933 in 111 s (≈11.6 k/s), coverage 616 edges / 2,221 features, corpus 812 | no crash |
| `proof` | 1 | 617,523 in 101 s (≈6.1 k/s), 1,825 edges, corpus 1,401 | no crash |
| `sig` | 1 | 57,921 in 101 s (≈570/s), 1,361 edges, corpus 281 | no crash |

100 s of coverage-guided fuzzing is a smoke test, not a proof: longer runs (the manual `fuzz.yml`) are the maintainer's call. The corpus and the 387 MB build directory were deleted after the runs; only the seeds and the F58 regression input are committed.

RUST lens §C: unit tests, shared vectors and env-gated live tests: yes. Fuzz targets for every hand-rolled decoder and for signature parsing: yes (new). A coverage tool named: yes (figure not re-measured). Malformed input does not panic: tested for tokens, frames, JSON and trailers.
WORKERS lens §C (three layers named separately): Node-pool native tests, workerd-pool black-box suites, env-gated live tests — all in CI except the live ones. PROXY lens §C: hop-by-hop, redirect, route, limit and admission cases are in `proxy.test.mjs`, `limits.test.mjs`, `redemption.test.mjs` (not run here).

### C.2 Hermetic vs. live paths

| Path | Hermetic unit test? | Deferred to | Tracking |
| --- | --- | --- | --- |
| gRPC-web against a real fullnode (field numbers) | literal-field-number fixtures against a scripted node | `gateway-rust` `live_*` tests (`--ignored`) | `gateway-rust` audit F45 |
| Durable Object atomicity and SQL | `scenario.json` on the pure tables; workerd suites on the real SQL | live Cloudflare DO behaviour | F54 |
| Origin lock (negative) | `ci` verdict logic and `origin-lock.test.mjs` against a stub | the daily `origin-lock.yml` run against the real origin (32 of 32 green) | I25, FU-0035 |
| Access enforcement at the origin, plan limits, edge CPU, cross-colo cache | no | live Cloudflare | F55, FU-0029, FU-0036 |
| wasm32 execution of the core | the core builds for wasm32 in CI; tests run native | workerd suites run the built wasm | F60, FU-0037 |
| Wallet display of the v3 message | n/a | live wallet | Risks |

---

## Section D — Deployment-readiness gates

The Worker already runs on testnet; "pre-testnet" is therefore the gate it must keep passing, and "pre-mainnet" is the open list.

### pre-localnet

- [x] builds; `cargo test --workspace --locked` 233 passed; fmt and clippy `-D warnings` clean — this pass
- [x] no panics on attacker-reachable paths — F58 fixed; F51/F61 for the lint scope
- [x] no secrets in source — `wrangler.toml` holds public values only; secrets are set with `wrangler secret`
- [x] dependencies install clean (`--locked`) and cargo-deny green — this pass
- [x] body cap enforced on streamed bytes and the declared length — I9
- [x] B.PX-1 and B.PX-2 complete; configuration fails startup — I20

### pre-testnet

- [x] timeouts on every outbound call — I11; **response bodies bounded: F63 open**
- [x] low-S and ed25519 rules match the Sui client lens; parity vectors green — I3, I21
- [x] rate limit keyed on a trusted address; challenge issuer limited; shard names allowlisted — I14, I2
- [x] origin lock verified positively (deploy) and negatively (daily; 32 of 32 green) — I25; the equality of the check URL and the secret origin is open (FU-0035)
- [x] workerd tests run in CI; replay and lease tests green in CI (not run here) — `rust-ci.yml`
- [x] admission-state tests (expiry, stale holder, store outage) — `redemption.test.mjs`, `scenario.json`
- [x] `SECURITY.md` present — and corrected in this pass (F62)
- [ ] B.AUTH-1 credential inventory verified against the live accounts — deploy token scope unverified (FU-0030)
- [x] decoders fuzzed — F66

### pre-mainnet

- [ ] mainnet `NFT_TYPE`, `GATE_ID`, `NETWORK`, `GATEWAY_ORIGIN`, route and relay from the canonical record — no mainnet `access_gate` is published (FU-0036)
- [ ] plan tier confirmed against the declared body cap, the CPU budget and the 100,000 requests/day Free limit — FU-0029, FU-0036
- [ ] deploys gated on CI and a protected environment with reviewers, or the choice recorded as an OQ; token scopes minimal — OQ1, FU-0030
- [x] cache key normalised (query dropped); CORS sends `Vary: Origin`; errors reveal no configuration — I17, I18, B.PX-1
- [ ] secrets management verified; Access token expiry tracked — FU-0030, FU-0035
- [ ] grants and denials logged, or the decision recorded — F64, OQ3
- [ ] external review of the forwarding and verification path — not started (`OPERATOR_TASKS.md`)

---

## Cross-project themes

- **Supply chain & release integrity:** `Cargo.lock` committed; actions pinned by SHA; build tools checksummed (F53); cargo-deny green; Dependabot weekly and grouped (not covering `core/fuzz`: FU-0037); crates.io by OIDC; the Worker is deployed by an API token whose scope is unverified (FU-0030).
- **Wire-format coupling & conformance vectors:** the proof format is defined in `@meddleware/access-gate-gateway-client` (`proof.ts`) and implemented once in `core/src/proof.rs`; drift is detected by `conformance/vectors.json` in the core and harness suites. No shared vectors exist for header extraction or the redemption-conflict body beyond the `responses` section.
- **On-chain-truth boundary:** admission is decided from live chain reads; single-use accounting is gateway-local state by design (Durable Object), age-bounded (5 days ≤ 30 days). No payment or accounting is decided here.
- **Deployment readiness:** Section D.
- **Chain-access layering & on-chain ID/ABI coupling:** ADR-0001's domain-client rule applies to TypeScript consumers; as a Rust gateway the core necessarily re-implements the read side, guarded by the vectors, the field-number fixtures and the live tests in `gateway-rust`. IDs come from `wrangler.toml` only (B.SC-1). Pre-v0.2 policy: no compatibility findings; the v2 proof is refused with no fallback.

---

## Normative requirements (MUST / MUST NOT)

Before the next deploy / at the current gate:

1. MUST NOT panic on attacker-reachable input — **holds after this pass** (F58 fixed, F60 fixed; core guarded sites reviewed: F61).
2. MUST verify signatures exactly as Sui accepts them and fail closed on other schemes — **holds** (I3).
3. MUST enforce the body cap on streamed bytes and the declared length, never buffering the body — **holds** (I9, I10).
4. MUST put a timeout on every outbound call and bound every response read — **partly holds**: timeouts yes; the RPC response bound is post-hoc (F63, FU-0032).
5. MUST keep single-use state atomic, owner-bound and fail-closed — **holds** (I6, I13).
6. MUST keep the deployed bundle free of test-only code and assert it on the artifact — **holds with the new guard** (F59; first CI run pending).
7. MUST keep the redemption lease longer than the longest request, checked at startup — **holds** (I28).
8. MUST lock the upstream to the gateway and verify the lock negatively on a schedule — **holds** (I25: 32 of 32 daily runs); the URL equality is open (FU-0035).
9. MUST NOT log or return proofs, signatures, secrets or configuration — **holds** (I18).
10. MUST redeploy the Worker from a commit that contains the fixes above — **open** (FU-0031).

Before mainnet:

11. MUST publish a mainnet `access_gate` and populate the Worker's mainnet configuration from the canonical record — **open** (FU-0036).
12. MUST confirm the plan tier against body cap, CPU and the daily request limit — **open** (FU-0029, FU-0036).
13. MUST record the deploy token's verified scope and expiry, with a reviewer or a recorded choice on the `production` environment — **open** (FU-0030, OQ1).
14. MUST decide and implement grant/denial logging — **open** (F64, OQ3).
15. MUST move the cross-implementation parity record (the TypeScript audit's B.SC-3 home table) before that audit is closed — **partly done**: the Rust-adapter rows are in B.SC-3 above and the F51–F57 pointers are in the TypeScript audit; the TypeScript column and the table's remaining rows end with `gateway-workers` and must not be relied on after it closes.

**Lens baselines.** RS-M1 holds (F58 fixed); RS-M2 holds; RS-M3 holds (bounded decoders, required status trailers, fuzzed); RS-M4 holds (declared + streamed cap; no buffering; isolate memory is the platform's); RS-M5 partly (F63); RS-M6 holds; RS-M7 holds; RS-M8 holds for logs and `Debug`, graceful shutdown is N/A on Workers; RS-M9 holds (one implementation + vectors).
CF-M1 holds; CF-M2 holds with FU-0035; CF-M3 holds (Durable Object, shard allowlist); CF-M4 holds (100 MB = the zone limit); CF-M5 holds; CF-M6 holds; CF-M7 holds (public `GET`, key without query); CF-M8 holds; CF-M9 partly (the workerd pools run in CI; the deploy is CI-gated; reviewers/token scope unverified).
PX-M1 holds; PX-M2 holds (rebuilt `Via`; other forwarding fields stripped, not rebuilt); PX-M3 holds (denylist; see B.PX-1); PX-M4 holds; PX-M5 partly (inbound header/body timeouts are the platform's); PX-M6 holds; PX-M7 holds; PX-M8 holds with FU-0035; PX-M9 holds.
AUTH-M8 holds (client `authorization` and `cf-access-*` stripped, configured headers `set`, redirects not followed); AUTH-M10 partly (uniform denials; rate-limited; decisions not logged: F64); AUTH-M11 holds (I22). AUTH-M1–M7 and M9 are N/A (no tokens issued or verified, no IdP, no browser session).
WAL-M2/M3 N/A (client side); WAL-M9 holds (the authoritative size limit is enforced on streamed bytes at the edge adapter).
SC-M1 N/A (no call targets); SC-M2 holds (full normalised type string); SC-M3 holds (effects status); SC-M4 holds (u64 handling in Rust; addresses normalised); SC-M5 holds (the network is configuration signed into the message; empty or invalid values stop startup); SC-M6 holds; SC-M7 holds (I5); SC-M8, M9 N/A; SC-M10 accepted exception (the Rust read side is a second implementation, vector-guarded).

## Implementation suggestions (SHOULD / MAY)

- **S1** SHOULD add an `[observability]` block once OQ3 is decided, and log a reason code per denial.
- **S2** SHOULD run `fuzz.yml` for longer (an hour per target) before mainnet and after any change to `grpc.rs`, `proof.rs` or `sig.rs`.
- **S3** SHOULD deny `indexing_slicing` and `unwrap_used` in non-test core code (F61) and move `unframe_request_for_test` behind a feature.
- **S4** MAY add a vector for the secp256k1 high-S rejection (the `gateway-rust` audit's F59 gap), so the explicit check is pinned on both curves.
- **S5** MAY add a wrangler `--dry-run --outdir` inspection of the final bundle to the deploy job to close F59's residual.
- **S6** MAY add `fuzz.yml` to a weekly schedule if CI minutes allow (a decision; the workflow is manual only today).
- **S7** MAY refresh `compatibility_date` (2026-06-01) after reading the workerd release notes; no `compatibility_flags` are set.

## Open questions

- **OQ1** Should the `production` environment require a reviewer for Worker deploys, or is the single-maintainer choice (a manual dispatch from `main` only) final? Today: no reviewer, recorded in the TypeScript audit's OQ4; not re-read.
- **OQ2** After `gateway-workers` is retired, is the differential harness replaced by anything (a recorded fixture run of the last TypeScript Worker, or nothing beyond the shared vectors)?
- **OQ3** What should the Worker log per grant and denial, and for how long (F64)? Options: (a) nothing beyond diagnostics; (b) a reason code and a truncated address hash with Workers Logs retention; (c) a Logpush destination.
- **OQ4** Free or Paid at mainnet: the Free plan's 100,000 requests a day is a hard stop under a flood (the quota guard only warns). Decide the threshold at which Paid is bought (`docs/economics/COST_MODEL.md`).
- **OQ5** Should `304` pass through (F65), or should validators be stripped on public paths?

## Risks

- **Fullnode honesty and availability.** The Worker trusts one operator-chosen fullnode. A lying node can admit non-holders; an unavailable one denies everyone (fail closed). A hostile node can still crash a native gateway with a malformed frame until the next deploy (F58 is fixed in source, not live).
- **Signature-scheme coverage.** Multisig, zkLogin and passkey holders cannot use the gateway until an official verifier is integrated.
- **Wallet UX.** The v3 message names the origin, gate and network; a user must still read it.
- **Durable Object as the single state authority.** Loss of the namespace (a mistaken script rename, a migration error) reopens the redemption replay window (F54).
- **Cloudflare dependency.** Access expiry, the 100,000 requests a day Free limit, edge CPU and platform incidents each stop paid uploads (fail closed).
- **0.x toolchain.** workers-rs, wasm-bindgen and worker-build move together and are pinned (F52).
- **Supply chain.** Checksummed build tools are trust-on-first-use (F53); crate advisories can appear after release.
- **Origin lock.** If the Access policy is removed or the check URL drifts from the Worker's origin, every guarantee here is moot; the daily check and FU-0035 are the controls.
- **Fuzzing is shallow so far.** Three 100-second runs found one real bug in the first second and nothing in the following ~2 million inputs; that is a smoke test, not an assurance.

---

## Re-verification log

- 2026-11-07 — first pass of this audit; F51–F57 moved from `gateway-workers-audit.md` (ids and dispositions preserved) and each re-verified against `main` `875220d`: the lint scope of F51 was narrowed to the adapter (core is F61), the pins, checksums, DO identifiers and `test-hooks` gating of F52–F54 and F57 were re-read in code, F55 was not re-read at the edge (FU-0029), and F56's differential half ends with the TypeScript Worker.
  - **Commands run:** `cargo +stable test --workspace --locked -j 2` (230 passed, 0 failed, 3 ignored; after the fixes 233), `cargo +stable fmt --check` (clean), `cargo +stable clippy --workspace --all-targets --locked -- -D warnings` (clean), `cargo +stable deny check` (ok), `cargo fuzz build` and runs of the three targets (Section C.1), a clippy lint experiment on core, `assert-prod-build.sh` against local artifacts, a scratch `url` 2.5.8 probe, `gh run list` / `gh run view` (read-only).
  - **Findings added:** F58 (RESOLVED), F59 (MITIGATED), F60 (RESOLVED), F61 (DEFERRED), F62 (RESOLVED), F63 (DEFERRED), F64 (DEFERRED), F65 (DEFERRED), F66 (Positive).
  - **Counts:** 3 RESOLVED (F58, F60, F62), 6 MITIGATED (F51, F53, F54, F55, F57, F59), 1 ACCEPTED-RISK (F52), 4 DEFERRED (F61, F63, F64, F65), 2 Positive (F56, F66); 16 findings.
  - **Not done / not verified here:** the workerd suites, the differential run, `cargo llvm-cov`, a wasm32 build of the Worker or a wasm32 test run, any Cloudflare read (edge CPU, token scope, Access policy, plan), the secret-versus-variable origin comparison, on-chain re-reads of the IDs. Follow-ups: FU-0029 to FU-0037.
  - **I27 of the `gateway-rust` audit (origin lock):** closed as far as the repository allows — the daily negative check, the positive deploy check and the classifier tests exist and the run history is green; the remainder is live (FU-0035).
