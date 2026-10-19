# Changelog

All notable changes to `@meddleware/nft-gate-gateway` are documented here.

## [0.0.26] - 2026-10-19

No change to the Worker's code; the version moves with the Rust gateway (one version for every artifact).

### Changed

- Docs: the Worker is being replaced by a Rust Worker (workers-rs) built on `nft-gate-core`, the decision logic now shared with `gateway-rust` (maintainer's
  standing rule: no JS/TS backend code). This TypeScript Worker stays the live deployment and the rollback until a measured cutover (CPU-time p99 on a shadow
  deploy). The Workers KV nonce backend will not be carried over. The single implementation refuses a literal `..` path segment, which `isSafePath` here lacks (not
  exploitable on Workers, whose URL parser normalises dot segments first).

## [0.0.25] - 2026-10-19

### Added

- `WORKERS_PLAN` (`free` default | `paid`, strict like every other var): the quota guard measures against the plan's published allowances. Free: daily (00:00 UTC) 100,000 Worker requests, 100,000 Durable Object requests and 13,000 DO GB-s; Paid: monthly 10M requests, 30M CPU-ms, 1M DO requests and 400,000 DO GB-s (Cloudflare docs, checked 2026-10-19). Worker and DO requests are separate meters (they were summed against a stale 3M/month figure), DO duration is active seconds × 0.128 GB, Worker CPU is read on Paid. On Paid the guard only warns (overage is billed, nothing fails) and never sets the degrade flag; single-use still ignores the flag. A GraphQL error is now a failed check instead of reading as zero usage. Tests: `test/quota.test.ts` (both modes), `test/config.test.ts`.
- CPU micro-benchmark of signature verification per scheme (audit F11): `test/cpu-bench.test.ts` in workerd (wall time; workerd exposes no CPU clock) and `test/cpu-bench.node.test.ts` (process CPU time), both on the shared vectors and asserting a warm verification stays under the Free 10 ms per-request limit.
- `wrangler.toml`: a commented `[limits] cpu_ms = 50` block (the denial-of-wallet ceiling for Workers Paid) and `WORKERS_PLAN = "free"`; README "Switch to Workers Paid" runbook and "CPU budget on Free".

### Changed

- `MAX_BODY_BYTES` in `wrangler.toml` is `100000000` (10⁸ B, the Free/Pro zone limit, which is decimal), so an oversized upload gets the gateway's own JSON `413` instead of Cloudflare's (it was `104857600`).

## [0.0.24] - 2026-10-19

### Added

- Loop detection (audit F43, both gateways at once): every upstream request carries `Via: 1.1 nft-gate` (a client-supplied `Via` is still dropped), and a request that arrives already naming `nft-gate` as a received-by hop is refused `508 {"error":"loop detected"}` after `/healthz` and the CORS preflight and before any nonce, rate-limit or redemption work. Only our own token matches; foreign values such as a CDN's `1.1 google` pass. Tests: `VIA_TABLE` in `test/proxy.test.ts` (identical table in the Rust gateway), the marker on the upstream request, and the 508/foreign-Via cases in the workerd router suite.

### Changed

- Docs: the commit-failure outcome (`502` + release, the use is kept) is documented as a decision (OQ6) in the READMEs and CLAUDE.md files.

## [0.0.23] - 2026-10-19

### Changed

- `@meddleware/access-gate-client` ^0.0.9 (was ^0.0.6): the 2026-10-09 package's abort codes 15 and 16 and the gate-policy validator; the ownership read is unchanged. Dependency refreshes (`@mysten/sui` 2.36, wrangler 4.151, `@cloudflare/vitest-pool-workers` 0.23, vitest 4.1.12, typescript-eslint 8.71.2) and the grouped GitHub Actions bump.
- Dependabot policy encoded in `.github/dependabot.yml`: the axum, redis and base64 majors, `@types/node` and TypeScript majors and the Node/Go container majors are ignored (Node 24 LTS only; the Rust toolchain and axum 0.8 / redis 1.x migrations are deployment-time work).

### Security

- Released together with `gateway-rust` 0.0.23, whose lockfile moves `rustls` to 0.23.46 (RUSTSEC-2026-0346, RUSTSEC-2026-0347 and the Brotli certificate-decompression advisory); the Worker has no Rust dependency.

## [0.0.22] - 2026-10-10

### Added

- `Origin lock` workflow (`.github/workflows/origin-lock.yml`, daily and on demand) with `scripts/check-origin-locked.mjs`: the scheduled negative check of the relay origin lock (audit F32). It sends GET requests without a token, and with an unknown one, to the origin in the repository variable `UPSTREAM_CHECK_URL` and fails unless Cloudflare Access refuses each. No secret involved. Unit-tested (`test/origin-lock.test.ts`).
- Tests: the new proof-decode reject vectors in the workerd router suite; public-path rate limit, IPv6 /64 keying, gated responses never cached, store outage as 503 and the quota-degrade flag (`test/gateway-state.test.ts`).

### Changed

- `@meddleware/nft-gate-client` ^0.0.17 (strict base64, UTF-8 and JSON proof decoding) and the refreshed `conformance/vectors.json` (11 new `proofDecodeRejects`); closes the base64-layer parity finding for this Worker.
- Comments only: `chain.ts` module doc, `cors.ts`, `wrangler.toml` header and the `proxy.ts` `@ts-expect-error` note now describe the current behaviour; the unused `nonceMatches` helper is removed.
- `NFT_TYPE` and `GATE_ID` in `wrangler.toml` name the 2026-10-09 testnet publication (access_gate `0xd7ddaa94…`, relay gate `0x316f1bf9…`); deploy together with the apps' `VITE_ACCESS_GATE_ID_TESTNET`.

## [0.0.21] - 2026-10-08

### Fixed

- `src/config.ts` has no imports again, so `scripts/check-upstream-auth.mjs` (the deploy workflow's pre-check) loads it under plain Node; 0.0.19 broke that check. A test guards it.

## [0.0.20] - 2026-10-08

### Changed

- `@meddleware/access-gate-client` ^0.0.6 (strict event decoding, exact pass variants).

## [0.0.19] - 2026-10-08

### Changed (breaking: protocol v2, configuration)

- **Audience-bound access proofs.** The signed message is now `nft-gate:access:v2` and binds this
  gateway's origin, the gate id, the network, the nonce and (single-use) the consume digest; the
  Worker rebuilds it from `GATEWAY_ORIGIN`, `GATE_ID` and `NETWORK`. v1 proofs are refused. New
  required vars: `GATEWAY_ORIGIN`, `NETWORK`.
- **Owner-bound redemption.** A lease returns a random token and commit/release are compare-and-set
  on it, so a lapsed request cannot clear or overwrite a newer holder's lease. A commit whose lease
  was lost is `502`. `REDEMPTION_LEASE_TTL_SECS` defaults to 900 and must exceed the new
  `UPSTREAM_TIMEOUT_SECS` (600, a total deadline, `504` past it); both are checked at startup.
- **Single-use needs the Durable Object.** `SINGLE_USE=true` with `NONCE_BACKEND=kv` is refused, the
  quota-degrade flag is ignored in that mode, and redemptions are no longer implemented on KV.
- A consume older than `CONSUME_MAX_AGE_SECS` (5 days) is refused, so it cannot outlive its
  redemption record. A digest the node does not know is `403`; only "not found" is retried, and a
  malformed digest never reaches the RPC.
- **Ownership mode counts usable passes only** (unlimited, or single-use with uses left;
  `@meddleware/access-gate-client` 0.0.5). An unrecognised `Gate` JSON denies (`502`) instead of
  reading as "not paused". Every Sui RPC read has a deadline (`RPC_TIMEOUT_SECS`).
- **Strict configuration.** Booleans must be `true`/`false`, numbers integers within bounds, origins
  canonical, `PUBLIC_PATHS` plain paths, `SUI_RPC_AUTH_HEADER` `Name: value`, URLs https. A bad value
  is a startup error, never a weaker mode. `ALLOWED_ORIGINS` defaults to none (`wrangler.toml` keeps
  Meddleware's origins).
- **Proxy hygiene.** Upstream redirects are never followed (`302` is `502`); hop-by-hop fields (and
  those named in `Connection`), cookies, forwarding fields and client `cf-access-*` headers are
  stripped from the request, and hop-by-hop fields, cookies and every upstream CORS field from the
  response; only `GET`/`HEAD`/`POST`/`PUT` are forwarded (`405`), public paths are `GET`/`HEAD` only,
  unsafe paths are `400`.
- Gated requests are rate-limited per client IP before signature verification
  (`GATED_PREAUTH_RATE_LIMIT_PER_MIN`); IPv6 clients are keyed by /64; the rate table is swept; the
  ownership cache is bounded.
- `wrangler.toml`: `compatibility_date` 2026-06-01, `workers_dev` and `preview_urls` off.
- The conformance vectors are published by `@meddleware/nft-gate-client` 0.0.16
  (`scripts/sync-vectors.mjs`); `scripts/gen-vectors.mjs` is gone.

## [0.0.18] - 2026-10-08

### Changed

- Worker source: `noUncheckedIndexedAccess` is on, with the mechanical fixes it required (byte
  loops iterate values; a missing row or capture group is handled explicitly in the nonce, rate and
  redemption checks). No behaviour change.
- `@meddleware/access-gate-client` 0.0.4 and `@meddleware/nft-gate-client` 0.0.15.
- `@mysten/sui` is `^2.33.1` like every other package (it was `~2.33.1`).
- Dev tooling: `source-map-js` 1.2.2 and a `sharp` 0.35.5 override (GHSA-68fv-2mgg-jv7q,
  GHSA-wq5f-xc86-pv6w). Rust gateway unchanged (version alignment only).

## [0.0.17] - 2026-10-02

### Changed

- No Worker changes: released with the Rust gateway 0.0.17 (one version for every artifact).

## [0.0.16] - 2026-10-02

### Changed

- `@meddleware/access-gate-client` 0.0.3: `ownsAccessNft` compares the configured `GATE_ID`
  normalised, and an NFT whose gate id is not an address is ignored.

## [0.0.15] - 2026-10-02

### Changed

- `@meddleware/access-gate-client` 0.0.2 (the version-gated `access_gate` client; `ownsAccessNft`
  is unchanged) and `@meddleware/nft-gate-client` 0.0.14.
- The shared `proofDecodeRejects` conformance vectors (oversized token, non-ASCII fields) are
  asserted here and in the Rust gateway.
- ESLint (typescript-eslint recommended) runs in CI.

## [0.0.14] - 2026-10-02

### Changed

- Testnet: the relay gate is `0xfd6c3b2a…b8a6` on the version-gated `access_gate` `0xa55789…6d41`
  (`NFT_TYPE` `0xa55789…::access_gate::SoulboundAccessNFT`). Passes from the superseded `0x1a81ca…`
  package and gate `0xcb8206…` are no longer accepted.
- `NFT_TYPE` is a `[vars]` entry in `wrangler.toml` instead of a Worker secret: it is a public on-chain
  type. The Deploy Workers workflow retires the old secret from a pending version first (a secret and a
  var may not share a name), so the switch has no downtime.
- `ALLOWED_ORIGINS` (and the code default) adds `https://sui-token-deployer.meddleware.co.uk`: the
  standalone token deployer uploads icons through the gated relay too (workspace decision D21).

- The `Deploy Workers` workflow also accepts `UPSTREAM_AUTH_HEADERS` as a GitHub secret: when set it
  is validated and deployed with the code as one Worker version; when unset the deploy is unchanged
  (`wrangler deploy`, Cloudflare-stored secrets).

## [0.0.13] - 2026-10-01

Versions are aligned from this release: the npm package, the crate and the image share one version.

### Security

- Single-use: the consume event must be exactly `<NFT_TYPE package>::access_gate::AccessConsumedEvent`
  (previously any `…::access_gate::AccessConsumedEvent` suffix, which a look-alike package could
  emit for free). Sender and gate ids are compared in normalised form.

### Changed

- **Breaking (operator):** `UPSTREAM_AUTH_HEADERS` is a JSON array of `{name, value}`; the old
  comma-separated `Name: value` string fails closed at startup. See the walrus runbook for the
  migration order.
- `ALLOWED_ORIGINS` code default matches `wrangler.toml` (`sui-walrus.` and `dash.`).
- A misconfigured gateway answers `500 gateway misconfigured` without echoing the config error.
- Public GET paths drop the query string from the edge-cache key and the forwarded request.
- ed25519 verification is explicitly ZIP-215 (Sui's rule).

### Added

- `GET /v1/challenge` per-IP rate limit (`CHALLENGE_RATE_LIMIT_PER_MIN`, default 30; Rust parity).
- Nonce shard tags are validated against the continent allowlist; forged tags are `NonceInvalid`.
- State-backend failures return a JSON `503` with CORS; a failed redemption commit releases the
  lease and returns `502` (Rust parity).
- `Vary: Origin` on every response.
- Conformance: `negativeSignatures` (high-S k1/r1, non-canonical ed25519 s, wrong intent,
  truncated, flags 0x03/0x05/0x06) and a `zip215` acceptance vector.

- Ownership checks use `@meddleware/access-gate-client` `ownsAccessNft`: exact NFT type at the
  package's original id, and every owned-object page is read (previously only the first page, so a
  holder with many objects could be denied). `@meddleware/nft-gate-client` 0.0.13 supplies only the
  wire format.

### Fixed

- The quota guard no longer throws when the KV degrade-flag write fails.

## [0.0.3] - 2026-08-29

### Added

- Inline TSDoc documentation on `chain.ts`, `config.ts`, `crypto.ts`, and `verify.ts`.
- `AGENTS.md` and `CLAUDE.md` developer documentation for `gateway-workers`.

## [0.0.2] - 2026-08-28

### Changed

- Bumped `@meddleware/nft-gate-client` peer dependency to `0.0.2`.
- Updated `wrangler.toml` operator placeholder values (upstream URL, route pattern, zone name).

## [0.0.1] - 2026-08-27

### Added

- `UPSTREAM_AUTH_HEADERS` env var: comma-separated `Name: value` header pairs injected on every
  upstream relay request. Enables Cloudflare Access service-token authentication when the relay
  origin is CF-Access-locked. Set via `wrangler secret put UPSTREAM_AUTH_HEADERS` — never in
  `wrangler.toml`.
- `wrangler.toml` operator placeholders for `UPSTREAM_URL`, route pattern, and zone name.
- `test/config.test.ts`: unit tests for `UPSTREAM_AUTH_HEADERS` parsing (single entry, two CF
  Access entries, whitespace trimming, value-internal colons).
