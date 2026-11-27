# Changelog

Changes to the Rust crates (`access-gate-gateway-core`, `access-gate-gateway`), the Rust Worker, the image and the workflows. The one version covers
every artifact (D16), so a release is a release of all of them. The history of the npm package up to 0.0.33, which also records every earlier
release of the whole repository, is in [gateway-workers/CHANGELOG.md](gateway-workers/CHANGELOG.md).

## Unreleased

## 0.0.34 - 2026-11-27

- The configuration errors for `ALLOWED_ORIGINS` and `PUBLIC_PATHS` name the entry by its position and no longer repeat it (the Rust core and the
  TypeScript Worker alike), so a list that was pasted with something sensitive in it is never echoed.
- `access-gate-gateway-core` no longer exports `chain::_unused_now_ms`, a function that returned zero and had no caller.
- `missing_docs` and `clippy::missing_docs_in_private_items` are denied in the workspace lints (and the Worker's own), and every item, field and variant has a
  doc comment. The sources, scripts, manifests and workflows carry line-level comments, and `CONTRIBUTING.md` is added.
- The chain client's tests moved from `gateway-rust/src/sui_rpc.rs` to `gateway-rust/src/sui_rpc_tests.rs`, next to `router_tests.rs`; no test changed.
- Dependabot no longer carries an ignore rule for the `golang` image, which the Dockerfile does not use.
- No other behaviour change.
