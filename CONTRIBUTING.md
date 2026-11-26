# Contributing to access-gate-gateway

Thank you for looking. access-gate-gateway is part of [Meddleware](https://meddleware.co.uk): open tools you can use, take everything when you leave,
and run yourself. This file says how to build it, test it and propose a change.

## Build and test

```bash
cargo fmt --check                                                              # formatting
cargo clippy --all-targets --locked --workspace -- -D warnings                 # lints; a missing doc comment on any item, private ones included, fails the build
cargo test --locked --workspace                                                # core + gateway-rust + the Worker's glue + the CI helper
cargo build --locked -p access-gate-gateway-core --target wasm32-unknown-unknown   # the Worker's target
cargo clippy --locked -p access-gate-gateway-worker --lib --target wasm32-unknown-unknown -- -D warnings
(cd worker && npm ci && bash scripts/build.sh all && npm test)                 # the Rust Worker under workerd (needs `npm ci` in gateway-workers for the differential run)
(cd gateway-workers && npm ci && npm run type-check && npm run lint && npm run test:all)   # the TypeScript Worker
bash scripts/check-versions.sh                                                 # one version for every artifact
```

CI runs the same commands on every push and pull request (`.github/workflows/`). A change is ready when they all pass locally.

## Proposing a change

1. Open an issue first for anything larger than a fix, so the design can be agreed before the work.
2. Keep a change to one purpose. Write a short subject line in the imperative ("Fix the relay timeout"), and say why in the pull request.
3. **Decision logic goes in `core/`, once.** A rule changed in only one adapter drifts from the others; the shared vectors in `conformance/vectors.json` are what keeps them equal.
4. Add or update tests with the behaviour they cover. A bug fix comes with a test that failed before it.
5. Add a line to `CHANGELOG.md` under `Unreleased` (and to `gateway-workers/CHANGELOG.md` when the npm package changes).
6. Security problems go to the address in [`SECURITY.md`](SECURITY.md), never to a public issue.

## House rules

- **Licence.** Everything here is [0BSD](LICENSE). By contributing you agree your contribution is released under it.
- **Versions.** Until the platform's mainnet launch, every release is a patch bump, breaking changes included; the changelog says what broke. One version covers the npm package, the crates, the Worker and the image.
- **Fail closed.** An ambiguous state (a bad signature, a missing nonce, a chain error, a store that cannot answer) denies; it never admits.
- **No echo.** A message, log line or error never repeats a configured or caller-supplied URL, header, token or key. Name the key or the position instead.
- **No secrets, no personal data** in code, tests, fixtures, comments or commit messages.
- **Privacy.** The gateway sets no cookie, stores nothing in a visitor's browser, and sends nothing to a host the project does not document. No telemetry, analytics or tracking.
- **Open standards.** Where a standard exists and fits, use it; the standards inventory in the audit (`docs/audit/access-gate-gateway-audit.md` in the workspace repository) lists the ones this project speaks.

## Documentation

Every file explains itself, line by line where the code is not self-evident:

- a header on every file saying what it is for;
- a doc comment on every declaration (`///` in Rust, TSDoc in TypeScript, a comment line above a shell function), private ones included;
- comments that say **why**, cite the decision, issue or standard behind a choice, and are updated with the code;
- no `TODO` or `FIXME` without an issue or follow-up reference on the same line;
- every command a document shows has been run, and every link resolves.
