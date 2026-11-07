# core/fuzz: cargo-fuzz targets for `access-gate-gateway-core`

Fuzz targets (libFuzzer) for the code that parses attacker-shaped bytes. This directory is its **own workspace** (see
`Cargo.toml`): it is not built by `cargo build/test --workspace`, not checked by `cargo deny`, and no default CI job runs it.
It needs a nightly toolchain.

| Target | What it exercises | Properties checked |
| --- | --- | --- |
| `grpc` | `grpc::unframe` / `frame`, `ProtoReader`, the `Value` lookups and the `chain` response parsers | no panic; an unframed message is at most 4 MiB and at most the input; `unframe(frame(x)) == x`; every field lies inside its message |
| `proof` | `proof::decode_access_proof` (raw, base64-wrapped and as JSON built from the input), `is_tx_digest`, `is_nonce`, `personal_message` | no panic; a successful decode satisfies the documented grammar and always yields a signable message |
| `sig` | `sig::verify_personal_message_signature` for every flag byte (structured and raw), the address helpers | no panic; multisig, zkLogin and unknown flags never verify; the ZIP-215 conformance signature verifies for every message and for no other address |

```sh
cargo install cargo-fuzz --locked          # once
cd core
mkdir -p fuzz/corpus/grpc
cargo fuzz run grpc fuzz/corpus/grpc fuzz/seeds/grpc -- -max_total_time=120 -dict=fuzz/dictionaries/grpc.dict
cargo fuzz run proof fuzz/corpus/proof fuzz/seeds/proof -- -max_total_time=120 -dict=fuzz/dictionaries/proof.dict
cargo fuzz run sig fuzz/corpus/sig -- -max_total_time=120
```

`fuzz/corpus/`, `fuzz/artifacts/` and `fuzz/target/` are git-ignored and large; delete them when done. `fuzz/seeds/` holds the few
committed inputs (golden proof tokens, framed gRPC responses, and `regression-*` files that are minimised crashes).

When a target crashes: `cargo fuzz tmin <target> <artifact>` minimises it; fix the bug in `core/src` with a regression test, copy
the minimised input to `fuzz/seeds/<target>/regression-<finding>`, and re-run. The manual workflow `.github/workflows/fuzz.yml`
(`workflow_dispatch` only) runs the same targets and prints a crash's input as base64.

Results are recorded in the Rust Worker audit (`worker/docs/audit/gateway-rust-worker-audit.md`, F58 and Section C).
