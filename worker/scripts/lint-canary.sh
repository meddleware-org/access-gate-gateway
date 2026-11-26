#!/usr/bin/env bash
# Proves the panic lints are live: a throw-away module that unwraps, expects, panics and indexes must make
# `cargo clippy` FAIL with each of the four lints. src/lib.rs is restored byte for byte afterwards. A lint
# level quietly weakened in Cargo.toml (or an `allow` slipped in) turns this red.
set -euo pipefail
# Run from the worker directory whatever the caller's working directory is.
cd "$(dirname "$0")/.."
# The throw-away module, and a byte-for-byte backup of lib.rs to restore afterwards.
canary=src/zz_lint_canary.rs
backup="$(mktemp)"
cp src/lib.rs "$backup"
# restore: put lib.rs back and remove the canary, whatever the outcome.
restore() { cp "$backup" src/lib.rs; rm -f "$canary" "$backup"; }
# The EXIT trap makes the restore run on success, failure and interruption.
trap restore EXIT
# A function that does everything the lints forbid: unwrap, expect, panic and indexing.
cat > "$canary" <<'RS'
pub fn canary(v: &[u8], o: Option<u8>) -> u8 {
    let a = o.unwrap();
    let b = o.expect("x");
    if v.is_empty() {
        panic!("x");
    }
    a + b + v[0]
}
RS
# Declare the module, then run clippy and keep its output and status (errexit is off for this one command).
printf '\nmod zz_lint_canary;\n' >> src/lib.rs
set +e
out="$(cargo clippy --locked -p access-gate-gateway-worker --lib 2>&1)"
status=$?
set -e
[ "$status" -ne 0 ] || { echo "::error::clippy accepted unwrap/expect/panic/indexing in the Worker"; exit 1; }
# clippy prints the lint names with hyphens (`clippy::unwrap-used`).
for lint in unwrap-used expect-used panic indexing-slicing; do
  echo "$out" | grep -q "clippy::$lint" || { echo "$out"; echo "::error::clippy::$lint is not enforced in worker/"; exit 1; }
done
echo "lint canary: unwrap_used, expect_used, panic and indexing_slicing are all denied in worker/"
