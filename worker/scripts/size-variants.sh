#!/usr/bin/env bash
# Size of the release wasm per opt-level (deployed variant and test-hooks variant). Usage: scripts/size-variants.sh <out-dir>
# Needs worker-build on PATH. Not part of CI; used for the README measurements and the opt-level choice.
set -euo pipefail
# The output directory is required: each build goes in its own subdirectory of it.
OUT=${1:?out dir}
# Run from the worker directory whatever the caller's working directory is.
cd "$(dirname "$0")/.."
# The three size/speed trade-offs rustc offers: s (small), 3 (fast) and z (smallest).
for lvl in s 3 z; do
  export CARGO_PROFILE_RELEASE_OPT_LEVEL=$lvl
  # The deployed variant, then the one with the test hooks, each at this level.
  worker-build --release -d "$OUT/prod-$lvl" >/dev/null 2>&1
  worker-build --release -d "$OUT/hooks-$lvl" --features test-hooks >/dev/null 2>&1
  # Report the raw size and the compressed sizes the platform serves with (gzip and brotli at their top levels).
  python3 -I - "$OUT" "$lvl" <<'PY'
import gzip, sys, brotli
out, lvl = sys.argv[1:3]
for kind in ("prod", "hooks"):
    d = open(f"{out}/{kind}-{lvl}/index_bg.wasm", "rb").read()
    print(f"opt-level={lvl} {kind}: raw {len(d)}  gzip9 {len(gzip.compress(d, 9))}  brotli11 {len(brotli.compress(d, quality=11))}")
PY
done
