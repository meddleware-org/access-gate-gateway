#!/usr/bin/env bash
# Size of the release wasm per opt-level (deployed variant and test-hooks variant). Usage: scripts/size-variants.sh <out-dir>
# Needs worker-build on PATH. Not part of CI; used for the README measurements and the opt-level choice.
set -euo pipefail
OUT=${1:?out dir}
cd "$(dirname "$0")/.."
for lvl in s 3 z; do
  export CARGO_PROFILE_RELEASE_OPT_LEVEL=$lvl
  worker-build --release -d "$OUT/prod-$lvl" >/dev/null 2>&1
  worker-build --release -d "$OUT/hooks-$lvl" --features test-hooks >/dev/null 2>&1
  python3 -I - "$OUT" "$lvl" <<'PY'
import gzip, sys, brotli
out, lvl = sys.argv[1:3]
for kind in ("prod", "hooks"):
    d = open(f"{out}/{kind}-{lvl}/index_bg.wasm", "rb").read()
    print(f"opt-level={lvl} {kind}: raw {len(d)}  gzip9 {len(gzip.compress(d, 9))}  brotli11 {len(brotli.compress(d, quality=11))}")
PY
done
