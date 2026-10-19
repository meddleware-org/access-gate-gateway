#!/usr/bin/env bash
# Build the Worker's two variants with worker-build (needs wasm32-unknown-unknown; worker-build 0.8.7 on PATH):
#   build/        the deployed Worker (no test routes)
#   build-hooks/  the same plus the `test-hooks` feature (routes under /__test/*), used only by the suites
# Same opt-level as wrangler.toml's [build]. Usage: scripts/build.sh [prod|hooks|all]
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_PROFILE_RELEASE_OPT_LEVEL=s
what="${1:-all}"
if [ "$what" = prod ] || [ "$what" = all ]; then
  worker-build --release
fi
if [ "$what" = hooks ] || [ "$what" = all ]; then
  worker-build --release -d build-hooks --features test-hooks
fi
