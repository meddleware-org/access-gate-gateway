#!/usr/bin/env bash
# Size gate: `wrangler deploy --dry-run` (builds nothing remote, deploys nothing) reports the bundle
# Cloudflare would receive; fail when its gzip total exceeds the budget. Cloudflare's limit is 64 MiB
# uncompressed on both plans (no compressed limit, docs checked 2026-10-19); the budget is a regression
# tripwire for the Rust Worker, whose TypeScript predecessor was 136.71 KiB gzip.
# Usage: scripts/size-gate.sh [budget-KiB, default 1536 = 1.5 MiB]   (run after scripts/build.sh prod)
set -euo pipefail
cd "$(dirname "$0")/.."
budget="${1:-1536}"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
# The build already ran; skip wrangler's [build] step by pointing a throwaway config at build/.
cat > "$out/wrangler.dry.json" <<JSON
{ "name": "access-gate-gateway-size-gate", "main": "$PWD/build/index.js", "compatibility_date": "2026-06-01",
  "durable_objects": { "bindings": [ { "name": "NONCE_STATE", "class_name": "NonceRateState" } ] },
  "migrations": [ { "tag": "v1", "new_sqlite_classes": ["NonceRateState"] } ] }
JSON
log="$(CI=1 WRANGLER_SEND_METRICS=false npx wrangler deploy --dry-run --outdir "$out/dist" -c "$out/wrangler.dry.json" 2>&1)"
echo "$log" | grep -E "Total Upload" || { echo "$log"; echo "::error::no 'Total Upload' line in the dry-run output"; exit 1; }
gz="$(echo "$log" | sed -n 's/.*Total Upload: .* gzip: \([0-9.]*\) KiB.*/\1/p' | head -n 1)"
[ -n "$gz" ] || { echo "$log"; echo "::error::could not read the gzip size"; exit 1; }
wasm="$(stat -c %s build/index_bg.wasm)"
echo "wasm: ${wasm} bytes; dry-run gzip total: ${gz} KiB; budget: ${budget} KiB"
awk -v gz="$gz" -v b="$budget" 'BEGIN { exit !(gz + 0 <= b + 0) }' || { echo "::error::the Worker bundle is ${gz} KiB gzip, over the ${budget} KiB budget"; exit 1; }
