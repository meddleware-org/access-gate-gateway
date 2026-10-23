#!/usr/bin/env bash
# Derive the SHADOW Worker's wrangler config from the production one: a different script name (so a new,
# empty Durable Object namespace: exactly right for a shadow, the live nonce/redemption data is never
# touched), served on workers.dev instead of the production route, and with its own GATEWAY_ORIGIN (the
# audience clients sign into proofs must be the shadow's own origin).
#
#   scripts/make-shadow-config.sh <worker-name> <https://origin> > wrangler.shadow.toml
set -euo pipefail
cd "$(dirname "$0")/.."
name="${1:?worker name}"
origin="${2:?gateway origin (https://host)}"
live=access-gate-gateway
[[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || { echo "invalid worker name: $name" >&2; exit 1; }
[ "$name" != "$live" ] || { echo "the shadow must not use the live Worker's name ($live)" >&2; exit 1; }
[[ "$origin" =~ ^https://[a-z0-9.-]+(:[0-9]+)?$ ]] || { echo "gateway origin must be a canonical https origin: $origin" >&2; exit 1; }
awk -v name="$name" -v origin="$origin" '
  /^\[\[routes\]\]/ { skip = 1; next }
  skip && (/^\[/ || /^#/ || /^$/) { skip = 0 }
  skip { next }
  /^name = / && !named { named = 1; print "name = \"" name "\""; next }
  /^workers_dev = / { print "workers_dev = true"; next }
  /^GATEWAY_ORIGIN = / { print "GATEWAY_ORIGIN = \"" origin "\""; next }
  { print }
' wrangler.toml
