#!/usr/bin/env bash
# Scheduled negative origin check (audit F32 / CF-M2; .github/workflows/origin-lock.yml).
#
# The relay origin must be reachable ONLY with the gateway's Cloudflare Access service token. The deploy
# check proves the positive case; this proves the negative: direct requests WITHOUT the token, and with a
# made-up token, must be refused by Access. Read-only, GET only, sends no secret (the origin URL is the
# public repository variable UPSTREAM_CHECK_URL). curl makes the requests; the verdict logic is
# `access-gate-gateway-ci classify-origin` (ci/src/lib.rs), so no TypeScript is involved.
#
#   UPSTREAM_CHECK_URL=https://<origin>/v1/tip-config scripts/check-origin-locked.sh
#
# Exit 0: every probe was refused by Access (a challenged probe only warns). Exit 1: a probe reached the
# origin, was refused by something other than Access, or could not be completed.
#
# Test seams (used only by worker/tests/origin-lock.test.mjs): ORIGIN_LOCK_TEST_HTTP=1 allows an http://
# URL; ORIGIN_LOCK_RETRY_SLEEP=0 removes the back-off; ACCESS_GATE_GATEWAY_CI names the CLI binary instead of `cargo run`.
# No `-e`: a failing probe is counted and the next one still runs, so one report covers all three.
set -uo pipefail
# Run from the repository root whatever the caller's working directory is.
cd "$(dirname "$0")/.."

# The URL to probe: the first argument, else the repository variable.
raw="${1:-${UPSTREAM_CHECK_URL:-}}"
if [ -z "$raw" ]; then
  echo "::error::UPSTREAM_CHECK_URL is not set (repository variable); the origin lock cannot be checked."
  exit 1
fi
# Only https is probed (the lock is for the public origin), except in the tests, which use a local http server.
case "$raw" in
  https://*) ;;
  http://*) [ "${ORIGIN_LOCK_TEST_HTTP:-}" = 1 ] || { echo "::error::UPSTREAM_CHECK_URL must be an https URL."; exit 1; } ;;
  *) echo "::error::UPSTREAM_CHECK_URL must be an https URL."; exit 1 ;;
esac

# ci ARGS...: run the CLI that classifies a response, from the given binary (tests) or built by cargo (workflow).
ci() { if [ -n "${ACCESS_GATE_GATEWAY_CI:-}" ]; then "$ACCESS_GATE_GATEWAY_CI" "$@"; else cargo run --quiet --locked -p access-gate-gateway-ci -- "$@"; fi; }

# The origin root, for the second probe: scheme and host of the check URL, with no path.
scheme_host="${raw%%://*}://$(printf '%s' "${raw#*://}" | cut -d/ -f1)"
root="$scheme_host/"
# A made-up service token, well-shaped but unknown, for the third probe: Access must refuse it as it refuses no token.
zeros32="$(printf '0%.0s' $(seq 1 32))"
zeros64="$(printf '0%.0s' $(seq 1 64))"
# A scratch directory for the response headers; removed on exit.
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT

# Probes that were not refused by Access, and probes the zone challenged (which prove nothing).
failures=0
inconclusive=0
probes=3
# probe LABEL URL [CURL HEADER ARGS...]: one GET, with up to three attempts for a network failure, classified by the CLI.
probe() {
  local label=$1 url=$2; shift 2
  local attempt code state detail verdict
  # curl prints 000 when no response arrived; retry with a growing pause (ORIGIN_LOCK_RETRY_SLEEP seconds times the attempt).
  for attempt in 1 2 3; do
    code="$(curl --silent --show-error --max-time 15 --request GET "$@" --dump-header "$dir/h" --output /dev/null --write-out '%{http_code}' "$url" 2>"$dir/err" || true)"
    if [ "$code" != 000 ] && [ -n "$code" ]; then break; fi
    sleep $((attempt * ${ORIGIN_LOCK_RETRY_SLEEP:-3}))
  done
  # Print host and path without the scheme.
  local where="${url#*://}"
  if [ "$code" = 000 ] || [ -z "$code" ]; then
    state=error; detail="request failed after 3 attempts: $(head -c 200 "$dir/err")"
  else
    # The verdict is `locked`, `open` or `inconclusive`, then a detail.
    verdict="$(ci classify-origin --status "$code" --headers "$dir/h")"
    state="${verdict%% *}"; detail="${verdict#* }"
  fi
  printf '%-12s %s (%s): %s\n' "$state" "$label" "$where" "$detail"
  # Only `locked` is a pass; a challenge is counted separately; open and error fail.
  case "$state" in
    inconclusive) inconclusive=$((inconclusive + 1)) ;;
    locked) ;;
    *) failures=$((failures + 1)) ;;
  esac
}

# The three probes: the check path and the root without a token, and the check path with an unknown token.
probe 'no token, check path' "$raw"
probe 'no token, root' "$root"
probe 'unknown token, check path' "$raw" --header "CF-Access-Client-Id: ${zeros32}.access" --header "CF-Access-Client-Secret: ${zeros64}"

# Any probe that was not refused by Access fails the run.
if [ "$failures" -gt 0 ]; then
  echo "::error::Origin lock check failed ($failures of $probes probes): the relay origin is not refusing direct requests as Cloudflare Access should (docs/networking/CLOUDFLARE.md section 2.4)."
  exit 1
fi
# Challenged probes only warn: the others still proved the lock.
if [ "$inconclusive" -gt 0 ]; then
  echo "::warning::$inconclusive of $probes probes were challenged by the zone (Bot Fight Mode) and prove nothing; the others were refused by Access."
fi
echo "Origin lock holds: direct requests without the service token are refused by Access."
