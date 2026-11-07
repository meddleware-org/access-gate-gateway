#!/usr/bin/env bash
# Artifact guard (audit F59): the DEPLOYED Worker bundle must not contain the code of the `test-hooks` cargo feature
# (the /__test/* routes, the TEST_FAIL_STATE fault injection, the QUOTA_GRAPHQL_URL override of the analytics endpoint,
# the deliberate panic). The feature is compiled out with `cfg`, so its strings are absent from a production build and
# present in the `build-hooks/` variant; this fails when any marker is found in any file under the directory.
#
#   scripts/assert-prod-build.sh [dir, default build]        # run after scripts/build.sh prod
#   scripts/assert-prod-build.sh --self-test [hooks-dir]     # proves the guard bites: it must FAIL on the hooks variant
set -euo pipefail
cd "$(dirname "$0")/.."
markers=('__test/' 'TEST_FAIL_STATE' 'QUOTA_GRAPHQL_URL' 'deliberate panic (test-hooks)')

scan() { # dir -> prints the markers found, returns 0 when none
  local dir=$1 found=0 m
  [ -d "$dir" ] || { echo "::error::$dir does not exist; build first" >&2; return 2; }
  [ -n "$(find "$dir" -type f \( -name '*.wasm' -o -name '*.js' -o -name '*.mjs' \) -print -quit)" ] \
    || { echo "::error::$dir holds no wasm or js to scan" >&2; return 2; }
  for m in "${markers[@]}"; do
    if grep -rlaF --include='*.wasm' --include='*.js' --include='*.mjs' -e "$m" "$dir" >/dev/null; then
      echo "found test-hooks marker '$m' under $dir" >&2
      found=1
    fi
  done
  return $found
}

if [ "${1:-}" = "--self-test" ]; then
  if scan "${2:-build-hooks}"; then
    echo "::error::the guard accepted the test-hooks build; it cannot detect the feature" >&2
    exit 1
  fi
  echo "self-test: the guard rejects the test-hooks build"
  exit 0
fi

dir="${1:-build}"
scan "$dir" || { echo "::error::the production bundle in $dir contains test-hooks code" >&2; exit 1; }
echo "production bundle in $dir has no test-hooks code"
