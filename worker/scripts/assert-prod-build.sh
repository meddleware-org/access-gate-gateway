#!/usr/bin/env bash
# Artifact guard (audit F59): the DEPLOYED Worker bundle must not contain the code of the `test-hooks` cargo feature
# (the /__test/* routes, the TEST_FAIL_STATE fault injection, the QUOTA_GRAPHQL_URL override of the analytics endpoint,
# the deliberate panic). The feature is compiled out with `cfg`, so its strings are absent from a production build and
# present in the `build-hooks/` variant; this fails when any marker is found in any file under the directory.
#
#   scripts/assert-prod-build.sh [dir, default build]        # run after scripts/build.sh prod
#   scripts/assert-prod-build.sh --self-test [hooks-dir]     # proves the guard bites: it must FAIL on the hooks variant
set -euo pipefail
# Run from the worker directory whatever the caller's working directory is.
cd "$(dirname "$0")/.."
# Strings that exist only in the test-hooks code: a route prefix, an environment variable, a URL override and a panic message.
markers=('__test/' 'TEST_FAIL_STATE' 'QUOTA_GRAPHQL_URL' 'deliberate panic (test-hooks)')

# scan DIR: print each marker found under DIR; returns 0 when none, 1 when any, 2 when DIR cannot be scanned.
scan() {
  local dir=$1 found=0 m
  # A missing directory is a usage error (status 2), not a clean result.
  [ -d "$dir" ] || { echo "::error::$dir does not exist; build first" >&2; return 2; }
  # An empty build would pass trivially, so it is refused too.
  [ -n "$(find "$dir" -type f \( -name '*.wasm' -o -name '*.js' -o -name '*.mjs' \) -print -quit)" ] \
    || { echo "::error::$dir holds no wasm or js to scan" >&2; return 2; }
  # -a treats the wasm binary as text, -F matches the marker literally, and -l reports a file once and stops reading it at the first match.
  for m in "${markers[@]}"; do
    if grep -rlaF --include='*.wasm' --include='*.js' --include='*.mjs' -e "$m" "$dir" >/dev/null; then
      echo "found test-hooks marker '$m' under $dir" >&2
      found=1
    fi
  done
  return $found
}

# The self-test runs the guard on the build that SHOULD contain the markers: if it passes that, it cannot see them.
if [ "${1:-}" = "--self-test" ]; then
  if scan "${2:-build-hooks}"; then
    echo "::error::the guard accepted the test-hooks build; it cannot detect the feature" >&2
    exit 1
  fi
  echo "self-test: the guard rejects the test-hooks build"
  exit 0
fi

# The normal run: the production bundle must be clean.
dir="${1:-build}"
scan "$dir" || { echo "::error::the production bundle in $dir contains test-hooks code" >&2; exit 1; }
echo "production bundle in $dir has no test-hooks code"
