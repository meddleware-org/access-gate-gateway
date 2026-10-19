#!/usr/bin/env bash
# One version for every artifact (grounding log D16): the npm package, the Cargo workspace (the crates
# nft-gate-core and nft-gate-gateway inherit it) and the image.
# Fails when gateway-workers/package.json and the workspace version in Cargo.toml differ, when a crate
# does not inherit the workspace version, when the gateway pins a different nft-gate-core than the
# workspace carries, and, on a tag push, when the version differs from the tag.
set -euo pipefail
cd "$(dirname "$0")/.."

npm_version="$(node -p "require('./gateway-workers/package.json').version")"
crate_version="$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version = "\(.*\)"$/\1/p}' Cargo.toml | head -n 1)"

if [ -z "$crate_version" ]; then
  echo "::error::no version in the [workspace.package] table of Cargo.toml"
  exit 1
fi

if [ "$npm_version" != "$crate_version" ]; then
  echo "::error::gateway-workers/package.json is ${npm_version} but the Cargo workspace (Cargo.toml) is ${crate_version}"
  exit 1
fi

# Every workspace crate takes the one version; none may carry its own.
for manifest in core/Cargo.toml gateway-rust/Cargo.toml; do
  if ! grep -q '^version\.workspace = true$' "$manifest"; then
    echo "::error::${manifest} must inherit the workspace version (version.workspace = true)"
    exit 1
  fi
done

# The gateway is published against the core of the same release.
core_pin="$(sed -n 's/^nft-gate-core = {.*version = "=\([^"]*\)".*$/\1/p' gateway-rust/Cargo.toml | head -n 1)"
if [ "$core_pin" != "$crate_version" ]; then
  echo "::error::gateway-rust/Cargo.toml pins nft-gate-core =${core_pin:-<none>} but the workspace version is ${crate_version}"
  exit 1
fi

if [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  tag_version="${GITHUB_REF_NAME#v}"
  if [ "$tag_version" != "$npm_version" ]; then
    echo "::error::tag ${GITHUB_REF_NAME} does not match the package version ${npm_version}"
    exit 1
  fi
fi

echo "versions aligned: ${npm_version}"
