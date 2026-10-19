#!/usr/bin/env bash
# Download the three tools worker-build would otherwise fetch on its own (wasm-bindgen CLI, Binaryen's
# wasm-opt, esbuild), verify each against a pinned SHA-256, unpack them under $TOOLS_DIR and point
# worker-build at them (WASM_BINDGEN_BIN, WASM_OPT_BIN, ESBUILD_BIN; written to $GITHUB_ENV in CI and
# printed as `export` lines otherwise). The versions are the ones worker-build 0.8.7 pins; bump them
# together with worker-build and the wasm-bindgen crate (see README "Toolchain").
#
#   eval "$(worker/scripts/fetch-build-tools.sh)"        # locally
# Linux x86_64 only (the CI runner); elsewhere let worker-build download its own.
set -euo pipefail

WASM_BINDGEN_VERSION=0.2.129
WASM_BINDGEN_SHA256=82d12bb940e2d4e72e0d5605387fc1b8ca179044e012b620f0ce4e7440e8320e
BINARYEN_VERSION=132
BINARYEN_SHA256=195ddc94f9bc89f45abdabb0b9eea86023d727ba90eac8b35b80f2544fc30572
ESBUILD_VERSION=0.28.2
ESBUILD_SHA256=9573bb2233aab0f9ea7647d5cca9726113cc1768de61d66b17267f4db84488f6 # npm @esbuild/linux-x64; sha512 matches the registry's dist.integrity

TOOLS_DIR="${TOOLS_DIR:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/nft-gate-build-tools}"
mkdir -p "$TOOLS_DIR"

fetch() { # url sha256 file
  local url=$1 sum=$2 file=$3
  [ -f "$TOOLS_DIR/$file" ] || curl --fail --silent --show-error --location --retry 3 -o "$TOOLS_DIR/$file" "$url"
  echo "$sum  $TOOLS_DIR/$file" | sha256sum --check --status || { echo "checksum mismatch for $file" >&2; rm -f "$TOOLS_DIR/$file"; exit 1; }
}

fetch "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl.tar.gz" "$WASM_BINDGEN_SHA256" wasm-bindgen.tar.gz
fetch "https://github.com/WebAssembly/binaryen/releases/download/version_${BINARYEN_VERSION}/binaryen-version_${BINARYEN_VERSION}-x86_64-linux.tar.gz" "$BINARYEN_SHA256" binaryen.tar.gz
fetch "https://registry.npmjs.org/@esbuild/linux-x64/-/linux-x64-${ESBUILD_VERSION}.tgz" "$ESBUILD_SHA256" esbuild.tgz

for d in wasm-bindgen binaryen esbuild; do rm -rf "${TOOLS_DIR:?}/$d"; mkdir -p "$TOOLS_DIR/$d"; done
tar -xzf "$TOOLS_DIR/wasm-bindgen.tar.gz" -C "$TOOLS_DIR/wasm-bindgen" --strip-components=1
tar -xzf "$TOOLS_DIR/binaryen.tar.gz" -C "$TOOLS_DIR/binaryen" --strip-components=1
tar -xzf "$TOOLS_DIR/esbuild.tgz" -C "$TOOLS_DIR/esbuild" --strip-components=1

out=(
  "WASM_BINDGEN_BIN=$TOOLS_DIR/wasm-bindgen/wasm-bindgen"
  "WASM_OPT_BIN=$TOOLS_DIR/binaryen/bin/wasm-opt"
  "ESBUILD_BIN=$TOOLS_DIR/esbuild/bin/esbuild"
)
for kv in "${out[@]}"; do
  [ -x "${kv#*=}" ] || { echo "missing tool ${kv#*=}" >&2; exit 1; }
  if [ -n "${GITHUB_ENV:-}" ]; then echo "$kv" >> "$GITHUB_ENV"; else echo "export $kv"; fi
done
