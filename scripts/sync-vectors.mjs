#!/usr/bin/env node
// The conformance vectors are generated and published by @meddleware/nft-gate-client (the protocol's
// home). This repository keeps a copy at conformance/vectors.json so the Rust gateway, which cannot
// import an npm package, tests against the same bytes.
//
//   node scripts/sync-vectors.mjs          copy the installed package's vectors here
//   node scripts/sync-vectors.mjs --check  fail if the copy differs (run in CI)
//
// Before a new client version is published, produce the copy from a local checkout of the client:
//
//   NFT_GATE_CLIENT_VECTORS=../nft-gate-client/vectors.json node scripts/sync-vectors.mjs
//
// The override exists for that one step only. It is refused when CI is set, so the CI check always
// compares against the PUBLISHED package that gateway-workers installs.
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const override = process.env.NFT_GATE_CLIENT_VECTORS
if (override && process.env.CI) {
  console.error('NFT_GATE_CLIENT_VECTORS is a local override and is refused when CI is set: CI compares against the published package')
  process.exit(1)
}
const source = override
  ? resolve(override)
  : join(root, 'gateway-workers', 'node_modules', '@meddleware', 'nft-gate-client', 'vectors.json')
if (override) console.warn(`using the local vectors file ${source} instead of the installed package`)
const copy = join(root, 'conformance', 'vectors.json')
const want = readFileSync(source, 'utf8')
if (process.argv.includes('--check')) {
  if (readFileSync(copy, 'utf8') !== want) {
    console.error('conformance/vectors.json differs from @meddleware/nft-gate-client/vectors.json; run: node scripts/sync-vectors.mjs')
    process.exit(1)
  }
  console.log(`conformance/vectors.json matches ${override ? 'the local override' : 'the installed @meddleware/nft-gate-client'}`)
} else {
  writeFileSync(copy, want)
  console.log('conformance/vectors.json updated')
}
