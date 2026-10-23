// Bundle the protocol client (it ships TypeScript source, which Node does not strip inside
// node_modules) into tests/.gen/client.mjs so the suites can build real access proofs with it.
import { build } from 'esbuild'
import path from 'node:path'

await build({
  entryPoints: [path.resolve(import.meta.dirname, '../node_modules/@meddleware/access-gate-gateway-client/src/index.ts')],
  bundle: true,
  format: 'esm',
  platform: 'node',
  outfile: path.resolve(import.meta.dirname, '.gen/client.mjs'),
  logLevel: 'warning',
})
