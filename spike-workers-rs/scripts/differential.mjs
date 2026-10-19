// Runs scripts/scenario.json against the real SQLite-backed Durable Object served by `wrangler dev`
// (TEST_CLOCK=1 lets the scenario pin the DO's clock). Each section uses a fresh DO shard.
//   node scripts/differential.mjs http://127.0.0.1:8799
import fs from 'node:fs'
import path from 'node:path'
import assert from 'node:assert/strict'

const base = process.argv[2] ?? 'http://127.0.0.1:8799'
const scenario = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, 'scenario.json'), 'utf8'))
const run = Math.random().toString(36).slice(2, 8)
let steps = 0
for (const [si, section] of scenario.sections.entries()) {
  const shard = `t${run}x${si}`
  const vars = {}
  for (const [i, step] of section.steps.entries()) {
    const q = new URLSearchParams()
    for (const [k, v] of Object.entries(step)) {
      if (['op', 'expect', 'bind'].includes(k)) continue
      q.set(k, typeof v === 'string' && v.startsWith('$') ? vars[v.slice(1)] : String(v))
    }
    const r = await fetch(`${base}/do/${shard}/${step.op}?${q}`)
    const body = await r.json()
    if (step.bind) vars[step.bind] = body.token
    if (step.expect) {
      const got = Object.fromEntries(Object.keys(step.expect).map((k) => [k, body[k]]))
      assert.deepEqual(got, step.expect, `${section.name} / step ${i}: ${JSON.stringify(body)}`)
    }
    steps++
  }
}
console.log(`differential OK: ${steps} steps in ${scenario.sections.length} sections against the SQLite Durable Object`)
