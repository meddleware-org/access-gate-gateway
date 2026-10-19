// Atomicity under concurrency (real clock): 100 simultaneous takes of one nonce -> exactly one true;
// 100 simultaneous leases of one consume -> exactly one ok; commit by the winner then 100 more leases -> all redeemed.
//   node scripts/concurrency.mjs http://127.0.0.1:8799
import assert from 'node:assert/strict'
const base = process.argv[2] ?? 'http://127.0.0.1:8799'
const shard = 'conc' + Math.random().toString(36).slice(2, 8)
const j = async (p) => (await fetch(`${base}/do/${shard}/${p}`)).json()
await j('issue?nonce=N1&ttl=300&max=1000')
const takes = await Promise.all(Array.from({ length: 100 }, () => j('take?nonce=N1')))
assert.equal(takes.filter((t) => t.ok).length, 1, 'exactly one take wins')
const leases = await Promise.all(Array.from({ length: 100 }, () => j('lease?key=D1&ttl=900&max=1000')))
const winners = leases.filter((l) => l.status === 'ok')
assert.equal(winners.length, 1, 'exactly one lease wins')
assert.equal(leases.filter((l) => l.status === 'leased').length, 99)
assert.equal((await j(`commit?key=D1&token=${winners[0].token}&retention=60`)).result, 'ok')
const after = await Promise.all(Array.from({ length: 100 }, () => j('lease?key=D1&ttl=900&max=1000')))
assert.ok(after.every((l) => l.status === 'redeemed'))
console.log('concurrency OK: 1/100 takes, 1/100 leases, then 100/100 redeemed')
