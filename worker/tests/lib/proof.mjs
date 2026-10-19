// Build real access proofs the way a client does: a fresh Ed25519 key signs the audience-bound message.
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519'
import { buildAccessProof } from '../.gen/client.mjs'
import { GATE_ID } from './worker.mjs'

export function newWallet() {
  const kp = Ed25519Keypair.generate()
  return { kp, address: kp.toSuiAddress() }
}

/** GET /v1/challenge → { nonce, expiresAt }. */
export async function challenge(base, headers = {}) {
  const r = await fetch(`${base}/v1/challenge`, { headers })
  if (r.status !== 200) throw new Error(`challenge ${r.status}: ${await r.text()}`)
  return await r.json()
}

/**
 * A bearer token for `wallet`, for the gateway at `origin` (the string signed into the proof, i.e. the
 * Worker's GATEWAY_ORIGIN) fetched from `base`. `consumeDigest` exactly when the gateway runs single-use.
 */
export async function proofToken({ base, origin = 'https://gw.example.com', wallet, consumeDigest, gateId = GATE_ID, network = 'testnet', headers = {} }) {
  const ch = await challenge(base, headers)
  return await buildAccessProof({
    address: wallet.address,
    challenge: ch,
    sign: async (m) => ({ signature: (await wallet.kp.signPersonalMessage(m)).signature }),
    gateway: origin,
    gateId,
    network,
    consumeDigest,
  })
}

/** Register a fresh consume made by `wallet` with the stub fullnode; returns its digest. */
export async function registerConsume(rpc, wallet) {
  const { txDigest } = await import('./stubs.mjs')
  const digest = txDigest()
  rpc.state.consumes.set(digest, wallet.address)
  return digest
}
