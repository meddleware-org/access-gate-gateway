import { describe, it, expect } from 'vitest'
import vectors from '../../conformance/vectors.json'
import published from '@meddleware/nft-gate-client/vectors.json'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { p256 } from '@noble/curves/nist.js'
import { verifyPersonalMessageSignature, normalizeAddress, signingDigest, verifyAccessRequest, type ChainQuery } from '../src/verify.js'
import { personalMessage, decodeAccessProof, isTransactionDigest } from '../src/wire.js'
import { base64ToBytes } from '../src/crypto.js'
import { deniedResponse, loopDetected, methodNotAllowed, missingProof, rateLimited, stateUnavailable } from '../src/responses.js'
import { redeemAndForward } from '../src/redemption.js'
import type { Config } from '../src/config.js'
import type { CommitResult, LeaseResult, NonceBackend, RedemptionStore } from '../src/state/types.js'

// The SAME fixtures the Rust gateway verifies (gateway-rust `conformance_shared_vectors`), generated
// and published by @meddleware/nft-gate-client. Drift on either side fails a test.
type Ctx = Parameters<typeof personalMessage>[0]
const msg = (c: unknown) => personalMessage(c as Ctx)

describe('conformance vectors (shared with the Rust gateway)', () => {
  it('the repository copy is the published package file', () => {
    expect(published).toEqual(vectors)
  })

  for (const c of vectors.personalMessage.cases) {
    it(`personal message: ${c.name}`, () => {
      const bytes = msg(c.context)
      expect(new TextDecoder().decode(bytes)).toBe(c.messageUtf8)
      expect(Array.from(bytes)).toEqual(Array.from(base64ToBytes(c.messageBytesBase64)))
    })
  }

  for (const c of vectors.personalMessageRejects) {
    it(`refuses to build a message: ${c.name}`, () => {
      expect(() => msg(c.context)).toThrow()
    })
  }

  it('proof token decode matches', () => {
    expect(decodeAccessProof(vectors.proofDecode.token)).toEqual(vectors.proofDecode.expect)
  })

  for (const c of vectors.proofDecodeRejects.cases) {
    it(`rejects a proof token: ${c.name}`, () => {
      expect(() => decodeAccessProof(c.token)).toThrow()
    })
  }

  for (const c of vectors.addressNormalization.cases) {
    it(`normalizes address ${c.input} to canonical form`, () => {
      expect(normalizeAddress(c.input)).toBe(c.expected)
    })
  }

  for (const sig of vectors.signatures) {
    it(`verifies the ${sig.scheme} golden signature and recovers the address`, () => {
      const m = msg(sig.context)
      expect(verifyPersonalMessageSignature(sig.address, m, sig.signature)).toBe(true)
      expect(verifyPersonalMessageSignature('0xdead', m, sig.signature)).toBe(false) // wrong address
      expect(verifyPersonalMessageSignature(sig.address, msg({ ...sig.context, nonce: 'GOLDEN-NONCE-124' }), sig.signature)).toBe(false)
      expect(decodeAccessProof(sig.proofToken).address).toBe(sig.address)
    })
  }

  for (const v of vectors.audienceMismatch) {
    it(`refuses a valid signature presented for a different audience: ${v.case}`, () => {
      expect(verifyPersonalMessageSignature(v.address, msg(v.context), v.signature)).toBe(false)
    })
  }

  for (const neg of vectors.negativeSignatures) {
    it(`rejects: ${neg.case}`, () => {
      expect(verifyPersonalMessageSignature(neg.address, msg(neg.context), neg.signature)).toBe(false)
    })
  }

  it('the high-S vectors fail only because of the low-S rule (otherwise valid ECDSA)', () => {
    const digest = signingDigest(msg(vectors.signatures[0]!.context))
    for (const [name, curve] of [
      ['secp256k1 high-S', secp256k1],
      ['secp256r1 high-S', p256],
    ] as const) {
      const raw = base64ToBytes(vectors.negativeSignatures.find((n) => n.case === name)!.signature)
      expect(curve.verify(raw.subarray(1, 65), digest, raw.subarray(65), { lowS: false })).toBe(true)
    }
  })

  it('accepts the ZIP-215 small-order vector (the rule Sui validators apply)', () => {
    const z = vectors.zip215
    expect(verifyPersonalMessageSignature(z.address, msg(z.context), z.signature)).toBe(true)
    // …for any message, which is exactly why it pins the verification rule.
    expect(verifyPersonalMessageSignature(z.address, msg({ ...z.context, nonce: 'other' }), z.signature)).toBe(true)
  })

  for (const c of vectors.txDigest.valid) {
    it(`accepts the transaction digest: ${c.name}`, () => {
      expect(isTransactionDigest(c.digest)).toBe(true)
    })
  }

  for (const c of vectors.txDigest.invalid) {
    it(`refuses the transaction digest: ${c.name}`, () => {
      expect(isTransactionDigest(c.digest)).toBe(false)
    })
  }
})

// ── the shared `responses` vectors: the answer for every outcome ─────────────────────────────────
// Each outcome is driven to the Response the gateway really produces (the real verifier for a denial,
// the real redemption flow for a conflict) and compared with the shared status and body. An outcome in
// the vectors without a driver fails, and so does a driver without a vector.
const golden = vectors.signatures[0]!
const goldenSingle = vectors.signatures.find((s) => s.context.consumeDigest)!
const cfg = (singleUse: boolean, over: Partial<Config> = {}): Config =>
  ({
    gatewayOrigin: golden.context.origin,
    network: golden.context.network,
    gateId: golden.context.gateId,
    nftType: '0x1::access_gate::AccessNFT',
    singleUse,
    consumeMaxAgeSecs: 432000,
    redemptionLeaseTtlSecs: 900,
    redemptionRetentionSecs: 3600,
    ...over,
  }) as Config

const nonces = (valid: boolean, fail = false): NonceBackend => ({
  issue: async () => ({ nonce: 'n', expiresAt: 1 }),
  takeIfValid: async () => {
    if (fail) throw new Error('store down')
    return valid
  },
  rateCheck: async () => true,
})
const chain = (o: { owns?: boolean | Error; consumed?: boolean; blocked?: boolean } = {}): ChainQuery => ({
  ownsNft: async () => {
    if (o.owns instanceof Error) throw o.owns
    return o.owns ?? true
  },
  consumeTxValid: async () => o.consumed ?? true,
  gateAccessBlocked: async () => o.blocked ?? false,
})

class Store implements RedemptionStore {
  constructor(
    private lease: LeaseResult,
    private commit: CommitResult | Error,
  ) {}
  async tryLeaseRedemption(): Promise<LeaseResult> {
    return this.lease
  }
  async commitRedemption(): Promise<CommitResult> {
    if (this.commit instanceof Error) throw this.commit
    return this.commit
  }
  async releaseRedemption(): Promise<void> {}
}

async function denial(c: Config, token: string, nonce: NonceBackend, q: ChainQuery): Promise<Response> {
  const result = await verifyAccessRequest(c, nonce, token, q)
  if (result.ok) throw new Error('expected a denial')
  return deniedResponse(result.denied)
}

const redeem = (store: RedemptionStore) =>
  redeemAndForward(cfg(true), store, 'key', async () => new Response('stored', { status: 200 }))

const drivers: Record<string, () => Promise<Response> | Response> = {
  'missing-proof': () => missingProof(),
  'bad-proof': () => denial(cfg(false), '!!!not-base64!!!', nonces(true), chain()),
  'bad-signature': () => denial(cfg(false, { gatewayOrigin: 'https://other.example' }), golden.proofToken, nonces(true), chain()),
  'nonce-invalid': () => denial(cfg(false), golden.proofToken, nonces(false), chain()),
  'not-owner': () => denial(cfg(false), golden.proofToken, nonces(true), chain({ owns: false })),
  'consume-missing': () => denial(cfg(true), goldenSingle.proofToken, nonces(true), chain({ consumed: false })),
  'gate-paused': () => denial(cfg(false), golden.proofToken, nonces(true), chain({ blocked: true })),
  'chain-error': () => denial(cfg(false), golden.proofToken, nonces(true), chain({ owns: new Error('rpc down') })),
  // The TypeScript gateway reports a failing store as a thrown StoreError, which the router answers 503.
  'state-unavailable': () => stateUnavailable(),
  'rate-limited': () => rateLimited(),
  'method-not-allowed': () => methodNotAllowed(),
  'loop-detected': () => loopDetected(),
  'consume-redeemed': () => redeem(new Store({ status: 'redeemed' }, 'ok')),
  'consume-leased': () => redeem(new Store({ status: 'leased' }, 'ok')),
  'commit-failed': () => redeem(new Store({ status: 'ok', token: 't' }, new Error('store down'))),
  'lease-lost': () => redeem(new Store({ status: 'ok', token: 't' }, 'lost')),
}

describe('response vectors: the gateway answers what the shared contract says', () => {
  it('has a driver for exactly the outcomes in the vectors', () => {
    expect(Object.keys(drivers).sort()).toEqual(vectors.responses.cases.map((c) => c.outcome).sort())
  })

  for (const c of vectors.responses.cases) {
    it(`${c.outcome}: ${c.status} ${c.error}`, async () => {
      const driver = drivers[c.outcome]
      if (!driver) throw new Error(`no driver for outcome ${c.outcome}`)
      const res = await driver()
      expect(res.status).toBe(c.status)
      expect(res.headers.get('content-type')).toBe('application/json')
      expect(await res.json()).toEqual('code' in c ? { error: c.error, code: c.code } : { error: c.error })
    })
  }
})
