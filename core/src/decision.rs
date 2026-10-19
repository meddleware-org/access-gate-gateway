//! The allow/deny decision, generic over the two things a platform supplies: the chain
//! ([`ChainQuery`]) and the single-use nonce store ([`NonceTake`], which every
//! [`StateStore`] is). The decision needs only the six fields of [`VerifyParams`].

use crate::config::GatewayConfig;
use crate::proof::{decode_access_proof, is_tx_digest, personal_message, MessageContext};
use crate::sig::{consumed_event_type, normalize_address, verify_personal_message_signature};
use crate::state::StateStore;

/// The configuration the decision reads (a subset of [`GatewayConfig`]).
#[derive(Debug, Clone)]
pub struct VerifyParams {
    pub single_use: bool,
    pub gateway_origin: String,
    pub gate_id: String,
    pub network: String,
    pub nft_type: String,
    pub consume_max_age_secs: u64,
}

impl From<&GatewayConfig> for VerifyParams {
    fn from(cfg: &GatewayConfig) -> Self {
        Self {
            single_use: cfg.single_use,
            gateway_origin: cfg.gateway_origin.clone(),
            gate_id: cfg.gate_id.clone(),
            network: cfg.network.clone(),
            nft_type: cfg.nft_type.clone(),
            consume_max_age_secs: cfg.consume_max_age_secs,
        }
    }
}

/// Consume a nonce exactly once; `Ok(true)` iff it was valid, unexpired and unused. `Err` = the
/// store failed (→ `Denied::StateUnavailable`, 503).
#[allow(async_fn_in_trait)]
pub trait NonceTake {
    async fn take_if_valid(&self, nonce: &str) -> anyhow::Result<bool>;
}

impl<T: StateStore + ?Sized> NonceTake for T {
    async fn take_if_valid(&self, nonce: &str) -> anyhow::Result<bool> {
        self.take_nonce(nonce).await
    }
}

/// Abstraction over on-chain lookups needed to authorise a request. Implemented by
/// [`crate::chain::SuiRpc`] in production and by a mock in tests. Kept as a generic trait
/// (not `dyn`) so async methods are allowed without `Box<dyn Future>` wrappers.
#[allow(async_fn_in_trait)]
pub trait ChainQuery {
    /// Does `address` own ≥1 NFT of `nft_type` (optionally for `gate_id`)?
    async fn owns_nft(
        &self,
        address: &str,
        nft_type: &str,
        gate_id: Option<&str>,
    ) -> anyhow::Result<bool>;

    /// Does `consume_digest` name a successful transaction that emitted an event of exactly
    /// `consumed_event_type` (the configured package's `AccessConsumedEvent`) for `address` (the
    /// sender) on `gate_id`, no older than `max_age_secs`? Digest-first and NOT bound to the
    /// challenge nonce — single-use is enforced by the redemption store keying on the digest, so an
    /// interrupted upload can resume with a fresh challenge while reusing the same consume. A digest
    /// the node does not know is `Ok(false)` (denied); an RPC failure is `Err` (`ChainError`).
    async fn consume_tx_valid(
        &self,
        consume_digest: &str,
        address: &str,
        consumed_event_type: &str,
        gate_id: Option<&str>,
        max_age_secs: u64,
    ) -> anyhow::Result<bool>;

    /// Is `gate_id` paused AND does its immutable `GatePolicy` have `pause_blocks_access`? Holders
    /// are then denied until the gate is unpaused. `Err` (→ `ChainError`, denied) if the gate's JSON
    /// is not the shape this version understands: a rendering change must never silently disable
    /// an admin's pause.
    async fn gate_access_blocked(&self, gate_id: &str) -> anyhow::Result<bool>;
}

/// Reason a request was rejected by [`verify_access_request`].
#[derive(Debug, PartialEq, Eq)]
pub enum Denied {
    /// The proof token could not be decoded (not valid base64 JSON or missing required fields).
    BadProof,
    /// The signature does not recover the claimed address.
    BadSignature,
    /// The challenge nonce was not found, is expired, or has already been used.
    NonceInvalid,
    /// The address does not hold the required access NFT (ownership mode).
    NotOwner,
    /// No matching on-chain single-use consume event was found (single-use mode).
    ConsumeMissing,
    /// The gate is paused and its policy has `pause_blocks_access`.
    GatePaused,
    /// An on-chain query failed; the gateway returns 502 for this variant.
    ChainError,
    /// The gateway's own state store failed; the gateway returns 503 (never a conflict).
    StateUnavailable,
}

impl Denied {
    /// A short, client-visible description of why access was denied.
    pub fn reason(&self) -> &'static str {
        match self {
            Denied::BadProof => "malformed access proof",
            Denied::BadSignature => "signature does not recover address",
            Denied::NonceInvalid => "challenge nonce invalid, expired, or already used",
            Denied::NotOwner => "address does not hold the required access NFT",
            Denied::ConsumeMissing => "no matching single-use consume for this address",
            Denied::GatePaused => "the gate is paused",
            Denied::ChainError => "on-chain verification failed",
            Denied::StateUnavailable => "gateway state unavailable",
        }
    }
}

/// A successful verification: the recovered address, plus (single-use mode) the `consume_digest`
/// the dispatcher leases/commits so a use is only spent on a successful upload.
#[derive(Debug)]
pub struct Verified {
    pub address: String,
    pub redemption_key: Option<String>,
}

/// Authorise a request from its base64 proof token. Returns the verified address on success.
/// The nonce is consumed (single-use at the gateway) as part of a successful signature check,
/// so a replay presents an already-used nonce and is rejected.
pub async fn verify_access_request<S: NonceTake, C: ChainQuery>(
    cfg: &VerifyParams,
    store: &S,
    token: &str,
    chain: &C,
) -> Result<Verified, Denied> {
    let proof = decode_access_proof(token).map_err(|_| Denied::BadProof)?;

    // Single-use gateways need the consume digest before anything else (it is part of the signed
    // message); ownership gateways build the message without one, so a signature made for the other
    // mode, another gateway, gate or network simply fails to verify.
    if cfg.single_use && proof.consume_digest.is_none() {
        return Err(Denied::ConsumeMissing);
    }
    let message = personal_message(&MessageContext {
        origin: &cfg.gateway_origin,
        gate_id: &normalize_address(&cfg.gate_id),
        network: &cfg.network,
        nonce: &proof.nonce,
        consume_digest: if cfg.single_use {
            proof.consume_digest.as_deref()
        } else {
            None
        },
    })
    .map_err(|_| Denied::BadProof)?;
    if !verify_personal_message_signature(&proof.address, &message, &proof.signature) {
        return Err(Denied::BadSignature);
    }

    // Canonicalise the address once the signature is proven, then use ONLY the normalised form for
    // on-chain comparisons and the returned value. The client emits the raw caller address; on-chain
    // owners are canonical (lower-case, 0x-prefixed, 64-hex), so comparing the raw string would
    // fail-closed for a non-canonical input (e.g. missing leading zeros). Owning canonicalisation
    // here — the security boundary — keeps the client wire format unchanged. (See conformance
    // vectors `addressNormalization`; matched by the Workers gateway.)
    let address = normalize_address(&proof.address);

    // Consume the nonce exactly once (fresh, unexpired, unused).
    if !store
        .take_if_valid(&proof.nonce)
        .await
        .map_err(|_| Denied::StateUnavailable)?
    {
        return Err(Denied::NonceInvalid);
    }

    // A gate whose policy has `pause_blocks_access` admits no one while paused. Checked before the
    // single-use lease, so a consume made just before a pause stays redeemable after unpausing.
    let blocked = chain
        .gate_access_blocked(&cfg.gate_id)
        .await
        .map_err(|_| Denied::ChainError)?;
    if blocked {
        return Err(Denied::GatePaused);
    }

    if cfg.single_use {
        // A single-use client MUST first submit an on-chain consume and include its digest;
        // its absence signals a misconfigured/replaying client.
        let Some(digest) = proof.consume_digest.as_deref().filter(|d| is_tx_digest(d)) else {
            return Err(Denied::ConsumeMissing);
        };
        let ok = chain
            .consume_tx_valid(
                digest,
                &address,
                &consumed_event_type(&cfg.nft_type),
                Some(cfg.gate_id.as_str()),
                cfg.consume_max_age_secs,
            )
            .await
            .map_err(|_| Denied::ChainError)?;
        if !ok {
            return Err(Denied::ConsumeMissing);
        }
        // The consume is valid on-chain; the dispatcher leases/commits this digest so the use is
        // spent only on a successful upload (and a duplicate can't double-spend it).
        return Ok(Verified {
            address,
            redemption_key: Some(digest.to_string()),
        });
    }

    let ok = chain
        .owns_nft(&address, &cfg.nft_type, Some(cfg.gate_id.as_str()))
        .await
        .map_err(|_| Denied::ChainError)?;
    if !ok {
        return Err(Denied::NotOwner);
    }
    Ok(Verified {
        address,
        redemption_key: None,
    })
}
