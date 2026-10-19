//! Sui personal-message signature verification and address helpers (pure; native + wasm32).
//! Verbatim move of the primitives in `gateway-rust/src/verify.rs` (lines 12-202) — the only edit is
//! that the "multisig/zkLogin not supported" warning is returned as a `false` without logging
//! (core has no logging dependency; callers may log the flag via [`unsupported_flag`]).

use base64::prelude::*;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

type Blake2b256 = Blake2b<U32>;

// Sui signature-scheme flag bytes (first byte of a serialized signature).
pub const FLAG_ED25519: u8 = 0x00;
pub const FLAG_SECP256K1: u8 = 0x01;
pub const FLAG_SECP256R1: u8 = 0x02;
pub const FLAG_MULTISIG: u8 = 0x03;
pub const FLAG_ZKLOGIN: u8 = 0x05;

/// Compute the 32-byte Blake2b-256 digest of `data`.
fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(data);
    h.finalize().into()
}

/// Append `v` to `out` in unsigned LEB-128 encoding. Used to BCS-encode the message-length
/// prefix in the Sui personal-message signing digest.
fn write_uleb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// blake2b256( intent(PersonalMessage,V0,Sui) || bcs(Vec<u8> message) ). This is exactly
/// what a Sui wallet signs for a personal message.
pub fn signing_digest(message: &[u8]) -> [u8; 32] {
    let mut data = vec![3u8, 0, 0]; // IntentScope::PersonalMessage, V0, AppId::Sui
    write_uleb128(&mut data, message.len() as u64);
    data.extend_from_slice(message);
    blake2b256(&data)
}

/// Sui address for a scheme: blake2b256(flag || pubkey), hex, 0x-prefixed. `pubkey` is the
/// 32-byte ed25519 key or the 33-byte SEC1-compressed secp256k1/r1 key.
pub fn derive_address(flag: u8, pk: &[u8]) -> String {
    let mut d = Vec::with_capacity(1 + pk.len());
    d.push(flag);
    d.extend_from_slice(pk);
    format!("0x{}", hex::encode(blake2b256(&d)))
}

/// Normalise a Sui address to lowercase, 0x-prefixed, zero-padded to 64 hex digits.
pub fn normalize_address(a: &str) -> String {
    let s = a.trim().trim_start_matches("0x").to_lowercase();
    format!("0x{s:0>64}")
}

/// Normalise the package address of a `<pkg>::<module>::<name>` type string so the short and
/// long (gRPC) address forms compare equal.
pub fn normalize_move_type(t: &str) -> String {
    match t.split_once("::") {
        Some((pkg, rest)) if !pkg.is_empty() => format!("{}::{rest}", normalize_address(pkg)),
        _ => t.to_string(),
    }
}

/// The exact `AccessConsumedEvent` type of the access_gate package that `nft_type` names. Matching
/// the full type (not a `::access_gate::AccessConsumedEvent` suffix) stops a look-alike package
/// from emitting a forged consume event. Event and NFT types both carry the package's original id.
pub fn consumed_event_type(nft_type: &str) -> String {
    let pkg = nft_type.split("::").next().unwrap_or_default();
    format!(
        "{}::access_gate::AccessConsumedEvent",
        normalize_address(pkg)
    )
}

/// Verify a Sui personal-message signature recovers `address` over `message`, dispatching on
/// the scheme flag byte. Serialized layout: `flag(1) || signature || pubkey` (base64).
///
/// Supported: **ed25519** (0x00), **secp256k1** (0x01), **secp256r1** (0x02) — the schemes used
/// by every current Sui browser/hardware wallet keypair. **multisig** (0x03) and **zkLogin**
/// (0x05) are recognised but not yet verified here (they require the official Sui verifier —
/// see the gateway audit F1 integration plan) and fail **closed**.
pub fn verify_personal_message_signature(
    address: &str,
    message: &[u8],
    signature_b64: &str,
) -> bool {
    let raw = match BASE64_STANDARD.decode(signature_b64.trim()) {
        Ok(r) => r,
        Err(_) => return false,
    };
    match raw.first().copied() {
        Some(FLAG_ED25519) => verify_ed25519(address, message, &raw[1..]),
        Some(FLAG_SECP256K1) => verify_secp256k1(address, message, &raw[1..]),
        Some(FLAG_SECP256R1) => verify_secp256r1(address, message, &raw[1..]),
        Some(FLAG_MULTISIG) | Some(FLAG_ZKLOGIN) => false,
        _ => false,
    }
}

/// ed25519 (flag 0x00): body = `sig(64) || pubkey(32)`. Verified under **ZIP-215** — the rule
/// Sui validators apply (and the Workers gateway's `zip215: true`) — so the gateway accepts
/// exactly the signatures the chain accepts; pinned by the conformance `zip215` vector.
fn verify_ed25519(address: &str, message: &[u8], body: &[u8]) -> bool {
    use ed25519_consensus::{Signature, VerificationKey};
    if body.len() != 96 {
        return false;
    }
    let sig_bytes: [u8; 64] = match body[0..64].try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk_bytes: [u8; 32] = match body[64..96].try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let vk = match VerificationKey::try_from(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let digest = signing_digest(message);
    if vk.verify(&Signature::from(sig_bytes), &digest).is_err() {
        return false;
    }
    normalize_address(address) == derive_address(FLAG_ED25519, &pk_bytes)
}

/// secp256k1 (flag 0x01): body = `sig(64, compact r||s) || pubkey(33, SEC1-compressed)`.
/// Sui signs `SHA256(blake2b256(intent||msg))` with ECDSA-secp256k1. `k256`'s `Verifier::verify`
/// applies the SHA256 step internally, so we pass the blake2b digest and let k256 do the rest.
fn verify_secp256k1(address: &str, message: &[u8], body: &[u8]) -> bool {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    if body.len() != 97 {
        return false;
    }
    let sig = match Signature::from_slice(&body[0..64]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Sui requires low-S; reject the high-S twin explicitly (k256 also does, but do not rely on
    // a library default for a consensus rule).
    if sig.normalize_s().is_some() {
        return false;
    }
    let pk_bytes = &body[64..97];
    let vk = match VerifyingKey::from_sec1_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let digest = signing_digest(message);
    if vk.verify(&digest, &sig).is_err() {
        return false;
    }
    normalize_address(address) == derive_address(FLAG_SECP256K1, pk_bytes)
}

/// secp256r1 (flag 0x02): as secp256k1 but over the NIST P-256 curve. Same SHA256-over-blake2b
/// signing hash; `p256`'s `Verifier::verify` applies SHA256 internally.
fn verify_secp256r1(address: &str, message: &[u8], body: &[u8]) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    if body.len() != 97 {
        return false;
    }
    let sig = match Signature::from_slice(&body[0..64]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // Sui requires low-S for secp256r1 too; `p256` does NOT enforce it on verify, so without this
    // check the gateway would accept the malleable high-S twin the chain and Workers reject.
    if sig.normalize_s().is_some() {
        return false;
    }
    let pk_bytes = &body[64..97];
    let vk = match VerifyingKey::from_sec1_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let digest = signing_digest(message);
    if vk.verify(&digest, &sig).is_err() {
        return false;
    }
    normalize_address(address) == derive_address(FLAG_SECP256R1, pk_bytes)
}

/// True for the scheme flags that are recognised but fail closed (multisig 0x03, zkLogin 0x05), so a
/// caller can log "unsupported scheme" without core depending on a logger.
pub fn unsupported_flag(signature_b64: &str) -> bool {
    matches!(
        BASE64_STANDARD
            .decode(signature_b64.trim())
            .ok()
            .and_then(|r| r.first().copied()),
        Some(FLAG_MULTISIG) | Some(FLAG_ZKLOGIN)
    )
}
