//! Access-proof wire format (protocol `access-gate-gateway:access:v3`). MUST stay in sync with
//! `@meddleware/access-gate-gateway-client`'s `proof.ts`; the shared conformance vectors
//! (`conformance/vectors.json`, published by that package) pin both.
//!
//! # Signed message
//!
//! ASCII, one `key:value` line each, no trailing newline. The gateway builds it from its OWN
//! configuration (origin, gate, network) plus the proof's nonce (and digest in single-use mode),
//! never from the token, so a signature made for another gateway, gate, network or consume is useless:
//!
//! ```text
//! access-gate-gateway:access:v3
//! origin:<canonical origin>
//! gate:<0x + 64 lower-case hex>
//! network:<localnet|devnet|testnet|mainnet>
//! nonce:<nonce>
//! consume:<base58 digest>        (single-use gateways only)
//! ```
//!
//! # Proof token
//!
//! `base64(UTF-8 JSON)` of `{ "address", "nonce", "signature", "consumeDigest"? }` (camelCase
//! `consumeDigest`, normalised to `consume_digest` here). Every field is validated by the same
//! grammar the client applies when it encodes: address `0x` + 1-64 hex digits, nonce
//! `[A-Za-z0-9._~-]{1,128}`, signature base64 (at most 1024 characters), consume digest base58 that decodes to 32 bytes.

use base64::prelude::*;

/// First line of every signed access message.
pub const ACCESS_MESSAGE_VERSION: &str = "access-gate-gateway:access:v3";

/// The Sui networks a gateway can serve; part of the signed message.
pub const NETWORKS: [&str; 4] = ["localnet", "devnet", "testnet", "mainnet"];

/// Decoded access-proof submitted by the client in the `Authorization: Bearer` (or
/// `X-Access-Proof`) header.
#[derive(Debug, Clone)]
pub struct AccessProof {
    /// The Sui address (0x-prefixed hex) that signed the challenge.
    pub address: String,
    /// The random nonce from `GET /v1/challenge`.
    pub nonce: String,
    /// Base64-encoded Sui personal-message signature (flag || sig || pubkey).
    pub signature: String,
    /// Single-use only: the digest of the on-chain consume (part of the signed message).
    pub consume_digest: Option<String>,
}

/// Everything the signed message binds.
pub struct MessageContext<'a> {
    /// Canonical origin of this gateway (`scheme://host[:port]`).
    pub origin: &'a str,
    /// The guarded `Gate` id, `0x` + 64 lower-case hex digits.
    pub gate_id: &'a str,
    /// One of [`NETWORKS`].
    pub network: &'a str,
    /// The challenge nonce being answered.
    pub nonce: &'a str,
    /// Single-use gateways only.
    pub consume_digest: Option<&'a str>,
}

/// `[A-Za-z0-9._~-]{1,128}`: a nonce a gateway may issue (no whitespace, so it cannot add a line).
pub fn is_nonce(s: &str) -> bool {
    (1..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
}

/// The Bitcoin base58 alphabet (no `0 O I l`).
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A Sui transaction digest is a 32-byte hash.
const TX_DIGEST_BYTES: usize = 32;

/// The number of bytes the base58 string `s` decodes to (every leading `1` is one zero byte), or `None`
/// if it holds a character outside the alphabet. No dependency; callers bound `s` to 44 characters first,
/// so the quadratic loop is tiny.
fn base58_decoded_len(s: &str) -> Option<usize> {
    let zeros = s.bytes().take_while(|&b| b == b'1').count();
    let mut magnitude: Vec<u8> = Vec::new(); // little-endian, no high zero byte
    for b in s.bytes().skip(zeros) {
        let mut carry = u32::try_from(BASE58.iter().position(|&a| a == b)?).ok()?;
        for byte in &mut magnitude {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            magnitude.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    Some(zeros + magnitude.len())
}

/// A Sui transaction digest: base58 (Bitcoin alphabet, no `0 O I l`) that decodes to exactly 32 bytes.
/// 32 bytes encode to 32-44 characters (each leading zero byte is a `1`), but the length alone is not
/// enough: 43 characters can be 31 bytes and 44 can be 33. Mirror of `isTransactionDigest` in
/// `@meddleware/access-gate-gateway-client`; the shared `txDigest` vectors pin both.
pub fn is_tx_digest(s: &str) -> bool {
    (32..=44).contains(&s.len()) && base58_decoded_len(s) == Some(TX_DIGEST_BYTES)
}

/// `0x` followed by 1-64 hex digits (either case).
fn is_address(s: &str) -> bool {
    s.strip_prefix("0x")
        .is_some_and(|h| (1..=64).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `0x` followed by exactly 64 lower-case hex digits.
pub fn is_canonical_id(s: &str) -> bool {
    s.strip_prefix("0x").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Standard base64 with optional padding, at most 1024 characters.
fn is_signature(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    let pad = s.len() - body.len();
    (1..=1024 + 2).contains(&s.len())
        && pad <= 2
        && !body.is_empty()
        && body.len() <= 1024
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// The exact bytes a wallet signs to answer a challenge for `ctx`.
///
/// # Errors
///
/// Returns an error if a field is not in its canonical form (which also rules out line injection).
pub fn personal_message(ctx: &MessageContext<'_>) -> anyhow::Result<Vec<u8>> {
    if !is_canonical_id(ctx.gate_id) {
        anyhow::bail!("gate id must be 0x followed by 64 lower-case hex digits");
    }
    if !NETWORKS.contains(&ctx.network) {
        anyhow::bail!("unknown network");
    }
    if !is_nonce(ctx.nonce) {
        anyhow::bail!("nonce is not a valid challenge nonce");
    }
    if let Some(d) = ctx.consume_digest {
        if !is_tx_digest(d) {
            anyhow::bail!("consume digest is not a base58 transaction digest");
        }
    }
    if ctx.origin.is_empty() || !ctx.origin.is_ascii() || ctx.origin.bytes().any(|b| b <= b' ') {
        anyhow::bail!("origin is not a canonical gateway origin");
    }
    let mut lines = vec![
        ACCESS_MESSAGE_VERSION.to_string(),
        format!("origin:{}", ctx.origin),
        format!("gate:{}", ctx.gate_id),
        format!("network:{}", ctx.network),
        format!("nonce:{}", ctx.nonce),
    ];
    if let Some(d) = ctx.consume_digest {
        lines.push(format!("consume:{d}"));
    }
    Ok(lines.join("\n").into_bytes())
}

/// Longest accepted token, checked before decoding. Mirror of the client's `MAX_TOKEN_BYTES`.
pub const MAX_TOKEN_BYTES: usize = 4096;

/// Decode the base64(JSON) proof token, applying the client's field grammar.
///
/// # Errors
///
/// Returns an error if `token` is longer than [`MAX_TOKEN_BYTES`], is not valid base64, if the
/// decoded bytes are not a JSON object, or if any field breaks the grammar above.
pub fn decode_access_proof(token: &str) -> anyhow::Result<AccessProof> {
    if token.len() > MAX_TOKEN_BYTES {
        anyhow::bail!(
            "access proof token too large ({} > {MAX_TOKEN_BYTES})",
            token.len()
        );
    }
    let json = BASE64_STANDARD
        .decode(token.trim())
        .map_err(|e| anyhow::anyhow!("proof not base64: {e}"))?;
    let value: serde_json::Value = serde_json::from_slice(&json)?;
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("malformed access proof"))?;
    let text = |key: &str| -> anyhow::Result<String> {
        obj.get(key)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow::anyhow!("malformed access proof"))
    };
    let address = text("address")?;
    let nonce = text("nonce")?;
    let signature = text("signature")?;
    if !(address.is_ascii() && nonce.is_ascii() && signature.is_ascii()) {
        anyhow::bail!("non-ASCII field in access proof");
    }
    if !is_address(&address) {
        anyhow::bail!("address must be 0x followed by 1-64 hex digits");
    }
    if !is_nonce(&nonce) {
        anyhow::bail!("nonce is not a valid challenge nonce");
    }
    if !is_signature(&signature) {
        anyhow::bail!("signature is not base64");
    }
    let consume_digest = match obj.get("consumeDigest") {
        None => None,
        Some(v) => {
            let d = v.as_str().filter(|d| is_tx_digest(d)).ok_or_else(|| {
                anyhow::anyhow!("consumeDigest is not a base58 transaction digest")
            })?;
            Some(d.to_string())
        }
    };
    Ok(AccessProof {
        address,
        nonce,
        signature,
        consume_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "5Wq9tE4gXz8hEvFhYt8KkTJb2Pp6qXqj8cRk3xN1mYdL";

    fn ctx<'a>(nonce: &'a str, digest: Option<&'a str>) -> MessageContext<'a> {
        MessageContext {
            origin: "https://gateway.example",
            gate_id: "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            network: "testnet",
            nonce,
            consume_digest: digest,
        }
    }

    fn token(json: &str) -> String {
        BASE64_STANDARD.encode(json)
    }

    #[test]
    fn personal_message_is_the_documented_multi_line_ascii() {
        let m =
            String::from_utf8(personal_message(&ctx("GOLDEN-NONCE-123", None)).unwrap()).unwrap();
        assert_eq!(
            m,
            format!(
                "access-gate-gateway:access:v3\norigin:https://gateway.example\ngate:0x{}\nnetwork:testnet\nnonce:GOLDEN-NONCE-123",
                "a1".repeat(32)
            )
        );
        let single = personal_message(&ctx("n", Some(DIGEST))).unwrap();
        assert!(String::from_utf8(single)
            .unwrap()
            .ends_with(&format!("\nconsume:{DIGEST}")));
    }

    #[test]
    fn tx_digest_is_base58_that_decodes_to_32_bytes() {
        assert!(is_tx_digest(DIGEST));
        assert!(is_tx_digest(&"1".repeat(32))); // 32 zero bytes
        assert!(is_tx_digest(&"z".repeat(43))); // 58^43 - 1 fits in 32 bytes
        assert!(is_tx_digest(&format!("1{}", "z".repeat(42)))); // a zero byte, then 31 bytes
        assert!(!is_tx_digest(""));
        assert!(!is_tx_digest(&"1".repeat(31)));
        assert!(!is_tx_digest(&"1".repeat(33)));
        assert!(!is_tx_digest(&"z".repeat(44))); // 33 bytes
        assert!(!is_tx_digest(&"z".repeat(45)));
        assert!(!is_tx_digest(&format!("1{}", "z".repeat(43)))); // a leading 1 is a byte: 33
        assert!(!is_tx_digest(&"2".repeat(32))); // 24 bytes
        for bad in ['0', 'O', 'I', 'l', '+', '_', 'é'] {
            let d = format!("{}{bad}{}", &DIGEST[..5], &DIGEST[6..]);
            assert!(!is_tx_digest(&d), "{d}");
        }
    }

    proptest::proptest! {
        // The decoder agrees with an independent big-integer encoding of 32 random bytes.
        #[test]
        fn every_32_byte_value_round_trips(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 32)) {
            proptest::prop_assert!(is_tx_digest(&encode_base58(&bytes)));
        }

        #[test]
        fn other_lengths_are_refused(n in 0usize..=40, fill in proptest::prelude::any::<u8>()) {
            proptest::prop_assume!(n != 32);
            proptest::prop_assert!(!is_tx_digest(&encode_base58(&vec![fill; n])));
        }
    }

    /// Reference encoder for the tests: repeated division of a big-endian byte string by 58.
    fn encode_base58(bytes: &[u8]) -> String {
        let zeros = bytes.iter().take_while(|&&b| b == 0).count();
        let mut digits: Vec<u8> = Vec::new();
        let mut rest: Vec<u8> = bytes.to_vec();
        while rest.iter().any(|&b| b != 0) {
            let mut rem = 0u32;
            for b in &mut rest {
                let cur = rem * 256 + u32::from(*b);
                *b = (cur / 58) as u8;
                rem = cur % 58;
            }
            digits.push(BASE58[rem as usize]);
        }
        let mut out = "1".repeat(zeros);
        out.extend(digits.iter().rev().map(|&d| d as char));
        out
    }

    #[test]
    fn personal_message_refuses_non_canonical_fields() {
        assert!(personal_message(&ctx("n\nconsume:x", None)).is_err());
        assert!(personal_message(&ctx("", None)).is_err());
        assert!(personal_message(&ctx("n", Some("DIGEST-1"))).is_err());
        let mut c = ctx("n", None);
        c.network = "testnet2";
        assert!(personal_message(&c).is_err());
        let mut c = ctx("n", None);
        c.gate_id = "0x1";
        assert!(personal_message(&c).is_err());
    }

    #[test]
    fn decodes_with_and_without_consume_digest() {
        let p = decode_access_proof(&token(&format!(
            r#"{{"address":"0x1","nonce":"n","signature":"AAAA","consumeDigest":"{DIGEST}"}}"#
        )))
        .unwrap();
        assert_eq!(p.address, "0x1");
        assert_eq!(p.consume_digest.as_deref(), Some(DIGEST));
        let p = decode_access_proof(&token(
            r#"{"address":"0x1","nonce":"n","signature":"AAAA"}"#,
        ))
        .unwrap();
        assert!(p.consume_digest.is_none());
    }

    #[test]
    fn rejects_an_oversized_token_before_decoding() {
        let err = decode_access_proof(&"A".repeat(MAX_TOKEN_BYTES + 1))
            .unwrap_err()
            .to_string();
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn rejects_everything_outside_the_field_grammar() {
        for json in [
            r#"{"address":"0x1","nonce":"nönce","signature":"AAAA"}"#,
            "{\"address\":\"0x\u{e9}1\",\"nonce\":\"n\",\"signature\":\"AAAA\"}",
            r#"{"address":"","nonce":"n","signature":"AAAA"}"#,
            r#"{"address":"1234","nonce":"n","signature":"AAAA"}"#,
            r#"{"address":"0xzz","nonce":"n","signature":"AAAA"}"#,
            r#"{"address":"0x1","nonce":"","signature":"AAAA"}"#,
            r#"{"address":"0x1","nonce":"a b","signature":"AAAA"}"#,
            r#"{"address":"0x1","nonce":"n","signature":""}"#,
            r#"{"address":"0x1","nonce":"n","signature":"***"}"#,
            r#"{"address":"0x1","nonce":"n","signature":"AAAA","consumeDigest":"DIGEST-1"}"#,
            r#"{"address":"0x1","nonce":"n","signature":"AAAA","consumeDigest":""}"#,
            r#"{"address":"0x1","nonce":"n","signature":"AAAA","consumeDigest":7}"#,
            r#"{"address":"0x1","nonce":"n","signature":"AAAA","consumeDigest":null}"#,
            r#"["0x1"]"#,
            "null",
            r#"{"address":"0x1"}"#,
        ] {
            assert!(decode_access_proof(&token(json)).is_err(), "{json}");
        }
        assert!(decode_access_proof("!!!not-base64!!!").is_err());
    }
}
