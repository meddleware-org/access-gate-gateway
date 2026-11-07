//! Fuzz target `proof`: access-proof decoding (`proof::decode_access_proof`), the grammar predicates and the signed
//! message builder. The token is the one attacker-controlled string every gated request carries, so it must never
//! panic and a successful decode must satisfy the documented grammar.
#![no_main]

use access_gate_gateway_core::proof::{
    decode_access_proof, is_canonical_id, is_nonce, is_tx_digest, personal_message, MessageContext,
    MAX_TOKEN_BYTES,
};
use base64::prelude::*;
use libfuzzer_sys::fuzz_target;

const GATE: &str = "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

/// What a successful decode promises (the field grammar in the module docs).
fn check_decoded(token: &str) {
    if let Ok(p) = decode_access_proof(token) {
        assert!(token.len() <= MAX_TOKEN_BYTES);
        let hex = p
            .address
            .strip_prefix("0x")
            .expect("address has the 0x prefix");
        assert!((1..=64).contains(&hex.len()) && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(is_nonce(&p.nonce));
        assert!(p.signature.is_ascii() && !p.signature.is_empty() && p.signature.len() <= 1026);
        if let Some(d) = &p.consume_digest {
            assert!(is_tx_digest(d));
        }
        // A decoded nonce and digest can always be put into the signed message (no line injection, no error).
        let ctx = MessageContext {
            origin: "https://gateway.example",
            gate_id: GATE,
            network: "testnet",
            nonce: &p.nonce,
            consume_digest: p.consume_digest.as_deref(),
        };
        let msg = personal_message(&ctx).expect("a decoded proof always yields a message");
        assert!(msg.is_ascii());
        assert!(msg.iter().filter(|b| **b == b'\n').count() <= 5);
    }
}

fuzz_target!(|data: &[u8]| {
    // (a) the bytes as a token string, as the header carries it
    if let Ok(s) = std::str::from_utf8(data) {
        check_decoded(s);
        let _ = (is_tx_digest(s), is_nonce(s), is_canonical_id(s));
    }
    // (b) the bytes as the JSON document inside a valid base64 wrapper, to reach the JSON layer
    check_decoded(&BASE64_STANDARD.encode(data));
    // (c) a well-formed JSON object whose four fields come from the input (split on NUL), to reach the grammar checks
    let parts: Vec<String> = data
        .split(|b| *b == 0)
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    let part = |i: usize| parts.get(i).cloned().unwrap_or_default();
    let mut obj = serde_json::json!({ "address": part(0), "nonce": part(1), "signature": part(2) });
    if parts.len() > 3 {
        obj["consumeDigest"] = serde_json::Value::String(part(3));
    }
    check_decoded(&BASE64_STANDARD.encode(obj.to_string()));
    // (d) the message builder on arbitrary fields: an error or a message, never a panic
    let digest = (parts.len() > 3).then(|| part(3));
    let _ = personal_message(&MessageContext {
        origin: &part(4),
        gate_id: &part(5),
        network: &part(6),
        nonce: &part(1),
        consume_digest: digest.as_deref(),
    });
});
