//! Fuzz target `sig`: the signature-verification entry point (`sig::verify_personal_message_signature`) for every
//! scheme flag, plus the address helpers. Properties: no panic on any input; a signature under multisig (0x03),
//! zkLogin (0x05) or an unknown flag never verifies; and the ZIP-215 conformance signature (identity key, valid for
//! every message under the rule Sui validators apply) verifies for every message and for no other address.
#![no_main]

use access_gate_gateway_core::sig::{
    consumed_event_type, derive_address, normalize_address, normalize_move_type, signing_digest,
    unsupported_flag, verify_personal_message_signature,
};
use arbitrary::Arbitrary;
use base64::prelude::*;
use libfuzzer_sys::fuzz_target;

/// `zip215` in conformance/vectors.json.
const ZIP215_ADDRESS: &str = "0x6e02ac5b501ce6f9a0ef3cb7026073505ce6b755f014f64738483f63c5d1b5c7";
const ZIP215_SIGNATURE: &str = "AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

#[derive(Debug, Arbitrary)]
struct Input {
    /// The scheme flag byte of the serialized signature.
    flag: u8,
    /// Bytes after the flag (clamped to the scheme's length by `shape`).
    body: Vec<u8>,
    /// 0: body as is; 1: exactly the scheme's length; 2: the scheme's length with a valid-looking SEC1 prefix.
    shape: u8,
    address: String,
    message: Vec<u8>,
    /// The signature string as received, unstructured.
    raw_signature: String,
}

fn body_for(i: &Input) -> Vec<u8> {
    let want = match i.flag {
        0x00 => 96,
        0x01 | 0x02 => 97,
        _ => return i.body.clone(),
    };
    let mut b = i.body.clone();
    if i.shape % 3 != 0 {
        b.resize(want, 0);
    }
    if i.shape % 3 == 2 && want == 97 {
        // pubkey is the last 33 bytes: give it a compressed-point prefix so the curve decoder works on real x-coordinates
        b[64] = 0x02 | (b[64] & 1);
    }
    b
}

fuzz_target!(|i: Input| {
    // The raw string entry point, as the decision calls it with a decoded proof's fields.
    let _ = verify_personal_message_signature(&i.address, &i.message, &i.raw_signature);
    let _ = unsupported_flag(&i.raw_signature);

    // A serialized signature of every flag, with the address derived from its own public key so that verification
    // is reached rather than stopped at the address comparison.
    let body = body_for(&i);
    let mut raw = vec![i.flag];
    raw.extend_from_slice(&body);
    let sig = BASE64_STANDARD.encode(&raw);
    let pk_len = if i.flag == 0 { 32 } else { 33 };
    let derived = body
        .len()
        .checked_sub(pk_len)
        .map(|at| derive_address(i.flag, &body[at..]));
    for address in [Some(i.address.as_str()), derived.as_deref()]
        .into_iter()
        .flatten()
    {
        let ok = verify_personal_message_signature(address, &i.message, &sig);
        if matches!(i.flag, 0x03 | 0x05) || i.flag > 0x02 {
            assert!(!ok, "flag {:#04x} must fail closed", i.flag);
        }
    }

    // ZIP-215: valid for any message, and bound to its own address.
    assert!(verify_personal_message_signature(
        ZIP215_ADDRESS,
        &i.message,
        ZIP215_SIGNATURE
    ));
    assert!(!verify_personal_message_signature(
        &derive_address(0, &[7u8; 32]),
        &i.message,
        ZIP215_SIGNATURE
    ));

    // Address helpers.
    let n = normalize_address(&i.address);
    assert!(n.starts_with("0x"));
    let _ = normalize_move_type(&i.address);
    let _ = consumed_event_type(&i.address);
    assert_eq!(signing_digest(&i.message).len(), 32);
});
