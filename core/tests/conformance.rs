//! The shared golden vectors (`conformance/vectors.json`) run against `nft-gate-core` — the same
//! assertions as `gateway-rust` `verify::tests::conformance_shared_vectors`, but against the core
//! crate alone, natively. The wasm32 build is checked by `worker/tests` through workerd.
use base64::prelude::*;
use nft_gate_core::origin::is_canonical_origin;
use nft_gate_core::proof::{decode_access_proof, is_tx_digest, personal_message, MessageContext};
use nft_gate_core::sig::{normalize_address, verify_personal_message_signature};

const VECTORS: &str = include_str!("../../conformance/vectors.json");

fn message_of(ctx: &serde_json::Value) -> anyhow::Result<Vec<u8>> {
    personal_message(&MessageContext {
        origin: ctx["origin"].as_str().unwrap(),
        gate_id: ctx["gateId"].as_str().unwrap(),
        network: ctx["network"].as_str().unwrap(),
        nonce: ctx["nonce"].as_str().unwrap(),
        consume_digest: ctx["consumeDigest"].as_str(),
    })
}

#[test]
fn conformance_shared_vectors() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(v["version"], "nft-gate:access:v2");
    for c in v["personalMessage"]["cases"].as_array().unwrap() {
        let bytes = message_of(&c["context"]).unwrap();
        assert_eq!(
            bytes,
            c["messageUtf8"].as_str().unwrap().as_bytes(),
            "{}",
            c["name"]
        );
        assert_eq!(
            BASE64_STANDARD.encode(&bytes),
            c["messageBytesBase64"].as_str().unwrap()
        );
    }
    for c in v["personalMessageRejects"].as_array().unwrap() {
        let origin = c["context"]["origin"].as_str().unwrap();
        assert!(
            message_of(&c["context"]).is_err() || !is_canonical_origin(origin),
            "must refuse: {}",
            c["name"]
        );
    }
    let pd = &v["proofDecode"];
    let decoded = decode_access_proof(pd["token"].as_str().unwrap()).unwrap();
    assert_eq!(decoded.address, pd["expect"]["address"].as_str().unwrap());
    assert_eq!(decoded.nonce, pd["expect"]["nonce"].as_str().unwrap());
    assert_eq!(
        decoded.signature,
        pd["expect"]["signature"].as_str().unwrap()
    );
    for case in v["proofDecodeRejects"]["cases"].as_array().unwrap() {
        assert!(
            decode_access_proof(case["token"].as_str().unwrap()).is_err(),
            "must reject: {}",
            case["name"]
        );
    }
    for case in v["txDigest"]["valid"].as_array().unwrap() {
        let d = case["digest"].as_str().unwrap();
        assert!(is_tx_digest(d), "must accept: {}", case["name"]);
    }
    for case in v["txDigest"]["invalid"].as_array().unwrap() {
        let d = case["digest"].as_str().unwrap();
        assert!(!is_tx_digest(d), "must refuse: {}", case["name"]);
    }
    for case in v["addressNormalization"]["cases"].as_array().unwrap() {
        let input = case["input"].as_str().unwrap();
        assert_eq!(
            normalize_address(input),
            case["expected"].as_str().unwrap(),
            "{input}"
        );
    }
    for sig in v["signatures"].as_array().unwrap() {
        let address = sig["address"].as_str().unwrap();
        let m = message_of(&sig["context"]).unwrap();
        assert!(
            verify_personal_message_signature(address, &m, sig["signature"].as_str().unwrap()),
            "scheme {} failed to verify",
            sig["scheme"].as_str().unwrap_or("?")
        );
        assert_eq!(
            decode_access_proof(sig["proofToken"].as_str().unwrap())
                .unwrap()
                .address,
            address
        );
    }
    for neg in v["audienceMismatch"].as_array().unwrap() {
        let m = message_of(&neg["context"]).unwrap();
        assert!(
            !verify_personal_message_signature(
                neg["address"].as_str().unwrap(),
                &m,
                neg["signature"].as_str().unwrap()
            ),
            "audience mismatch accepted: {}",
            neg["case"]
        );
    }
    for neg in v["negativeSignatures"].as_array().unwrap() {
        let m = message_of(&neg["context"]).unwrap();
        assert!(
            !verify_personal_message_signature(
                neg["address"].as_str().unwrap(),
                &m,
                neg["signature"].as_str().unwrap()
            ),
            "negative vector accepted: {}",
            neg["case"].as_str().unwrap_or("?")
        );
    }
    let z = &v["zip215"];
    assert!(
        verify_personal_message_signature(
            z["address"].as_str().unwrap(),
            &message_of(&z["context"]).unwrap(),
            z["signature"].as_str().unwrap()
        ),
        "ZIP-215 vector rejected"
    );
}
