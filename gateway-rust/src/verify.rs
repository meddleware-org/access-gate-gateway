//! Access verification. The decision logic and the signature primitives live in `nft-gate-core`
//! (shared with the Cloudflare Worker); this module adapts the native pieces to it: the
//! `GatewayConfig` -> `VerifyParams` mapping and the `NonceStore` -> `NonceTake` adapter.

use crate::challenge::NonceStore;
use crate::config::GatewayConfig;
#[allow(unused_imports)]
use crate::proof::{decode_access_proof, is_tx_digest, personal_message, MessageContext};
#[allow(unused_imports)]
use base64::prelude::*;

pub use nft_gate_core::decision::{ChainQuery, Denied, Verified};
use nft_gate_core::decision::{NonceTake, VerifyParams};
#[allow(unused_imports)]
pub use nft_gate_core::sig::{
    consumed_event_type, derive_address, normalize_address, normalize_move_type, signing_digest,
    verify_personal_message_signature, FLAG_ED25519, FLAG_MULTISIG, FLAG_SECP256K1, FLAG_SECP256R1,
    FLAG_ZKLOGIN,
};

impl NonceTake for NonceStore {
    async fn take_if_valid(&self, nonce: &str) -> anyhow::Result<bool> {
        NonceStore::take_if_valid(self, nonce).await
    }
}

fn params(cfg: &GatewayConfig) -> VerifyParams {
    VerifyParams {
        single_use: cfg.single_use,
        gateway_origin: cfg.gateway_origin.clone(),
        gate_id: cfg.gate_id.clone(),
        network: cfg.network.clone(),
        nft_type: cfg.nft_type.clone(),
        consume_max_age_secs: cfg.consume_max_age_secs,
    }
}

/// Authorise a request from its base64 proof token (see `nft_gate_core::decision`).
pub async fn verify_access_request<C: ChainQuery>(
    cfg: &GatewayConfig,
    store: &NonceStore,
    token: &str,
    chain: &C,
) -> Result<Verified, Denied> {
    nft_gate_core::decision::verify_access_request(&params(cfg), store, token, chain).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::AccessProof;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const DIGEST: &str = "5Wq9tE4gXz8hEvFhYt8KkTJb2Pp6qXqj8cRk3xN1mYdL";

    /// The message a client signs for the test gateway (origin https://gateway.example, gate 0x2,
    /// testnet), with an optional consume digest.
    fn msg_for(nonce: &str, consume_digest: Option<&str>) -> Vec<u8> {
        let cfg = crate::tests_support::test_cfg();
        personal_message(&MessageContext {
            origin: &cfg.gateway_origin,
            gate_id: &normalize_address(&cfg.gate_id),
            network: &cfg.network,
            nonce,
            consume_digest,
        })
        .unwrap()
    }

    /// `msg_for` with no consume digest.
    fn signed_msg(nonce: &str) -> Vec<u8> {
        msg_for(nonce, None)
    }

    fn build_token(
        sk: &SigningKey,
        address: &str,
        nonce: &str,
        consume_digest: Option<&str>,
    ) -> String {
        let message = msg_for(nonce, consume_digest);
        let digest = signing_digest(&message);
        let sig = sk.sign(&digest);
        let mut serialized = Vec::with_capacity(97);
        serialized.push(0x00);
        serialized.extend_from_slice(&sig.to_bytes());
        serialized.extend_from_slice(sk.verifying_key().as_bytes());
        let sig_b64 = BASE64_STANDARD.encode(serialized);
        let mut obj = json!({ "address": address, "nonce": nonce, "signature": sig_b64 });
        if let Some(d) = consume_digest {
            obj["consumeDigest"] = json!(d);
        }
        BASE64_STANDARD.encode(serde_json::to_vec(&obj).unwrap())
    }

    fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let address = derive_address(FLAG_ED25519, sk.verifying_key().as_bytes());
        (sk, address)
    }

    #[test]
    fn signature_verifies_and_recovers_address() {
        let (sk, address) = keypair();
        let msg = signed_msg("nonce-1");
        let proof: AccessProof =
            crate::proof::decode_access_proof(&build_token(&sk, &address, "nonce-1", None))
                .unwrap();
        assert!(verify_personal_message_signature(
            &address,
            &msg,
            &proof.signature
        ));
    }

    // ── secp256k1 (flag 0x01) ──────────────────────────────────────────────
    #[test]
    fn secp256k1_signature_verifies_and_recovers_address() {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey as K1SigningKey};
        let sk = K1SigningKey::from_slice(&[9u8; 32]).unwrap();
        let pk = sk.verifying_key().to_encoded_point(true);
        let pk_bytes = pk.as_bytes(); // 33-byte compressed
        let address = derive_address(FLAG_SECP256K1, pk_bytes);

        let msg = signed_msg("k1-nonce");
        let digest = signing_digest(&msg);
        // k256 Signer applies SHA256 internally, matching Sui's ECDSA hash: SHA256(blake2b).
        let sig: Signature = sk.sign(&digest);
        let mut serialized = vec![FLAG_SECP256K1];
        serialized.extend_from_slice(&sig.to_bytes());
        serialized.extend_from_slice(pk_bytes);
        let sig_b64 = BASE64_STANDARD.encode(serialized);

        assert!(verify_personal_message_signature(&address, &msg, &sig_b64));
        // wrong address rejected
        assert!(!verify_personal_message_signature("0xdead", &msg, &sig_b64));
        // tampered message rejected
        let other = signed_msg("k1-other");
        assert!(!verify_personal_message_signature(
            &address, &other, &sig_b64
        ));
    }

    // ── secp256r1 (flag 0x02) ──────────────────────────────────────────────
    #[test]
    fn secp256r1_signature_verifies_and_recovers_address() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey as R1SigningKey};
        let sk = R1SigningKey::from_slice(&[11u8; 32]).unwrap();
        let pk = sk.verifying_key().to_encoded_point(true);
        let pk_bytes = pk.as_bytes();
        let address = derive_address(FLAG_SECP256R1, pk_bytes);

        let msg = signed_msg("r1-nonce");
        let digest = signing_digest(&msg);
        // p256 Signer applies SHA256 internally, matching Sui's ECDSA hash: SHA256(blake2b).
        let sig: Signature = sk.sign(&digest);
        let mut serialized = vec![FLAG_SECP256R1];
        serialized.extend_from_slice(&sig.to_bytes());
        serialized.extend_from_slice(pk_bytes);
        let sig_b64 = BASE64_STANDARD.encode(serialized);

        assert!(verify_personal_message_signature(&address, &msg, &sig_b64));
        assert!(!verify_personal_message_signature("0xdead", &msg, &sig_b64));
    }

    #[test]
    fn multisig_and_zklogin_flags_fail_closed() {
        // flag 0x03 (multisig) / 0x05 (zkLogin) are recognised but not yet verified → false.
        let msg = signed_msg("n");
        let mut ms = vec![FLAG_MULTISIG];
        ms.extend_from_slice(&[0u8; 96]);
        assert!(!verify_personal_message_signature(
            "0x1",
            &msg,
            &BASE64_STANDARD.encode(ms)
        ));
        let mut zk = vec![FLAG_ZKLOGIN];
        zk.extend_from_slice(&[0u8; 96]);
        assert!(!verify_personal_message_signature(
            "0x1",
            &msg,
            &BASE64_STANDARD.encode(zk)
        ));
    }

    // ── cross-implementation conformance: the SAME fixtures the Workers gateway verifies
    // (conformance/vectors.json, generated and published by @meddleware/nft-gate-client), so the
    // implementations cannot silently drift on the wire format. Each `signatures[]` entry is a real
    // Sui personal-message signature over the v2 message for its `context`. ──
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
        let raw = include_str!("../../conformance/vectors.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(v["version"], "nft-gate:access:v2");

        // personal-message derivation, byte for byte
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
            // `message_of` does not re-check the origin (config does); the other fields it does.
            let origin = c["context"]["origin"].as_str().unwrap();
            let refused =
                message_of(&c["context"]).is_err() || !crate::config::is_canonical_origin(origin);
            assert!(refused, "must refuse: {}", c["name"]);
        }

        // proof decode
        let pd = &v["proofDecode"];
        let decoded = crate::proof::decode_access_proof(pd["token"].as_str().unwrap()).unwrap();
        assert_eq!(decoded.address, pd["expect"]["address"].as_str().unwrap());
        assert_eq!(decoded.nonce, pd["expect"]["nonce"].as_str().unwrap());
        assert_eq!(
            decoded.signature,
            pd["expect"]["signature"].as_str().unwrap()
        );

        // proof decode rejections: the field grammar, size and ASCII rules
        for case in v["proofDecodeRejects"]["cases"].as_array().unwrap() {
            assert!(
                crate::proof::decode_access_proof(case["token"].as_str().unwrap()).is_err(),
                "must reject: {}",
                case["name"]
            );
        }

        // address normalization — canonicalised before on-chain owner comparison
        for case in v["addressNormalization"]["cases"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            assert_eq!(
                normalize_address(input),
                case["expected"].as_str().unwrap(),
                "address normalization diverged for input {input}"
            );
        }

        // per-scheme signature verification (ed25519 / secp256k1 / secp256r1 / single-use)
        for sig in v["signatures"].as_array().unwrap() {
            let address = sig["address"].as_str().unwrap();
            let m = message_of(&sig["context"]).unwrap();
            assert!(
                verify_personal_message_signature(address, &m, sig["signature"].as_str().unwrap()),
                "scheme {} failed to verify",
                sig["scheme"].as_str().unwrap_or("?")
            );
            let p = crate::proof::decode_access_proof(sig["proofToken"].as_str().unwrap()).unwrap();
            assert_eq!(p.address, address);
        }

        // a valid signature presented for a different audience (origin, gate, network, nonce, consume)
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

        // negative vectors: high-S ECDSA, non-canonical ed25519 s, wrong intent, truncation and the
        // unsupported flags must all be rejected by both implementations.
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

        // ZIP-215: Sui validators verify ed25519 under ZIP-215, so the gateway must accept this
        // small-order vector (a strict RFC 8032 verifier rejects it).
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

    #[test]
    fn signature_rejected_for_wrong_address() {
        let (sk, _addr) = keypair();
        let msg = signed_msg("nonce-1");
        let proof: AccessProof =
            crate::proof::decode_access_proof(&build_token(&sk, "0xdead", "nonce-1", None))
                .unwrap();
        assert!(!verify_personal_message_signature(
            "0xdead",
            &msg,
            &proof.signature
        ));
    }

    #[test]
    fn signature_rejected_when_tampered() {
        let (sk, address) = keypair();
        // sign nonce A but verify against nonce B's message
        let proof: AccessProof =
            crate::proof::decode_access_proof(&build_token(&sk, &address, "nonce-A", None))
                .unwrap();
        let other_msg = signed_msg("nonce-B");
        assert!(!verify_personal_message_signature(
            &address,
            &other_msg,
            &proof.signature
        ));
    }

    struct MockChain {
        owns: bool,
        consumed: bool,
        blocked: bool,
    }
    impl ChainQuery for MockChain {
        async fn owns_nft(&self, _a: &str, _t: &str, _g: Option<&str>) -> anyhow::Result<bool> {
            Ok(self.owns)
        }
        async fn consume_tx_valid(
            &self,
            _d: &str,
            _a: &str,
            event_type: &str,
            _g: Option<&str>,
            max_age_secs: u64,
        ) -> anyhow::Result<bool> {
            assert_eq!(max_age_secs, 432_000, "the configured consume age bound");
            // The verifier must ask for the configured package's exact event type.
            assert_eq!(
                event_type,
                "0x0000000000000000000000000000000000000000000000000000000000000001::access_gate::AccessConsumedEvent"
            );
            Ok(self.consumed)
        }
        async fn gate_access_blocked(&self, _g: &str) -> anyhow::Result<bool> {
            Ok(self.blocked)
        }
    }

    fn cfg(single_use: bool) -> GatewayConfig {
        GatewayConfig {
            single_use,
            ..crate::tests_support::test_cfg()
        }
    }

    #[tokio::test]
    async fn allows_owner_with_valid_proof() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("real-nonce").await;
        let token = build_token(&sk, &address, &nonce, None);
        let res = verify_access_request(
            &cfg(false),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: false,
                blocked: false,
            },
        )
        .await;
        let v = res.unwrap();
        assert_eq!(v.address, address);
        assert_eq!(v.redemption_key, None); // ownership mode has no redemption key
    }

    #[tokio::test]
    async fn denies_non_owner() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("n2").await;
        let token = build_token(&sk, &address, &nonce, None);
        let res = verify_access_request(
            &cfg(false),
            &store,
            &token,
            &MockChain {
                owns: false,
                consumed: false,
                blocked: false,
            },
        )
        .await;
        assert_eq!(res.unwrap_err(), Denied::NotOwner);
    }

    #[tokio::test]
    async fn denies_replayed_nonce() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("n3").await;
        let token = build_token(&sk, &address, &nonce, None);
        let ok = verify_access_request(
            &cfg(false),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: false,
                blocked: false,
            },
        )
        .await;
        assert!(ok.is_ok());
        // second use of the same nonce is rejected
        let again = verify_access_request(
            &cfg(false),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: false,
                blocked: false,
            },
        )
        .await;
        assert_eq!(again.unwrap_err(), Denied::NonceInvalid);
    }

    #[tokio::test]
    async fn denies_bad_signature() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("n4").await;
        // sign a different nonce than the proof claims
        let mut token_proof: serde_json::Value = serde_json::from_slice(
            &BASE64_STANDARD
                .decode(build_token(&sk, &address, "OTHER", None))
                .unwrap(),
        )
        .unwrap();
        token_proof["nonce"] = json!(nonce); // claim n4 but signature is over OTHER
        let token = BASE64_STANDARD.encode(serde_json::to_vec(&token_proof).unwrap());
        let res = verify_access_request(
            &cfg(false),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: false,
                blocked: false,
            },
        )
        .await;
        assert_eq!(res.unwrap_err(), Denied::BadSignature);
    }

    #[tokio::test]
    async fn single_use_requires_consume_event() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("n5").await;
        let token = build_token(&sk, &address, &nonce, Some(DIGEST));
        // owns but no consume -> denied
        let denied = verify_access_request(
            &cfg(true),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: false,
                blocked: false,
            },
        )
        .await;
        assert_eq!(denied.unwrap_err(), Denied::ConsumeMissing);

        let (nonce2, _) = store.issue_specific("n6").await;
        let token2 = build_token(&sk, &address, &nonce2, Some(DIGEST));
        let ok = verify_access_request(
            &cfg(true),
            &store,
            &token2,
            &MockChain {
                owns: false,
                consumed: true,
                blocked: false,
            },
        )
        .await;
        let v = ok.unwrap();
        assert_eq!(v.address, address);
        // single-use returns the consume digest as the redemption key for the dispatcher to lease
        assert_eq!(v.redemption_key.as_deref(), Some(DIGEST));
    }

    #[tokio::test]
    async fn single_use_denies_missing_consume_digest() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("n7").await;
        let token = build_token(&sk, &address, &nonce, None); // no consumeDigest
        let res = verify_access_request(
            &cfg(true),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: true,
                blocked: false,
            },
        )
        .await;
        assert_eq!(res.unwrap_err(), Denied::ConsumeMissing);
    }

    #[tokio::test]
    async fn denies_owner_while_gate_paused_with_access_policy() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("paused-1").await;
        let token = build_token(&sk, &address, &nonce, None);
        let chain = MockChain {
            owns: true,
            consumed: false,
            blocked: true,
        };
        let res = verify_access_request(&cfg(false), &store, &token, &chain).await;
        assert_eq!(res.unwrap_err(), Denied::GatePaused);
    }

    #[tokio::test]
    async fn single_use_paused_gate_denies_before_redemption() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("paused-2").await;
        let token = build_token(&sk, &address, &nonce, Some(DIGEST));
        let chain = MockChain {
            owns: true,
            consumed: true,
            blocked: true,
        };
        let res = verify_access_request(&cfg(true), &store, &token, &chain).await;
        // No redemption key is produced, so the consume is never leased and stays redeemable.
        assert_eq!(res.unwrap_err(), Denied::GatePaused);
    }

    // ── audience binding (protocol v2) ──
    fn chain_ok() -> MockChain {
        MockChain {
            owns: true,
            consumed: true,
            blocked: false,
        }
    }

    #[tokio::test]
    async fn refuses_a_proof_made_for_another_gateway_gate_or_network() {
        let (sk, address) = keypair();
        let signed_for_this_gateway = || build_token(&sk, &address, "aud-nonce", None);
        for (what, mutate) in [
            (
                "another gateway origin",
                Box::new(|c: &mut GatewayConfig| c.gateway_origin = "https://other.example".into())
                    as Box<dyn Fn(&mut GatewayConfig)>,
            ),
            (
                "another gate",
                Box::new(|c: &mut GatewayConfig| c.gate_id = "0x3".into()),
            ),
            (
                "another network",
                Box::new(|c: &mut GatewayConfig| c.network = "mainnet".into()),
            ),
        ] {
            let store = NonceStore::in_memory(300, 10_000);
            store.issue_specific("aud-nonce").await;
            let token = signed_for_this_gateway();
            let mut c = cfg(false);
            mutate(&mut c);
            let res = verify_access_request(&c, &store, &token, &chain_ok()).await;
            assert_eq!(res.unwrap_err(), Denied::BadSignature, "{what}");
        }
    }

    #[tokio::test]
    async fn refuses_the_v1_message_and_a_cross_mode_signature() {
        let (sk, address) = keypair();
        // v1: just "nft-gate:access:<nonce>" signed.
        let v1 = b"nft-gate:access:aud-nonce".to_vec();
        let sig = sk.sign(&signing_digest(&v1));
        let mut ser = vec![0x00];
        ser.extend_from_slice(&sig.to_bytes());
        ser.extend_from_slice(sk.verifying_key().as_bytes());
        let token = BASE64_STANDARD.encode(
            serde_json::to_vec(&json!({"address": address, "nonce": "aud-nonce", "signature": BASE64_STANDARD.encode(ser)})).unwrap(),
        );
        let store = NonceStore::in_memory(300, 10_000);
        store.issue_specific("aud-nonce").await;
        let res = verify_access_request(&cfg(false), &store, &token, &chain_ok()).await;
        assert_eq!(res.unwrap_err(), Denied::BadSignature);

        // An ownership gateway refuses a proof signed for single-use (consume line in the message).
        let store = NonceStore::in_memory(300, 10_000);
        store.issue_specific("aud-nonce").await;
        let token = build_token(&sk, &address, "aud-nonce", Some(DIGEST));
        let res = verify_access_request(&cfg(false), &store, &token, &chain_ok()).await;
        assert_eq!(res.unwrap_err(), Denied::BadSignature);
    }

    #[tokio::test]
    async fn single_use_refuses_a_swapped_consume_digest() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        store.issue_specific("aud-nonce").await;
        let signed = build_token(&sk, &address, "aud-nonce", Some(DIGEST));
        let mut obj: serde_json::Value =
            serde_json::from_slice(&BASE64_STANDARD.decode(signed).unwrap()).unwrap();
        obj["consumeDigest"] = json!(format!("9{}", &DIGEST[1..]));
        let token = BASE64_STANDARD.encode(serde_json::to_vec(&obj).unwrap());
        let res = verify_access_request(&cfg(true), &store, &token, &chain_ok()).await;
        assert_eq!(res.unwrap_err(), Denied::BadSignature);
    }
}
