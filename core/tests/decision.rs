//! The allow/deny decision and the Sui signature schemes, end to end with real signatures: ed25519,
//! secp256k1 and secp256r1 proofs are built here, then judged by [`verify_access_request`] against a
//! scripted chain and a single-use nonce store. (Moved from `gateway-rust/src/verify.rs`: the code under
//! test now lives in `access-gate-gateway-core`.)
use base64::prelude::*;
use ed25519_dalek::{Signer, SigningKey};
use access_gate_gateway_core::config::GatewayConfig;
use access_gate_gateway_core::decision::{
    verify_access_request as decide, ChainQuery, Denied, NonceTake, Verified, VerifyParams,
};
use access_gate_gateway_core::proof::{decode_access_proof, personal_message, AccessProof, MessageContext};
use access_gate_gateway_core::sig::{
    derive_address, normalize_address, signing_digest, verify_personal_message_signature,
    FLAG_ED25519, FLAG_MULTISIG, FLAG_SECP256K1, FLAG_SECP256R1, FLAG_ZKLOGIN,
};
use serde_json::json;
use std::collections::HashSet;
use std::sync::Mutex;

/// A nonce store that knows exactly the nonces a test issued, each valid once.
#[derive(Default)]
struct Nonces(Mutex<HashSet<String>>);

impl Nonces {
    fn issue(&self, nonce: &str) -> (String, u64) {
        self.0.lock().unwrap().insert(nonce.to_string());
        (nonce.to_string(), 0)
    }
}

impl NonceTake for Nonces {
    async fn take_if_valid(&self, nonce: &str) -> anyhow::Result<bool> {
        Ok(self.0.lock().unwrap().remove(nonce))
    }
}

/// The gateway the tests sign for: origin https://gateway.example, gate 0x2, testnet, ownership mode.
fn test_cfg() -> GatewayConfig {
    let env = |k: &str| {
        Some(
            match k {
                "GATEWAY_ORIGIN" => "https://gateway.example",
                "NETWORK" => "testnet",
                "UPSTREAM_URL" => "https://upstream.example",
                "SUI_RPC_URL" => "https://rpc.example",
                "NFT_TYPE" => "0x1::access_gate::AccessNFT",
                "GATE_ID" => "0x2",
                _ => return None,
            }
            .to_string(),
        )
    };
    GatewayConfig::from_env(&env).unwrap()
}

async fn verify_access_request<C: ChainQuery>(
    cfg: &GatewayConfig,
    store: &Nonces,
    token: &str,
    chain: &C,
) -> Result<Verified, Denied> {
    decide(&VerifyParams::from(cfg), store, token, chain).await
}

const DIGEST: &str = "5Wq9tE4gXz8hEvFhYt8KkTJb2Pp6qXqj8cRk3xN1mYdL";

/// The message a client signs for the test gateway (origin https://gateway.example, gate 0x2,
/// testnet), with an optional consume digest.
fn msg_for(nonce: &str, consume_digest: Option<&str>) -> Vec<u8> {
    let cfg = test_cfg();
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
        decode_access_proof(&build_token(&sk, &address, "nonce-1", None)).unwrap();
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

#[test]
fn signature_rejected_for_wrong_address() {
    let (sk, _addr) = keypair();
    let msg = signed_msg("nonce-1");
    let proof: AccessProof =
        decode_access_proof(&build_token(&sk, "0xdead", "nonce-1", None)).unwrap();
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
        decode_access_proof(&build_token(&sk, &address, "nonce-A", None)).unwrap();
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
        ..test_cfg()
    }
}

#[test]
fn allows_owner_with_valid_proof() {
    pollster::block_on(async {
        let (sk, address) = keypair();
        let store = Nonces::default();
        let (nonce, _) = store.issue("real-nonce");
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
    });
}

#[test]
fn denies_non_owner() {
    pollster::block_on(async {
        let (sk, address) = keypair();
        let store = Nonces::default();
        let (nonce, _) = store.issue("n2");
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
    });
}

#[test]
fn denies_replayed_nonce() {
    pollster::block_on(async {
        let (sk, address) = keypair();
        let store = Nonces::default();
        let (nonce, _) = store.issue("n3");
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
    });
}

#[test]
fn denies_bad_signature() {
    pollster::block_on(async {
        let (sk, address) = keypair();
        let store = Nonces::default();
        let (nonce, _) = store.issue("n4");
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
    });
}

#[test]
fn single_use_requires_consume_event() {
    pollster::block_on(async {
        let (sk, address) = keypair();
        let store = Nonces::default();
        let (nonce, _) = store.issue("n5");
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

        let (nonce2, _) = store.issue("n6");
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
    });
}

#[test]
fn single_use_denies_missing_consume_digest() {
    pollster::block_on(async {
        let (sk, address) = keypair();
        let store = Nonces::default();
        let (nonce, _) = store.issue("n7");
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
    });
}

#[test]
fn denies_owner_while_gate_paused_with_access_policy() {
    pollster::block_on(async {
        let (sk, address) = keypair();
        let store = Nonces::default();
        let (nonce, _) = store.issue("paused-1");
        let token = build_token(&sk, &address, &nonce, None);
        let chain = MockChain {
            owns: true,
            consumed: false,
            blocked: true,
        };
        let res = verify_access_request(&cfg(false), &store, &token, &chain).await;
        assert_eq!(res.unwrap_err(), Denied::GatePaused);
    });
}

#[test]
fn single_use_paused_gate_denies_before_redemption() {
    pollster::block_on(async {
        let (sk, address) = keypair();
        let store = Nonces::default();
        let (nonce, _) = store.issue("paused-2");
        let token = build_token(&sk, &address, &nonce, Some(DIGEST));
        let chain = MockChain {
            owns: true,
            consumed: true,
            blocked: true,
        };
        let res = verify_access_request(&cfg(true), &store, &token, &chain).await;
        // No redemption key is produced, so the consume is never leased and stays redeemable.
        assert_eq!(res.unwrap_err(), Denied::GatePaused);
    });
}

// ── audience binding (protocol v2) ──
fn chain_ok() -> MockChain {
    MockChain {
        owns: true,
        consumed: true,
        blocked: false,
    }
}

#[test]
fn refuses_a_proof_made_for_another_gateway_gate_or_network() {
    pollster::block_on(async {
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
            let store = Nonces::default();
            store.issue("aud-nonce");
            let token = signed_for_this_gateway();
            let mut c = cfg(false);
            mutate(&mut c);
            let res = verify_access_request(&c, &store, &token, &chain_ok()).await;
            assert_eq!(res.unwrap_err(), Denied::BadSignature, "{what}");
        }
    });
}

#[test]
fn refuses_the_v1_message_and_a_cross_mode_signature() {
    pollster::block_on(async {
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
        let store = Nonces::default();
        store.issue("aud-nonce");
        let res = verify_access_request(&cfg(false), &store, &token, &chain_ok()).await;
        assert_eq!(res.unwrap_err(), Denied::BadSignature);

        // An ownership gateway refuses a proof signed for single-use (consume line in the message).
        let store = Nonces::default();
        store.issue("aud-nonce");
        let token = build_token(&sk, &address, "aud-nonce", Some(DIGEST));
        let res = verify_access_request(&cfg(false), &store, &token, &chain_ok()).await;
        assert_eq!(res.unwrap_err(), Denied::BadSignature);
    });
}

#[test]
fn single_use_refuses_a_swapped_consume_digest() {
    pollster::block_on(async {
        let (sk, address) = keypair();
        let store = Nonces::default();
        store.issue("aud-nonce");
        let signed = build_token(&sk, &address, "aud-nonce", Some(DIGEST));
        let mut obj: serde_json::Value =
            serde_json::from_slice(&BASE64_STANDARD.decode(signed).unwrap()).unwrap();
        obj["consumeDigest"] = json!(format!("9{}", &DIGEST[1..]));
        let token = BASE64_STANDARD.encode(serde_json::to_vec(&obj).unwrap());
        let res = verify_access_request(&cfg(true), &store, &token, &chain_ok()).await;
        assert_eq!(res.unwrap_err(), Denied::BadSignature);
    });
}
