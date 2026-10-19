//! Signature-verification timing inside the Worker. Wall time only (`performance.now()` in
//! workerd advances locally; on the edge it is frozen between I/O, so only the Node harness and the
//! deployed CPU-time analytics are authoritative for CPU).
use nft_gate_core::proof::{personal_message, MessageContext};
use nft_gate_core::sig::verify_personal_message_signature;
use worker::*;

#[cfg(feature = "bench")]
const VECTORS: &str = include_str!("../../../conformance/vectors.json");
#[cfg(not(feature = "bench"))]
const VECTORS: &str = "{\"signatures\":[]}";

fn now_ms() -> f64 {
    js_sys::global()
        .unchecked_into::<web_sys::WorkerGlobalScope>()
        .performance()
        .map(|p| p.now())
        .unwrap_or_else(js_sys::Date::now)
}
use wasm_bindgen::JsCast;

pub fn handle(url: &Url) -> Result<Response> {
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let want = q.get("scheme").map(String::as_str).unwrap_or("ed25519");
    let iters: u32 = q
        .get("iters")
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
        .max(1);
    let warmup: u32 = q.get("warmup").and_then(|v| v.parse().ok()).unwrap_or(20);
    let v: serde_json::Value =
        serde_json::from_str(VECTORS).map_err(|e| Error::RustError(e.to_string()))?;
    let sig = v["signatures"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["scheme"] == want))
        .ok_or_else(|| Error::RustError("no such scheme (build with --features bench)".into()))?;
    let ctx = &sig["context"];
    let message = personal_message(&MessageContext {
        origin: ctx["origin"].as_str().unwrap(),
        gate_id: ctx["gateId"].as_str().unwrap(),
        network: ctx["network"].as_str().unwrap(),
        nonce: ctx["nonce"].as_str().unwrap(),
        consume_digest: ctx["consumeDigest"].as_str(),
    })
    .map_err(|e| Error::RustError(e.to_string()))?;
    let address = sig["address"].as_str().unwrap();
    let signature = sig["signature"].as_str().unwrap();
    let verify = || {
        if !verify_personal_message_signature(address, &message, signature) {
            panic!("vector failed");
        }
    };
    let t0 = now_ms();
    verify();
    let first_ms = now_ms() - t0;
    for _ in 0..warmup {
        verify();
    }
    let t1 = now_ms();
    for _ in 0..iters {
        verify();
    }
    let warm = (now_ms() - t1) / f64::from(iters);
    Response::from_json(
        &serde_json::json!({ "scheme": want, "firstMs": first_ms, "warmMeanMs": warm, "iterations": iters }),
    )
}
