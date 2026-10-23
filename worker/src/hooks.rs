//! Test-only routes (cargo feature `test-hooks`; never in the deployed build, which the size gate and
//! `wrangler deploy` use). They exist so the black-box suite can reach what a client cannot:
//!
//! - `/__test/do/<shard>/<op>?...`  the Durable Object directly, with a pinned clock (`now=`)
//! - `/__test/bench?scheme=&iters=` signature-verification timing over the embedded conformance vectors
//! - `/__test/mem`                   wasm linear-memory size (streaming stays flat)
//! - `/__test/panic`                 a deliberate panic, to record what a trap looks like

// Test-only module: the deliberate `/__test/panic` route and JSON indexing over the embedded vectors are
// the point of it, and none of this is compiled into the deployed Worker.
#![allow(clippy::panic, clippy::indexing_slicing)]

use access_gate_gateway_core::proof::{personal_message, MessageContext};
use access_gate_gateway_core::sig::verify_personal_message_signature;
use wasm_bindgen::JsCast;
use worker::*;

const VECTORS: &str = include_str!("../../conformance/vectors.json");

fn json(status: u16, v: serde_json::Value) -> Result<Response> {
    Ok(Response::from_json(&v)?.with_status(status))
}

fn now_ms() -> f64 {
    js_sys::global()
        .unchecked_into::<web_sys::WorkerGlobalScope>()
        .performance()
        .map_or_else(js_sys::Date::now, |p| p.now())
}

fn bench(url: &Url) -> Result<Response> {
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let want = q.get("scheme").map_or("ed25519", String::as_str);
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
        .ok_or_else(|| Error::RustError("no such scheme".into()))?;
    let field = |v: &serde_json::Value, k: &str| v[k].as_str().unwrap_or_default().to_string();
    let ctx = &sig["context"];
    let (origin, gate, network, nonce) = (
        field(ctx, "origin"),
        field(ctx, "gateId"),
        field(ctx, "network"),
        field(ctx, "nonce"),
    );
    let consume = ctx["consumeDigest"].as_str();
    let message = personal_message(&MessageContext {
        origin: &origin,
        gate_id: &gate,
        network: &network,
        nonce: &nonce,
        consume_digest: consume,
    })
    .map_err(|e| Error::RustError(e.to_string()))?;
    let (address, signature) = (field(sig, "address"), field(sig, "signature"));
    let verify = || verify_personal_message_signature(&address, &message, &signature);
    let t0 = now_ms();
    let ok = verify();
    let first_ms = now_ms() - t0;
    for _ in 0..warmup {
        verify();
    }
    let t1 = now_ms();
    for _ in 0..iters {
        verify();
    }
    let warm = (now_ms() - t1) / f64::from(iters);
    json(
        200,
        serde_json::json!({ "scheme": want, "valid": ok, "firstMs": first_ms, "warmMeanMs": warm, "iterations": iters }),
    )
}

/// Handle a `/__test/*` request; `None` when the path is not one.
pub async fn route(req: &web_sys::Request, env: &Env) -> Option<Result<Response>> {
    let url = Url::parse(&req.url()).ok()?;
    let path = url.path().to_string();
    let rest = path.strip_prefix("/__test/")?;
    Some(match rest {
        "bench" => bench(&url),
        "mem" => {
            let mem = wasm_bindgen::memory().unchecked_into::<js_sys::WebAssembly::Memory>();
            let bytes = mem
                .buffer()
                .unchecked_into::<js_sys::ArrayBuffer>()
                .byte_length();
            json(200, serde_json::json!({ "wasmMemoryBytes": bytes }))
        }
        "panic" => panic!("deliberate panic (test-hooks)"),
        r if r.starts_with("do/") => do_op(r, &url, env).await,
        _ => json(404, serde_json::json!({ "error": "not found" })),
    })
}

async fn do_op(rest: &str, url: &Url, env: &Env) -> Result<Response> {
    let mut parts = rest.trim_start_matches("do/").splitn(2, '/');
    let shard = parts.next().unwrap_or("g");
    let op = parts.next().unwrap_or("");
    let ns = env.durable_object("NONCE_STATE")?;
    let stub = ns.id_from_name(&format!("nonce:{shard}"))?.get_stub()?;
    let mut inner = Url::parse("https://do.internal/")?;
    inner.set_path(op);
    inner.set_query(url.query());
    stub.fetch_with_str(inner.as_str()).await
}
