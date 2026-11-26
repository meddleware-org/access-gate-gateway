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

/// The shared conformance vectors, embedded so the timing route needs no network.
const VECTORS: &str = include_str!("../../conformance/vectors.json");

/// A JSON answer with this status.
fn json(status: u16, v: serde_json::Value) -> Result<Response> {
    Ok(Response::from_json(&v)?.with_status(status))
}

/// A monotonic millisecond reading (`performance.now`), or the wall clock where that is missing.
fn now_ms() -> f64 {
    js_sys::global()
        .unchecked_into::<web_sys::WorkerGlobalScope>()
        .performance()
        .map_or_else(js_sys::Date::now, |p| p.now())
}

/// Time signature verification of one scheme: the first call (cold), then the mean of `iters` warm calls.
fn bench(url: &Url) -> Result<Response> {
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    // Default to ed25519, the common wallet scheme.
    let want = q.get("scheme").map_or("ed25519", String::as_str);
    let iters: u32 = q
        .get("iters")
        .and_then(|v| v.parse().ok())
        // 200 iterations is enough to see a warm mean without a long request.
        .unwrap_or(200)
        .max(1);
    // Warm-up calls are not timed: they let the runtime compile and cache.
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
    // The first call is timed on its own because cold start is what matters at the edge.
    let t0 = now_ms();
    let ok = verify();
    // The cold figure: what the first request of an isolate pays.
    let first_ms = now_ms() - t0;
    // Let the runtime settle before the timed loop.
    for _ in 0..warmup {
        verify();
    }
    let t1 = now_ms();
    for _ in 0..iters {
        verify();
    }
    // The mean per call over the timed loop.
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

/// Forward `/do/<shard>/<op>` to the Durable Object of that shard, with the query string intact (including a pinned `now`).
async fn do_op(rest: &str, url: &Url, env: &Env) -> Result<Response> {
    let mut parts = rest.trim_start_matches("do/").splitn(2, '/');
    let shard = parts.next().unwrap_or("g");
    let op = parts.next().unwrap_or("");
    // The same binding the gateway uses.
    let ns = env.durable_object("NONCE_STATE")?;
    // The id derives from the shard name, as the gateway derives it, so a test reaches the same object.
    let stub = ns.id_from_name(&format!("nonce:{shard}"))?.get_stub()?;
    let mut inner = Url::parse("https://do.internal/")?;
    inner.set_path(op);
    inner.set_query(url.query());
    stub.fetch_with_str(inner.as_str()).await
}
