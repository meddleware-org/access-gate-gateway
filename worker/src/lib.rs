//! Feasibility spike: the nft-gate Worker's building blocks in Rust (workers-rs, wasm32).
//! Routes (all under one Worker; see ../README.md):
//!   GET  /healthz                 liveness, no work
//!   GET  /bench?scheme=&iters=    signature verification timing (feature `bench`: embedded vectors)
//!   GET  /mem                     wasm linear-memory size (bytes)
//!   ANY  /do/<op>?...             Durable Object (SQLite) nonce / rate / redemption ops
//!   POST|PUT /proxy/<path>        streaming proxy to UPSTREAM_URL with a byte cap
//!   GET  /chain/tx?digest=&...    GetTransaction through the SHARED nft-gate-core over `fetch`
//!   GET  /chain/owned?address=..  ListOwnedObjects (paged) likewise
//!   POST /verify                  full verify_access_request decision (nonce from the DO, chain over fetch)
use wasm_bindgen::JsCast;
use worker::*;

mod bench;
mod chain;
mod do_state;
mod proxy;

pub use do_state::NonceRateState;

fn json(status: u16, v: serde_json::Value) -> Result<Response> {
    Ok(Response::from_json(&v)?.with_status(status))
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();
    let url = req.url()?;
    let path = url.path().to_string();
    match path.as_str() {
        "/healthz" => Response::ok("ok"),
        "/mem" => {
            let mem = wasm_bindgen::memory().unchecked_into::<js_sys::WebAssembly::Memory>();
            let bytes = mem
                .buffer()
                .unchecked_into::<js_sys::ArrayBuffer>()
                .byte_length();
            json(200, serde_json::json!({ "wasmMemoryBytes": bytes }))
        }
        "/bench" => bench::handle(&url),
        #[cfg(feature = "bench")]
        "/panic" => panic!("deliberate panic (spike: does the isolate recover?)"),
        p if p.starts_with("/do/") => do_state::route(req, env).await,
        p if p.starts_with("/proxy/") => proxy::handle(req, env).await,
        p if p.starts_with("/chain/") => chain::handle(req, env).await,
        "/verify" => chain::verify(req, env).await,
        _ => json(404, serde_json::json!({ "error": "not found" })),
    }
}
