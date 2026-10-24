//! The access-gate gateway as a Cloudflare Worker: an I/O adapter on `access-gate-gateway-core`.
//!
//! Everything the gateway decides is the core's (`Gateway::handle`, the proof and signature checks, the
//! Sui reads, the header / path / config policy, the quota maths). This crate supplies only what a
//! Worker has and a server does not:
//!
//! | File | Role |
//! | --- | --- |
//! | `lib.rs` | the `fetch` / `scheduled` entry points, routing around the core (`/healthz`, CORS, 508) |
//! | `state.rs`, `do_state.rs` | `StateStore` over the region-sharded SQLite Durable Object `NonceRateState` |
//! | `upstream.rs` | `Upstream` over streamed `fetch`: byte cap, `FixedLengthStream`, public edge cache |
//! | `transport.rs` | the gRPC-web `Transport` over `fetch` |
//! | `config.rs`, `region.rs`, `cors.rs`, `json.rs`, `out.rs` | Worker-only variables, shard routing, CORS, body rendering, response assembly |
//! | `quota_guard.rs` | the `scheduled` quota guard |
//!
//! Parity target: `gateway-workers` (TypeScript), request for request. A panic cannot be caught on
//! wasm32 (it is a trap, answered by the runtime's generic 500 without the JSON/CORS shape), so the
//! request path is linted free of `unwrap`, `expect`, `panic!` and indexing (`[lints.clippy]`).
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

mod config;
mod cors;
mod do_state;
#[cfg(feature = "test-hooks")]
mod hooks;
mod json;
mod out;
mod quota_guard;
mod region;
mod state;
mod transport;
mod upstream;

pub use do_state::NonceRateState;

use access_gate_gateway_core::chain::SuiRpc;
use access_gate_gateway_core::config::Env as CoreEnv;
use access_gate_gateway_core::gateway::{Gateway, JsonReply, Reply, RequestHead};
use access_gate_gateway_core::headers::{cors_allowed_origin, via_is_looped};
use access_gate_gateway_core::net::rate_key;
use config::WorkerConfig;
use out::{finish, Out};
use state::{Budgets, DoState};
use std::cell::RefCell;
use std::rc::Rc;
use transport::WorkerTransport;
use upstream::{ProxyRequest, WorkerUpstream};
use wasm_bindgen::JsValue;
use worker::{console_error, event, Context, Env, Result, ScheduleContext, ScheduledEvent};

/// Reads Worker `vars` and secrets (both are plain strings on `env`).
struct WorkerEnv<'a>(&'a Env);

impl CoreEnv for WorkerEnv<'_> {
    fn get(&self, key: &str) -> Option<String> {
        js_sys::Reflect::get(self.0, &JsValue::from_str(key))
            .ok()
            .and_then(|v| v.as_string())
    }
}

/// Configuration and the Sui client, built once per isolate.
struct Shared {
    cfg: WorkerConfig,
    chain: SuiRpc<WorkerTransport>,
}

thread_local! {
    static SHARED: RefCell<Option<Rc<Shared>>> = const { RefCell::new(None) };
}

fn shared(env: &Env) -> anyhow::Result<Rc<Shared>> {
    if let Some(s) = SHARED.with(|c| c.borrow().clone()) {
        return Ok(s);
    }
    let cfg = WorkerConfig::load(&WorkerEnv(env))?;
    let chain = SuiRpc::new(
        WorkerTransport {
            auth: cfg.core.sui_rpc_auth_header.clone(),
            timeout_ms: u32::try_from(cfg.core.rpc_timeout_secs.saturating_mul(1000))
                .unwrap_or(u32::MAX),
        },
        cfg.core.sui_rpc_url.clone(),
        cfg.core.ownership_cache_ttl_ms,
        cfg.core.rpc_timeout_secs.saturating_mul(1000),
    );
    let s = Rc::new(Shared { cfg, chain });
    SHARED.with(|c| *c.borrow_mut() = Some(s.clone()));
    Ok(s)
}

fn header(req: &web_sys::Request, name: &str) -> Option<String> {
    req.headers().get(name).ok().flatten()
}

/// `cf.continent` of the request (Cloudflare metadata; absent in some local setups).
fn continent(req: &web_sys::Request) -> Option<String> {
    let cf = js_sys::Reflect::get(req, &JsValue::from_str("cf")).ok()?;
    js_sys::Reflect::get(&cf, &JsValue::from_str("continent"))
        .ok()?
        .as_string()
}

/// The rate-limit key for the client Cloudflare observed (the only trustworthy source at the edge).
/// IPv6 clients are keyed by their /64; a request with no `CF-Connecting-IP` shares one `unknown`.
fn client_ip(req: &web_sys::Request) -> String {
    header(req, "cf-connecting-ip").map_or_else(|| "unknown".to_string(), |ip| rate_key(&ip))
}

fn json_out(r: JsonReply) -> std::result::Result<Out, JsValue> {
    if let Some(d) = &r.diag {
        console_error!("{d}");
    }
    Out::json(r.status, json::render(&r.body), r.allow)
}

/// Everything except CORS decoration: the answer, and the allowed origins to decorate it with.
async fn route(
    req: &web_sys::Request,
    env: &Env,
    ctx: &Context,
    shared: &anyhow::Result<Rc<Shared>>,
) -> std::result::Result<Out, JsValue> {
    let url = worker::Url::parse(&req.url()).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let path = url.path().to_string();
    let method = req.method();

    if path == "/healthz" {
        return Out::text(200, "ok");
    }
    // The browser sends OPTIONS before non-simple cross-origin requests; answering here (before any
    // auth or config work) keeps the auth path from returning 401 and aborting the real request.
    if method == "OPTIONS" {
        return Out::preflight();
    }
    // A request that already carries this gateway's own `Via` entry has looped back through it.
    if via_is_looped(&header(req, "via").unwrap_or_default()) {
        return Out::error(508, "loop detected");
    }
    let shared = match shared {
        Ok(s) => s.clone(),
        Err(e) => {
            // Fail closed; the detail goes to the Worker log only.
            console_error!("gateway misconfigured: {e}");
            return Out::error(500, "gateway misconfigured");
        }
    };
    let cfg = &shared.cfg;
    let Ok(ns) = env.durable_object("NONCE_STATE") else {
        console_error!("gateway misconfigured: the NONCE_STATE Durable Object binding is missing");
        return Out::error(500, "gateway misconfigured");
    };

    let head = RequestHead {
        method: method.clone(),
        path: path.clone(),
        authorization: header(req, "authorization"),
        x_access_proof: header(req, "x-access-proof"),
        via: header(req, "via"),
        client_ip: client_ip(req),
    };
    let state = DoState {
        ns,
        region: region::region_of(cfg.shard_global, continent(req).as_deref()),
        challenge_ttl_secs: cfg.core.challenge_ttl_secs,
        max_entries: cfg.core.nonce_max_entries,
        budgets: Budgets {
            challenge: cfg.core.challenge_rate_limit_per_min,
            public: cfg.public_rate_limit_per_min,
            gated_preauth: cfg.core.gated_preauth_rate_limit_per_min,
            address: cfg.core.rate_limit_per_min,
        },
        #[cfg(feature = "test-hooks")]
        fail: WorkerEnv(env).get("TEST_FAIL_STATE"),
    };
    let upstream = WorkerUpstream { cfg, ctx };
    let gateway = Gateway {
        cfg: &cfg.core,
        state: &state,
        chain: &shared.chain,
        upstream: &upstream,
    };
    let proxy_req = ProxyRequest {
        req: Clone::clone(req),
        path,
        search: url.query().map(|q| format!("?{q}")).unwrap_or_default(),
    };
    match gateway.handle(&head, proxy_req).await {
        Reply::Json(r) => json_out(r),
        Reply::Upstream(out) => Ok(out),
    }
}

async fn respond(req: web_sys::Request, env: Env, ctx: Context) -> Result<web_sys::Response> {
    let origin = header(&req, "origin");
    let shared = shared(&env);
    let out = match route(&req, &env, &ctx, &shared).await {
        Ok(o) => o,
        Err(e) => {
            // Fail closed with a JSON body the browser can read (CORS is still applied below).
            console_error!("unhandled gateway error: {e:?}");
            Out::error(502, "bad gateway").map_err(|e| worker::Error::JsError(format!("{e:?}")))?
        }
    };
    let allowed = shared.as_ref().ok().and_then(|s| {
        cors_allowed_origin(origin.as_deref(), &s.cfg.core.allowed_origins).map(str::to_string)
    });
    finish(out, allowed.as_deref()).map_err(|e| worker::Error::JsError(format!("{e:?}")))
}

#[event(fetch)]
async fn fetch(req: web_sys::Request, env: Env, ctx: Context) -> Result<web_sys::Response> {
    console_error_panic_hook::set_once();
    #[cfg(feature = "test-hooks")]
    if let Some(r) = hooks::route(&req, &env).await {
        return r.map(Into::into);
    }
    respond(req, env, ctx).await
}

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    quota_guard::run(&env).await;
}
