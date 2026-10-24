//! Generic NFT-gated reverse proxy binary: the hyper/axum/tokio/Redis adapter around `access-gate-gateway-core`.
#![forbid(unsafe_code)]
//!
//! Everything the gateway decides and does lives in `access-gate-gateway-core` (shared with the Cloudflare
//! Worker): the proof, the signature schemes, the decision, the Sui reads, the state machines, the
//! header / path / config policy and the request orchestration (`access_gate_gateway_core::gateway`). This crate
//! supplies only I/O: the TCP server and its limits, the hyper HTTP client, Redis, the system clock and
//! entropy, and the mapping between axum types and the core's [`RequestHead`] / [`Reply`].
//!
//! # Startup sequence
//!
//! 1. Load [`config::ServerConfig`] from environment variables (see `config.rs`). Abort on
//!    missing required vars.
//! 2. Build an [`http_client::HttpClient`] for upstream and Sui RPC HTTP.
//! 3. Construct a [`sui_rpc::SuiRpc`] from the shared client.
//! 4. Open either an in-memory or Redis [`challenge::NonceStore`] based on `REDIS_URL`.
//! 5. Create the in-memory rate windows.
//! 6. Spawn a background task that prunes the in-memory nonce store every
//!    `NONCE_PRUNE_INTERVAL_SECS` (no-op for the Redis backend).
//! 7. Bind an axum TCP listener and serve (with the peer address available for client-IP
//!    derivation) under a `MAX_CONCURRENT_REQUESTS` cap, with graceful shutdown on SIGINT/SIGTERM.
//!
//! # AppState
//!
//! [`AppState`] is the single shared object threaded through every request via
//! `axum::extract::State`. It holds:
//!
//! - `cfg` — the loaded configuration (`cfg.gateway` is the part shared with the Worker).
//! - `store` — the nonce / redemption store (in-memory or Redis).
//! - `rates` — the per-IP and per-address rate windows.
//! - `chain` — the Sui RPC client for ownership / event queries.
//! - `http` — the shared [`http_client::HttpClient`] used both by the proxy and the RPC client.

mod challenge;
mod config;
mod grpc;
mod headers;
mod http_client;
mod proxy;
#[cfg(test)]
mod router_tests;
mod state;
mod sui_rpc;
#[cfg(test)]
mod testkit;

use access_gate_gateway_core::gateway::{Gateway, JsonReply, Reply, RequestHead};
use access_gate_gateway_core::headers::{cors_allowed_origin, CORS_GRANTS};
use access_gate_gateway_core::net::client_ip;
use access_gate_gateway_core::state::{MemoryRates, RateBudgets};
use axum::error_handling::HandleErrorLayer;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceBuilder;

use challenge::NonceStore;
use config::ServerConfig;
use http_client::HttpClient;
use state::{NativeState, SystemClock};
use sui_rpc::SuiRpc;

/// Shared state threaded through every axum request handler.
pub struct AppState {
    /// Loaded configuration (env vars).
    cfg: ServerConfig,
    /// Single-use nonce and redemption store (in-memory or Redis).
    store: NonceStore,
    /// Rate windows: per client IP (challenge and public paths), per client IP for gated requests
    /// BEFORE signature verification, and per authenticated address (post-auth).
    rates: MemoryRates<SystemClock>,
    /// Sui gRPC client (gRPC-web) for ownership and consume-transaction queries.
    chain: SuiRpc,
    /// Shared HTTP client used by both the reverse proxy and the Sui RPC calls.
    http: HttpClient,
}

impl AppState {
    /// Wire the server state from its configuration, nonce store and clients.
    fn new(cfg: ServerConfig, store: NonceStore, chain: SuiRpc, http: HttpClient) -> Self {
        let g = &cfg.gateway;
        let rates = MemoryRates::new(
            SystemClock::new(),
            RateBudgets {
                ip: g.challenge_rate_limit_per_min,
                gated_preauth: g.gated_preauth_rate_limit_per_min,
                address: g.rate_limit_per_min,
            },
        );
        Self {
            cfg,
            store,
            rates,
            chain,
            http,
        }
    }
}

impl AppState {
    /// The periodic sweep: expired nonces and ended rate windows (`NONCE_PRUNE_INTERVAL_SECS`).
    fn sweep(&self) {
        self.store.prune();
        self.rates.prune();
    }
}

/// Render a gateway-generated answer: `{"error": reason}` (plus `code`), or the challenge. The
/// operator-only `diag` goes to the log and never to the client.
fn render(reply: JsonReply) -> Response {
    if let Some(diag) = &reply.diag {
        tracing::error!("{diag}");
    }
    let status = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut res = (status, Json(reply.body)).into_response();
    if let Some(allow) = reply.allow {
        res.headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static(allow));
    }
    res
}

/// The fields of a request the shared orchestration reads. The client IP is the TCP peer unless
/// `TRUSTED_PROXY_HOPS` says how many proxies to trust (never the leftmost `X-Forwarded-For` entry,
/// which the client controls).
fn request_head(app: &AppState, req: &Request) -> RequestHead {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let xff: Vec<&str> = req
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let text = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    RequestHead {
        method: req.method().as_str().to_string(),
        path: req.uri().path().to_string(),
        authorization: text("authorization"),
        x_access_proof: text("x-access-proof"),
        via: headers::joined(req.headers(), "via"),
        client_ip: client_ip(&xff, peer, app.cfg.trusted_proxy_hops),
    }
}

/// Main request dispatcher: derive the [`RequestHead`], hand the request to the shared orchestration
/// (`/v1/challenge`, public paths, signature + ownership verification, single-use redemption) and
/// render its [`Reply`]. `/healthz` and CORS preflights are answered before this point.
async fn handle(State(app): State<Arc<AppState>>, req: Request) -> Response {
    let head = request_head(&app, &req);
    let state = NativeState {
        store: &app.store,
        rates: &app.rates,
    };
    let gateway = Gateway {
        cfg: &app.cfg.gateway,
        state: &state,
        chain: &app.chain,
        upstream: &*app,
    };
    match gateway.handle(&head, req).await {
        Reply::Json(reply) => render(reply),
        Reply::Upstream(response) => response,
    }
}

/// CORS as the Workers gateway does it: a preflight is answered here, before rate limits and auth;
/// every response (errors included) carries the grants and `Vary: Origin`; the request `Origin` is
/// reflected only on an exact `ALLOWED_ORIGINS` match (`access_gate_gateway_core::headers`) — otherwise no
/// `Access-Control-Allow-Origin`.
async fn cors(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let allowed = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .and_then(|o| cors_allowed_origin(Some(o), &state.cfg.gateway.allowed_origins))
        .and_then(|o| HeaderValue::from_str(o).ok());
    let mut resp = if req.method() == Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    let headers = resp.headers_mut();
    // Only the gateway's own CORS policy applies: nothing an inner handler set survives.
    let stale: Vec<_> = headers
        .keys()
        .filter(|k| k.as_str().starts_with("access-control-"))
        .cloned()
        .collect();
    for k in stale {
        headers.remove(k);
    }
    for (name, value) in CORS_GRANTS {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = allowed {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    }
    resp
}

/// A JSON `{"error": reason}` answer for the layers around the orchestration.
fn deny(status: StatusCode, reason: &str) -> Response {
    (status, Json(json!({ "error": reason }))).into_response()
}

/// Construct the axum [`Router`] with the shared [`AppState`]. `/healthz` is answered directly and
/// is never shed (so probes stay truthful under load); everything else goes through the single
/// [`handle`] fallback behind a `MAX_CONCURRENT_REQUESTS` cap that answers `503` at once when full.
fn build_router(state: Arc<AppState>) -> Router {
    let max_in_flight = state.cfg.max_concurrent_requests;
    let cors_layer = middleware::from_fn_with_state(state.clone(), cors);
    let gated = Router::new().fallback(any(handle)).with_state(state).layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|_: tower::BoxError| async {
                deny(StatusCode::SERVICE_UNAVAILABLE, "gateway overloaded")
            }))
            .load_shed()
            .concurrency_limit(max_in_flight),
    );
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .merge(gated)
        .layer(cors_layer)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = ServerConfig::from_env()?;
    let g = &cfg.gateway;
    // The upstream URL is deliberately not logged: it is the private origin (audit F26).
    tracing::info!(?cfg.bind_addr, nft_type = %g.nft_type, single_use = g.single_use, "starting access-gate-gateway");

    let http = HttpClient::new()?;
    let chain = sui_rpc::new_sui_rpc(
        http.clone(),
        g.sui_rpc_url.clone(),
        g.ownership_cache_ttl_ms,
        g.sui_rpc_auth_header.clone(),
        std::time::Duration::from_secs(g.rpc_timeout_secs),
    );
    if g.single_use && cfg.redis_url.is_none() && cfg.allow_volatile_redemptions {
        tracing::warn!(
            "SINGLE_USE with an in-memory store (ALLOW_VOLATILE_REDEMPTIONS): spent consumes are \
             forgotten on restart; use REDIS_URL outside development"
        );
    }
    let store = match &cfg.redis_url {
        Some(url) => {
            tracing::info!("using Redis/Dragonfly nonce store — fleet-wide replay protection");
            NonceStore::redis(url, g.challenge_ttl_secs).await?
        }
        None => {
            tracing::info!(
                "using in-memory nonce store (correct at replicas:1; set REDIS_URL to scale out)"
            );
            NonceStore::in_memory(g.challenge_ttl_secs, g.nonce_max_entries)
        }
    };
    let bind_addr = cfg.bind_addr;
    let prune_interval = cfg.nonce_prune_interval_secs.max(1);

    let state = Arc::new(AppState::new(cfg, store, chain, http));

    // Background prune keeps the in-memory nonce map and the rate windows bounded independent of
    // traffic (the nonce prune is a no-op for the Redis backend, which expires via key TTL; the rate
    // windows are always in memory, and each table is also capped, F10).
    {
        let prune_state = state.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(prune_interval));
            loop {
                ticker.tick().await;
                prune_state.sweep();
            }
        });
    }

    let limits = ServerLimits {
        header_read_timeout: std::time::Duration::from_secs(state.cfg.header_read_timeout_secs),
        max_connections: state.cfg.max_connections,
        shutdown_grace: std::time::Duration::from_secs(state.cfg.shutdown_grace_secs),
    };
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(%bind_addr, "listening");
    serve(listener, app, limits, shutdown_signal()).await
}

/// Connection-level limits applied by [`serve`].
struct ServerLimits {
    /// A client must send its request head within this long (also bounds an idle keep-alive wait).
    header_read_timeout: std::time::Duration,
    /// Open connections; further clients wait in the TCP backlog until one closes.
    max_connections: usize,
    /// After the shutdown signal, in-flight requests get this long before the process exits.
    shutdown_grace: std::time::Duration,
}

/// Serve `app` over HTTP/1 with connection-level limits axum's own `serve` does not offer: a header
/// read timeout (slowloris), a cap on open connections, and a bounded graceful shutdown.
async fn serve(
    listener: tokio::net::TcpListener,
    app: Router,
    limits: ServerLimits,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    use hyper_util::rt::{TokioIo, TokioTimer};
    use hyper_util::service::TowerToHyperService;
    use tower::ServiceExt as _;

    let permits = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let mut tasks = tokio::task::JoinSet::new();
    let mut make = app.into_make_service_with_connect_info::<SocketAddr>();
    tokio::pin!(shutdown);
    loop {
        let permit = tokio::select! {
            () = &mut shutdown => break,
            p = permits.clone().acquire_owned() => p?,
        };
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            r = listener.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            },
        };
        // The service for this connection carries the peer address (`ConnectInfo`).
        let Ok(service) = (&mut make).oneshot(peer).await;
        let hyper_service = TowerToHyperService::new(service);
        let header_timeout = limits.header_read_timeout;
        tasks.spawn(async move {
            let _permit = permit;
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(header_timeout)
                .serve_connection(TokioIo::new(stream), hyper_service);
            if let Err(e) = conn.await {
                tracing::debug!(error = %e, "connection closed with error");
            }
        });
        // Reap finished connection tasks so the set stays small.
        while tasks.try_join_next().is_some() {}
    }
    tracing::info!(
        grace_secs = limits.shutdown_grace.as_secs(),
        "draining connections"
    );
    drop(listener);
    // In-flight requests finish within the grace period; whatever remains is dropped.
    let drain = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(limits.shutdown_grace, drain)
        .await
        .is_err()
    {
        tracing::warn!("shutdown grace elapsed; dropping remaining connections");
        tasks.abort_all();
    }
    Ok(())
}

/// Resolves on SIGINT (Ctrl-C) or SIGTERM (what Kubernetes and Docker send), triggering axum's
/// graceful shutdown so in-flight uploads finish.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutting down");
}

/// Shared test fixtures.
#[cfg(test)]
pub(crate) mod tests_support {
    use crate::config::ServerConfig;
    use std::collections::HashMap;

    /// A complete config with test defaults (single-use off, `/v1/tip-config` public), built by the
    /// real parser so the fixtures can never drift from what a deployment can express.
    pub fn test_cfg() -> ServerConfig {
        let env: HashMap<&str, &str> = HashMap::from([
            ("GATEWAY_ORIGIN", "https://gateway.example"),
            ("NETWORK", "testnet"),
            ("UPSTREAM_URL", "http://upstream"),
            ("SUI_RPC_URL", "http://rpc"),
            ("NFT_TYPE", "0x1::access_gate::AccessNFT"),
            ("GATE_ID", "0x2"),
            ("ALLOW_INSECURE_HTTP", "1"),
            ("ALLOWED_ORIGINS", "https://app.example"),
            ("NONCE_MAX_ENTRIES", "10000"),
        ]);
        ServerConfig::from_lookup(&|k: &str| env.get(k).map(|v| v.to_string())).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `AppState` over the test config with in-memory state and a hermetic client.
    fn test_state(cfg: ServerConfig) -> AppState {
        let g = &cfg.gateway;
        let chain = sui_rpc::new_sui_rpc(
            HttpClient::new().unwrap(),
            g.sui_rpc_url.clone(),
            0,
            None,
            std::time::Duration::from_secs(15),
        );
        AppState::new(
            cfg,
            NonceStore::in_memory(300, 100),
            chain,
            HttpClient::new().unwrap(),
        )
    }

    #[tokio::test]
    async fn router_serves_healthz_and_routes_through_the_concurrency_layer() {
        use tower::ServiceExt;
        let mut cfg = tests_support::test_cfg();
        cfg.max_concurrent_requests = 1;
        let app = build_router(Arc::new(test_state(cfg)));
        let get = |p: &str| {
            axum::http::Request::builder()
                .uri(p)
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let health = app.clone().oneshot(get("/healthz")).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        let challenge = app.oneshot(get("/v1/challenge")).await.unwrap();
        assert_eq!(challenge.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn the_periodic_sweep_covers_the_rate_windows_without_changing_a_verdict() {
        use tower::ServiceExt;
        let mut cfg = tests_support::test_cfg();
        cfg.gateway.challenge_rate_limit_per_min = 1;
        let state = Arc::new(test_state(cfg));
        let app = build_router(state.clone());
        let challenge = || {
            axum::http::Request::builder()
                .uri("/v1/challenge")
                .body(axum::body::Body::empty())
                .unwrap()
        };
        assert_eq!(
            app.clone().oneshot(challenge()).await.unwrap().status(),
            StatusCode::OK
        );
        assert!(state.rates.key_count() >= 1, "the request opened a window");
        state.sweep(); // the window is still running: nothing to drop, and the budget stays spent
        assert!(state.rates.key_count() >= 1);
        assert_eq!(
            app.oneshot(challenge()).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    fn cors_app() -> Router {
        let cfg = tests_support::test_cfg();
        build_router(Arc::new(test_state(cfg)))
    }

    fn with_origin(
        method: Method,
        path: &str,
        origin: Option<&str>,
    ) -> axum::http::Request<axum::body::Body> {
        let mut b = axum::http::Request::builder().method(method).uri(path);
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        b.body(axum::body::Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn cors_preflight_is_answered_before_auth_for_an_allowed_origin() {
        use tower::ServiceExt;
        let resp = cors_app()
            .oneshot(with_origin(
                Method::OPTIONS,
                "/v1/blob-upload-relay",
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let h = resp.headers();
        assert_eq!(
            h[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://app.example"
        );
        assert_eq!(
            h["access-control-allow-headers"],
            "authorization, content-type, x-access-proof"
        );
        assert_eq!(h[header::VARY], "Origin");
    }

    #[tokio::test]
    async fn cors_never_reflects_an_unlisted_or_absent_origin() {
        use tower::ServiceExt;
        for origin in [
            Some("https://evil.example"),
            Some("https://app.example.evil"),
            None,
        ] {
            let resp = cors_app()
                .oneshot(with_origin(Method::OPTIONS, "/v1/challenge", origin))
                .await
                .unwrap();
            assert!(
                resp.headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none(),
                "{origin:?}"
            );
            assert_eq!(resp.headers()[header::VARY], "Origin");
        }
    }

    #[tokio::test]
    async fn cors_headers_are_on_error_responses_too() {
        use tower::ServiceExt;
        let resp = cors_app()
            .oneshot(with_origin(
                Method::POST,
                "/v1/blob-upload-relay",
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://app.example"
        );
    }

    async fn status_of(app: Router, method: Method, path: &str, auth: Option<&str>) -> StatusCode {
        use tower::ServiceExt;
        let mut b = axum::http::Request::builder().method(method).uri(path);
        if let Some(a) = auth {
            b = b.header(header::AUTHORIZATION, a);
        }
        app.oneshot(b.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn public_paths_are_read_only_and_gated_methods_are_listed() {
        // A body-carrying method on a public path never reaches the upstream.
        assert_eq!(
            status_of(cors_app(), Method::POST, "/v1/tip-config", None).await,
            StatusCode::METHOD_NOT_ALLOWED
        );
        // A method outside the list is refused before any verification work.
        assert_eq!(
            status_of(cors_app(), Method::DELETE, "/v1/x", Some("Bearer abc")).await,
            StatusCode::METHOD_NOT_ALLOWED
        );
        // A listed method with a malformed proof reaches verification (403), not the method check.
        assert_eq!(
            status_of(cors_app(), Method::POST, "/v1/x", Some("Bearer !!!")).await,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn gated_requests_are_rate_limited_per_ip_before_verification() {
        use tower::ServiceExt;
        let mut cfg = tests_support::test_cfg();
        cfg.gateway.gated_preauth_rate_limit_per_min = 3;
        let app = build_router(Arc::new(test_state(cfg)));
        let mut seen = Vec::new();
        for _ in 0..5 {
            let req = axum::http::Request::builder()
                .method(Method::POST)
                .uri("/v1/x")
                .header(header::AUTHORIZATION, "Bearer !!!")
                .body(axum::body::Body::empty())
                .unwrap();
            seen.push(app.clone().oneshot(req).await.unwrap().status());
        }
        assert_eq!(
            seen,
            [
                StatusCode::FORBIDDEN,
                StatusCode::FORBIDDEN,
                StatusCode::FORBIDDEN,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS
            ]
        );
    }

    #[tokio::test]
    async fn the_server_drops_a_client_that_never_finishes_its_headers() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limits = ServerLimits {
            header_read_timeout: std::time::Duration::from_millis(200),
            max_connections: 4,
            shutdown_grace: std::time::Duration::from_secs(1),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, cors_app(), limits, async {
            let _ = stopped.await;
        }));
        let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap(); // never finishes
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), slow.read(&mut buf))
            .await
            .expect("the server must close the stalled connection")
            .unwrap_or(0);
        let reply = String::from_utf8_lossy(&buf[..n]);
        assert!(n == 0 || reply.starts_with("HTTP/1.1 408"), "{reply}");
        // A well-formed request is still served.
        let mut ok = tokio::net::TcpStream::connect(addr).await.unwrap();
        ok.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        ok.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        let _ = stop.send(());
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn the_connection_cap_holds_extra_clients_until_a_slot_frees() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limits = ServerLimits {
            header_read_timeout: std::time::Duration::from_secs(30),
            max_connections: 1,
            shutdown_grace: std::time::Duration::from_secs(1),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, cors_app(), limits, async {
            let _ = stopped.await;
        }));
        // The only slot is taken by an idle keep-alive connection.
        let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
        first
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        assert!(first.read(&mut buf).await.unwrap() > 0);
        // A second client connects (TCP backlog) but is not served while the first holds the slot.
        let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
        second
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let waited =
            tokio::time::timeout(std::time::Duration::from_millis(300), second.read(&mut buf))
                .await;
        assert!(waited.is_err(), "served beyond the connection cap");
        // Freeing the slot lets it through.
        drop(first);
        let mut out = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            second.read_to_string(&mut out),
        )
        .await
        .expect("served once a slot frees")
        .unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        let _ = stop.send(());
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_gives_in_flight_requests_a_bounded_grace() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limits = ServerLimits {
            header_read_timeout: std::time::Duration::from_secs(60),
            max_connections: 4,
            shutdown_grace: std::time::Duration::from_millis(300),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, cors_app(), limits, async {
            let _ = stopped.await;
        }));
        // A client that never finishes its request keeps a connection open.
        let mut stuck = tokio::net::TcpStream::connect(addr).await.unwrap();
        stuck.write_all(b"GET /healthz HTTP/1.1\r\n").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let started = std::time::Instant::now();
        let _ = stop.send(());
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .expect("serve must return after the grace period")
            .unwrap()
            .unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
    }
}
