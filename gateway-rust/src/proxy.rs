//! Reverse-proxy an authorised request to the configured upstream: the native
//! [`nft_gate_core::gateway::Upstream`]. Body is capped at `max_body_bytes` (a griefing guard): a
//! declared `Content-Length` over the cap is rejected before any byte is read; otherwise the body is
//! read up to the cap, within `BODY_READ_TIMEOUT_SECS`.
//!
//! Scope: this gateway is for **small-body upstreams** (a tip-config read, a small API). The request
//! body is buffered in full (`to_bytes`), and so is the upstream response (capped at
//! `MAX_RESPONSE_BYTES`). Worst case per in-flight request is about `2 × max_body_bytes` plus the
//! response; `MAX_CONCURRENT_REQUESTS` bounds the number in flight. A large-upload relay (the
//! Walrus upload relay takes up to ~100 MiB) belongs behind the streaming Worker gateway; see
//! README.
//!
//! Policy (`nft_gate_core::forward` and `nft_gate_core::headers`, the same on every platform): only
//! `GET`, `HEAD`, `POST` and `PUT` are forwarded (405 otherwise); the path must be free of encoded
//! separators and dot segments (400); hop-by-hop fields (and those named in `Connection`),
//! credentials, cookies and spoofable forwarding fields are stripped from the request, and
//! hop-by-hop fields, cookies and CORS fields from the response. `UPSTREAM_AUTH_HEADERS` are then
//! added (replacing any client-supplied header of the same name). Redirects are never followed (the
//! service-token headers must not follow a `Location`): an upstream 3xx is a 502. The whole exchange
//! is bounded by `UPSTREAM_TIMEOUT_SECS` (504).

use crate::headers::{client_response_headers, upstream_request_headers};
use crate::http_client::TimedOut;
use crate::AppState;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use nft_gate_core::forward::{
    self, Refusal, BODY_TIMED_OUT, BODY_TOO_LARGE, UPSTREAM_ERROR, UPSTREAM_TIMED_OUT,
};
use nft_gate_core::gateway::{ForwardKind, Upstream};
use serde_json::json;

/// A gateway-generated `{"error": reason}` response for a refusal.
fn refuse(r: Refusal) -> Response {
    let status = StatusCode::from_u16(r.status).unwrap_or(StatusCode::BAD_GATEWAY);
    (status, Json(json!({ "error": r.reason }))).into_response()
}

/// Forward `req` to the upstream configured in `app.cfg.gateway.upstream_url`.
///
/// # Errors
///
/// Answers 400 (unsafe path), 405 (method), 413 (body over the cap), 408 (slow body), 502 (upstream
/// failure or redirect) or 504 (upstream deadline).
pub async fn forward(app: &AppState, req: Request) -> Response {
    let cfg = &app.cfg.gateway;
    let (parts, body) = req.into_parts();

    let declared = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok());
    if let Err(r) = forward::preflight(
        parts.method.as_str(),
        parts.uri.path(),
        declared,
        cfg.max_body_bytes,
    ) {
        return refuse(r);
    }
    let read = axum::body::to_bytes(body, cfg.max_body_bytes);
    let bytes = match tokio::time::timeout(
        std::time::Duration::from_secs(cfg.body_read_timeout_secs),
        read,
    )
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(_)) => return refuse(BODY_TOO_LARGE),
        Err(_) => return refuse(BODY_TIMED_OUT),
    };

    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| parts.uri.path());
    let url = format!("{}{}", cfg.upstream_url, path_and_query);
    let headers = upstream_request_headers(&parts.headers);

    match app
        .http
        .forward(
            parts.method,
            &url,
            headers,
            bytes,
            &cfg.upstream_auth_headers,
            std::time::Duration::from_secs(cfg.upstream_timeout_secs),
            cfg.max_response_bytes,
        )
        .await
    {
        // A relay has no business redirecting; treating a 3xx as an error also covers an Access
        // login redirect after the service token expires. Nothing from the response is passed on.
        Ok(resp) if forward::is_redirect(resp.status.as_u16()) => {
            tracing::warn!(status = %resp.status, "upstream answered a redirect; refusing to follow");
            refuse(UPSTREAM_ERROR)
        }
        Ok(resp) => {
            let mut builder = Response::builder().status(resp.status);
            if let Some(h) = builder.headers_mut() {
                *h = client_response_headers(&resp.headers);
            }
            builder
                .body(Body::from(resp.body))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
        }
        Err(e) if e.downcast_ref::<TimedOut>().is_some() => refuse(UPSTREAM_TIMED_OUT),
        Err(e) => {
            tracing::warn!(error = %e, "upstream request failed");
            refuse(UPSTREAM_ERROR)
        }
    }
}

/// The native gateway forwards through its shared hyper client.
impl Upstream for AppState {
    type Request = Request;
    type Response = Response;

    async fn forward(&self, req: Request, _kind: ForwardKind) -> Response {
        forward(self, req).await
    }

    fn status(&self, resp: &Response) -> u16 {
        resp.status().as_u16()
    }
}
