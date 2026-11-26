//! Thin async HTTP client for Sui RPC calls and upstream proxy forwarding.
//!
//! Uses hyper 1.x + hyper-rustls directly instead of reqwest to avoid the
//! `url → idna → icu_normalizer` compile-time dep chain (~10 min on GHA).
//! All URLs here are operator-configured ASCII-domain strings; `hyper::Uri`
//! handles them without any IDNA processing.
//!
//! Every call is bounded: a connect timeout, a whole-request timeout (headers **and** body), and a
//! response-size cap, so a slow or hostile peer can neither hold a task forever nor exhaust memory.

use crate::config::AuthHeader;
use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use hyper::Request;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;
use std::time::Duration;

/// The rustls HTTPS connector over a plain TCP connector.
type Connector = HttpsConnector<HttpConnector>;

/// TCP connect timeout for every outbound call.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on a gRPC-web response body (the gateway reads small messages only).
pub const MAX_RPC_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// The upstream (or RPC) did not finish within its deadline; the proxy answers 504 for it.
#[derive(Debug)]
pub struct TimedOut;

impl std::fmt::Display for TimedOut {
    /// Show a fixed message, never the URL or the response, so a log line cannot carry a credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("request timed out")
    }
}

impl std::error::Error for TimedOut {}

/// Response from a proxied upstream request.
pub struct ProxyResponse {
    /// The upstream's status.
    pub status: StatusCode,
    /// The upstream's headers, before the response policy is applied.
    pub headers: HeaderMap,
    /// The upstream's body, read within the size cap.
    pub body: Bytes,
}

/// Shared async HTTP client (cheap to clone — inner client is `Arc`-backed).
#[derive(Clone)]
pub struct HttpClient {
    /// The hyper client.
    inner: Client<Connector, Full<Bytes>>,
}

/// Add `h` to `headers` (validated at config load; a failure here is a programming error surfaced
/// as a request error, never a panic).
fn insert_auth(headers: &mut HeaderMap, h: &AuthHeader) -> anyhow::Result<()> {
    let name = HeaderName::from_bytes(h.name.as_bytes()).context("invalid auth header name")?;
    let value = HeaderValue::from_str(&h.value).context("invalid auth header value")?;
    headers.insert(name, value);
    Ok(())
}

impl HttpClient {
    /// Build a new client backed by rustls with bundled WebPKI/Mozilla root certificates. The
    /// URL schemes are policed at config load (`https://` unless `ALLOW_INSECURE_HTTP=1`).
    pub fn new() -> anyhow::Result<Self> {
        let mut http = HttpConnector::new();
        // Let the connector handle `https` URLs too; the scheme policy is applied when the configuration loads.
        http.enforce_http(false);
        // A connect that never completes would otherwise hold the request until its overall timeout.
        http.set_connect_timeout(Some(CONNECT_TIMEOUT));
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            // Bundled root certificates: the image needs no system certificate store.
            .with_webpki_roots()
            // `http` is allowed here because `ALLOW_INSECURE_HTTP` lets an operator opt into it for local and in-cluster addresses.
            .https_or_http()
            // Sui full nodes serve gRPC-web over HTTP/1.1.
            .enable_http1()
            .wrap_connector(http);
        let inner = Client::builder(TokioExecutor::new()).build(https);
        Ok(Self { inner })
    }

    /// Send `req` and collect at most `max_body` bytes of the response, all within `timeout`.
    async fn send(
        &self,
        req: Request<Full<Bytes>>,
        timeout: Duration,
        max_body: usize,
        what: &str,
    ) -> anyhow::Result<(StatusCode, HeaderMap, Bytes)> {
        let fut = async {
            let resp = self
                .inner
                .request(req)
                .await
                .with_context(|| format!("{what} request failed"))?;
            let status = resp.status();
            let headers = resp.headers().clone();
            // The body is read through a size limit, so a large or endless response cannot exhaust memory.
            let body = Limited::new(resp.into_body(), max_body)
                .collect()
                .await
                .map_err(|e| {
                    anyhow::anyhow!("reading {what} response (cap {max_body} bytes): {e}")
                })?
                .to_bytes();
            Ok::<_, anyhow::Error>((status, headers, body))
        };
        // One deadline for the whole exchange: connect, headers and body.
        match tokio::time::timeout(timeout, fut).await {
            Ok(r) => r,
            Err(_) => {
                tracing::warn!(what, secs = timeout.as_secs(), "request timed out");
                Err(anyhow::Error::new(TimedOut))
            }
        }
    }

    /// POST an already gRPC-web-framed `body` to `url` with the `application/grpc-web+proto`
    /// content type and return the raw response body (a message frame plus a trailer frame — the
    /// caller unframes it; see `grpc::unframe`). Sui full nodes serve gRPC-web over HTTP/1.1.
    pub async fn post_grpc_web(
        &self,
        url: &str,
        body: Bytes,
        auth: Option<&AuthHeader>,
        timeout: Duration,
    ) -> anyhow::Result<(HeaderMap, Bytes)> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(header::CONTENT_TYPE, "application/grpc-web+proto")
            .header(header::ACCEPT, "application/grpc-web+proto")
            .body(Full::new(body))
            .context("failed to build gRPC-web request")?;
        if let Some(h) = auth {
            // `insert` replaces, so a header the client sent with the same name cannot survive.
            insert_auth(req.headers_mut(), h)?;
        }
        let (status, headers, bytes) = self
            .send(req, timeout, MAX_RPC_RESPONSE_BYTES, "gRPC-web")
            .await?;
        if !status.is_success() {
            // Only the status is reported: the response body of a failing node is not repeated.
            anyhow::bail!("gRPC-web HTTP {status}");
        }
        Ok((headers, bytes))
    }

    /// Forward a request to `url`, preserving the method, headers, and body, adding `auth`
    /// headers (which replace any client-supplied header of the same name).
    #[allow(clippy::too_many_arguments)]
    pub async fn forward(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Bytes,
        auth: &[AuthHeader],
        timeout: Duration,
        max_response: usize,
    ) -> anyhow::Result<ProxyResponse> {
        let mut builder = Request::builder().method(method).uri(url);
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        let mut req = builder
            .body(Full::new(body))
            .context("failed to build proxy request")?;
        for h in auth {
            insert_auth(req.headers_mut(), h)?;
        }
        let (status, headers, body) = self.send(req, timeout, max_response, "upstream").await?;
        Ok(ProxyResponse {
            status,
            headers,
            body,
        })
    }
}
