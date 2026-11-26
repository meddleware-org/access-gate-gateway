//! gRPC-web codec and chain client: moved to `access-gate-gateway-core` (shared with the Worker). This module keeps
//! only the hyper-backed [`Transport`].
use crate::config::AuthHeader;
use crate::http_client::HttpClient;
pub use access_gate_gateway_core::grpc::*;
use bytes::Bytes;
use std::time::Duration;

/// [`Transport`] over the shared hyper-rustls [`HttpClient`].
pub struct HyperTransport {
    /// The shared HTTP client.
    http: HttpClient,
    /// The credential header sent with every node call, if one is configured.
    auth: Option<AuthHeader>,
    /// The deadline for one call.
    timeout: Duration,
}

impl HyperTransport {
    /// A transport over the shared client.
    pub fn new(http: HttpClient, auth: Option<AuthHeader>, timeout: Duration) -> Self {
        Self {
            http,
            auth,
            timeout,
        }
    }
}

impl Transport for HyperTransport {
    /// POST one gRPC-web frame through the shared HTTP client and return the `grpc-status` header (if any) with the body.
    async fn post_grpc_web(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<(Option<String>, Vec<u8>)> {
        let (headers, bytes) = self
            .http
            // The optional RPC credential header is attached inside the client, never built into the URL.
            .post_grpc_web(url, Bytes::from(body), self.auth.as_ref(), self.timeout)
            .await?;
        let status = headers
            .get("grpc-status")
            // A status that is not valid text is treated as absent, which the caller reports as a missing status.
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        Ok((status, bytes.to_vec()))
    }

    /// Sleep without blocking the runtime.
    async fn sleep_ms(&self, ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    /// Wall-clock milliseconds, the same source the state module uses.
    fn now_ms(&self) -> u64 {
        crate::state::wall_ms()
    }
}
