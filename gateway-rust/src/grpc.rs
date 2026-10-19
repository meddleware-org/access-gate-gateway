//! gRPC-web codec and chain client: moved to `nft-gate-core` (shared with the Worker). This module keeps
//! only the hyper-backed [`Transport`].
use crate::config::AuthHeader;
use crate::http_client::HttpClient;
use bytes::Bytes;
pub use nft_gate_core::grpc::*;
use std::time::Duration;

/// [`Transport`] over the shared hyper-rustls [`HttpClient`].
pub struct HyperTransport {
    http: HttpClient,
    auth: Option<AuthHeader>,
    timeout: Duration,
}

impl HyperTransport {
    pub fn new(http: HttpClient, auth: Option<AuthHeader>, timeout: Duration) -> Self {
        Self { http, auth, timeout }
    }
}

impl Transport for HyperTransport {
    async fn post_grpc_web(&self, url: &str, body: Vec<u8>) -> anyhow::Result<(Option<String>, Vec<u8>)> {
        let (headers, bytes) = self
            .http
            .post_grpc_web(url, Bytes::from(body), self.auth.as_ref(), self.timeout)
            .await?;
        let status = headers.get("grpc-status").and_then(|v| v.to_str().ok()).map(str::to_string);
        Ok((status, bytes.to_vec()))
    }

    async fn sleep_ms(&self, ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64)
    }
}
