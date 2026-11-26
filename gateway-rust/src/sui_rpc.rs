//! Production [`ChainQuery`]: the chain logic moved to `access-gate-gateway-core::chain` (generic over a
//! `Transport`, shared with the Cloudflare Worker); this module binds it to the hyper client.

use crate::config::AuthHeader;
use crate::grpc::HyperTransport;
use crate::http_client::HttpClient;
use std::time::Duration;

/// The native chain client.
pub type SuiRpc = access_gate_gateway_core::chain::SuiRpc<HyperTransport>;

/// Create a new client. `rpc_url` is the full-node origin; `cache_ttl_ms` `0` disables the ownership cache.
pub fn new_sui_rpc(
    client: HttpClient,
    rpc_url: String,
    cache_ttl_ms: u64,
    auth: Option<AuthHeader>,
    timeout: Duration,
) -> SuiRpc {
    access_gate_gateway_core::chain::SuiRpc::new(
        // The transport carries the shared client, the optional RPC credential and the per-call deadline.
        HyperTransport::new(client, auth, timeout),
        rpc_url,
        cache_ttl_ms,
        timeout.as_millis() as u64,
    )
}
