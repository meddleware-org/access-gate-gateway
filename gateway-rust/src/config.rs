//! Configuration of the native server. The shared part (origin, network, upstream, NFT type, gate,
//! windows, limits, credentials) is `nft_gate_core::config::GatewayConfig`, validated once for every
//! platform; this module adds only what a long-lived process has and a Worker does not: the listen
//! address, the connection limits, the trusted-proxy count and the Redis store.
//!
//! Native-only variables (all validated like the shared ones: a typo is an error, never a silent
//! fall-back to a weaker mode):
//!
//! - `BIND_ADDR` — TCP listen address (default: `0.0.0.0:8080`).
//! - `REDIS_URL` — Redis/Dragonfly URL for fleet-wide replay protection (default: unset →
//!   in-memory store, correct only at `replicas: 1`). `SINGLE_USE=true` requires it (a restart or a
//!   second replica would otherwise forget spent consumes), unless `ALLOW_VOLATILE_REDEMPTIONS=true`
//!   accepts that for development.
//! - `NONCE_PRUNE_INTERVAL_SECS` — background prune cadence for the in-memory store (default: `60`).
//! - `HEADER_READ_TIMEOUT_SECS` — slow-client head limit (default: `10`).
//! - `MAX_CONNECTIONS` — open client connections (default: `1024`).
//! - `SHUTDOWN_GRACE_SECS` — how long in-flight requests may finish after SIGTERM (default: `30`).
//! - `MAX_CONCURRENT_REQUESTS` — in-flight request cap; excess requests get `503` at once
//!   (default: `64`). Peak body memory ≈ `2 × MAX_BODY_BYTES × MAX_CONCURRENT_REQUESTS`.
//! - `TRUSTED_PROXY_HOPS` — reverse proxies in front of the gateway (default: `0` → the TCP peer
//!   address is the client IP). With N > 0 the client IP is the Nth `X-Forwarded-For` entry from
//!   the right, i.e. the address the outermost trusted proxy saw.
//!
//! The shared variables are documented in `nft_gate_core::config`.

use nft_gate_core::config::{boolean, int, Env, GatewayConfig};
use std::net::SocketAddr;

pub use nft_gate_core::config::AuthHeader;

/// Configuration read from the process environment.
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    /// The configuration every platform shares.
    pub gateway: GatewayConfig,
    /// Address to bind the HTTP server to.
    pub bind_addr: SocketAddr,
    /// Optional Redis/Dragonfly URL for a shared TTL nonce store (fleet-wide replay
    /// protection). When unset, an in-memory store is used (correct only at 1 replica).
    pub redis_url: Option<String>,
    /// Background prune interval for the in-memory nonce store (seconds).
    pub nonce_prune_interval_secs: u64,
    /// Single-use without Redis: accept that redemptions are forgotten on restart (development).
    pub allow_volatile_redemptions: bool,
    /// Slow-client limits and connection cap.
    pub header_read_timeout_secs: u64,
    pub max_connections: usize,
    pub shutdown_grace_secs: u64,
    /// In-flight request cap (load-shed beyond it).
    pub max_concurrent_requests: usize,
    /// Number of trusted reverse proxies in front of the gateway (client-IP derivation).
    pub trusted_proxy_hops: usize,
}

/// Hand-written so logs never carry credentials: the Redis URL (which may embed a password) is
/// redacted, and the shared part redacts its own.
impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("gateway", &self.gateway)
            .field("bind_addr", &self.bind_addr)
            .field("redis_url", &self.redis_url.as_ref().map(|_| "<redacted>"))
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("trusted_proxy_hops", &self.trusted_proxy_hops)
            .finish_non_exhaustive()
    }
}

impl ServerConfig {
    /// Load configuration from the process environment.
    ///
    /// # Errors
    ///
    /// Returns an error if any required variable is absent or invalid, or any optional one is
    /// malformed or out of range.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(&ProcessEnv)
    }

    /// [`from_env`](Self::from_env) over an arbitrary variable lookup (so tests need no process env).
    pub fn from_lookup(env: &dyn Env) -> anyhow::Result<Self> {
        let gateway = GatewayConfig::from_env(env)?;
        let bind_addr: SocketAddr = env
            .get("BIND_ADDR")
            .unwrap_or_else(|| "0.0.0.0:8080".to_string())
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid BIND_ADDR: {e}"))?;
        let redis_url = env.get("REDIS_URL").filter(|s| !s.is_empty());
        let allow_volatile_redemptions = boolean(env, "ALLOW_VOLATILE_REDEMPTIONS", false)?;
        if gateway.single_use && redis_url.is_none() && !allow_volatile_redemptions {
            anyhow::bail!(
                "SINGLE_USE=true requires REDIS_URL: an in-memory store forgets spent consumes on restart \
                 (set ALLOW_VOLATILE_REDEMPTIONS=true for development)"
            );
        }
        Ok(Self {
            gateway,
            bind_addr,
            redis_url,
            nonce_prune_interval_secs: int(env, "NONCE_PRUNE_INTERVAL_SECS", 60, 1, 86_400)?,
            allow_volatile_redemptions,
            header_read_timeout_secs: int(env, "HEADER_READ_TIMEOUT_SECS", 10, 1, 300)?,
            max_connections: int(env, "MAX_CONNECTIONS", 1024, 1, 1_000_000)?,
            shutdown_grace_secs: int(env, "SHUTDOWN_GRACE_SECS", 30, 1, 3600)?,
            max_concurrent_requests: int(env, "MAX_CONCURRENT_REQUESTS", 64, 1, 100_000)?,
            trusted_proxy_hops: int(env, "TRUSTED_PROXY_HOPS", 0, 0, 16)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base() -> HashMap<&'static str, String> {
        HashMap::from([
            ("GATEWAY_ORIGIN", "https://gateway.example.com".to_string()),
            ("NETWORK", "testnet".to_string()),
            (
                "UPSTREAM_URL",
                "https://relay-origin.example.com".to_string(),
            ),
            (
                "SUI_RPC_URL",
                "https://fullnode.testnet.sui.io:443".to_string(),
            ),
            ("NFT_TYPE", "0x1::access_gate::AccessNFT".to_string()),
            ("GATE_ID", "0x2".to_string()),
        ])
    }

    fn load(extra: &[(&'static str, &str)]) -> anyhow::Result<ServerConfig> {
        let mut env = base();
        for (k, v) in extra {
            if v == &"<unset>" {
                env.remove(k);
            } else {
                env.insert(k, v.to_string());
            }
        }
        ServerConfig::from_lookup(&|k: &str| env.get(k).cloned())
    }

    fn err(extra: &[(&'static str, &str)]) -> String {
        load(extra).err().unwrap().to_string()
    }

    #[test]
    fn defaults_load() {
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.bind_addr, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(cfg.redis_url, None);
        assert_eq!(cfg.max_concurrent_requests, 64);
        assert_eq!(cfg.trusted_proxy_hops, 0);
        assert_eq!(cfg.gateway.network, "testnet");
    }

    #[test]
    fn shared_validation_still_applies_to_the_server() {
        assert!(err(&[("GATEWAY_ORIGIN", "<unset>")]).contains("GATEWAY_ORIGIN"));
        assert!(err(&[("SINGLE_USE", "yes")]).contains("SINGLE_USE"));
    }

    #[test]
    fn a_typo_in_a_native_variable_never_selects_a_weaker_mode() {
        for (key, bad) in [
            ("TRUSTED_PROXY_HOPS", "-1"),
            ("TRUSTED_PROXY_HOPS", "17"),
            ("MAX_CONNECTIONS", "0"),
            ("MAX_CONCURRENT_REQUESTS", "0"),
            ("SHUTDOWN_GRACE_SECS", "0"),
            ("HEADER_READ_TIMEOUT_SECS", "301"),
            ("NONCE_PRUNE_INTERVAL_SECS", "1.5"),
            ("BIND_ADDR", "everywhere"),
            ("ALLOW_VOLATILE_REDEMPTIONS", "1"),
        ] {
            assert!(err(&[(key, bad)]).contains(key), "{key}={bad}");
        }
    }

    #[test]
    fn single_use_needs_a_durable_store() {
        assert!(err(&[("SINGLE_USE", "true")]).contains("REDIS_URL"));
        assert!(load(&[("SINGLE_USE", "true"), ("REDIS_URL", "redis://r:6379")]).is_ok());
        assert!(load(&[
            ("SINGLE_USE", "true"),
            ("ALLOW_VOLATILE_REDEMPTIONS", "true")
        ])
        .is_ok());
        // An empty REDIS_URL is no URL.
        assert!(err(&[("SINGLE_USE", "true"), ("REDIS_URL", "")]).contains("REDIS_URL"));
    }

    #[test]
    fn debug_redacts_credentials() {
        let cfg = load(&[("REDIS_URL", "redis://:hunter2@redis:6379")]).unwrap();
        let out = format!("{cfg:?}");
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("<redacted>"));
    }
}
