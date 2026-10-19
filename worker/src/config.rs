//! Worker configuration: the core's validated [`GatewayConfig`] plus the Worker-only variables.
//! All validation rules are the core's (`nft_gate_core::config`); this file only reads the
//! variables that exist on Cloudflare alone.
//!
//! | Variable | Meaning | Default |
//! | --- | --- | --- |
//! | `NONCE_SHARD` | `region` (one Durable Object per continent) or `global` | `region` |
//! | `PUBLIC_RATE_LIMIT_PER_MIN` | per-IP budget for public paths (0 disables) | `120` |
//! | `PUBLIC_CACHE_TTL_SECS` | edge-cache TTL for public GETs (0 disables) | `60` |
//! | `QUOTA_GUARD_ENABLED` | the scheduled quota guard | `false` |
//! | `WORKERS_PLAN` | `free` or `paid` | `free` |
//! | `NONCE_BACKEND` | only `durable-object` is accepted (the KV backend is not carried over) | unset |

use nft_gate_core::config::{boolean, int, Env, GatewayConfig};
use nft_gate_core::quota::{parse_workers_plan, WorkersPlan};

/// Everything the Worker reads at startup.
#[derive(Clone)]
pub struct WorkerConfig {
    pub core: GatewayConfig,
    /// `NONCE_SHARD=global`: one shard for everything.
    pub shard_global: bool,
    pub public_rate_limit_per_min: u32,
    pub public_cache_ttl_secs: u64,
    #[allow(dead_code)] // validated here so a typo fails at startup; the scheduled handler reads its own env
    pub quota_guard_enabled: bool,
    #[allow(dead_code)] // as above
    pub workers_plan: WorkersPlan,
}

impl WorkerConfig {
    /// Load and validate. Any missing or malformed variable is an error (the Worker then answers
    /// `500 gateway misconfigured` and logs the reason; the client learns nothing).
    pub fn load(env: &dyn Env) -> anyhow::Result<Self> {
        let core = GatewayConfig::from_env(env)?;
        match env.get("NONCE_BACKEND").as_deref() {
            None | Some("durable-object") => {}
            Some("kv") => anyhow::bail!(
                "NONCE_BACKEND=kv is not supported by the Rust Worker (Durable Objects only)"
            ),
            Some(_) => anyhow::bail!("NONCE_BACKEND must be durable-object"),
        }
        let shard_global = match env.get("NONCE_SHARD").as_deref() {
            None | Some("region") => false,
            Some("global") => true,
            Some(_) => anyhow::bail!("NONCE_SHARD must be one of region, global"),
        };
        Ok(Self {
            core,
            shard_global,
            public_rate_limit_per_min: int(env, "PUBLIC_RATE_LIMIT_PER_MIN", 120, 0, 1_000_000)?,
            public_cache_ttl_secs: int(env, "PUBLIC_CACHE_TTL_SECS", 60, 0, 86_400)?,
            quota_guard_enabled: boolean(env, "QUOTA_GUARD_ENABLED", false)?,
            workers_plan: parse_workers_plan(env.get("WORKERS_PLAN").as_deref())?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base() -> HashMap<&'static str, String> {
        HashMap::from([
            ("GATEWAY_ORIGIN", "https://gw.example".to_string()),
            ("NETWORK", "testnet".to_string()),
            ("UPSTREAM_URL", "https://relay.example".to_string()),
            ("SUI_RPC_URL", "https://rpc.example".to_string()),
            ("NFT_TYPE", "0x1::access_gate::SoulboundAccessNFT".to_string()),
            ("GATE_ID", "0x2".to_string()),
        ])
    }

    fn load(extra: &[(&'static str, &str)]) -> anyhow::Result<WorkerConfig> {
        let mut env = base();
        for (k, v) in extra {
            env.insert(k, (*v).to_string());
        }
        WorkerConfig::load(&|k: &str| env.get(k).cloned())
    }

    #[test]
    fn defaults_match_wrangler_toml_semantics() {
        let c = load(&[]).unwrap();
        assert!(!c.shard_global && !c.quota_guard_enabled && !c.core.single_use);
        assert_eq!(
            (c.public_rate_limit_per_min, c.public_cache_ttl_secs),
            (120, 60)
        );
        assert_eq!(c.workers_plan, WorkersPlan::Free);
    }

    #[test]
    fn worker_only_variables_are_strict() {
        for (k, v) in [
            ("NONCE_SHARD", "continent"),
            ("QUOTA_GUARD_ENABLED", "TRUE"),
            ("WORKERS_PLAN", "pro"),
            ("PUBLIC_RATE_LIMIT_PER_MIN", "-1"),
            ("PUBLIC_CACHE_TTL_SECS", "86401"),
            ("NONCE_BACKEND", "redis"),
        ] {
            assert!(load(&[(k, v)]).is_err(), "{k}={v}");
        }
        assert!(load(&[("NONCE_SHARD", "global")]).unwrap().shard_global);
        assert!(load(&[("NONCE_BACKEND", "durable-object")]).is_ok());
    }

    #[test]
    fn the_kv_backend_is_refused_with_a_clear_message() {
        let e = load(&[("NONCE_BACKEND", "kv")]).err().unwrap().to_string();
        assert!(e.contains("not supported"), "{e}");
    }

    #[test]
    fn the_core_rules_apply() {
        // Loopback http needs the explicit opt-in (stricter than the TypeScript Worker).
        assert!(load(&[("UPSTREAM_URL", "http://127.0.0.1:1")]).is_err());
        assert!(load(&[("UPSTREAM_URL", "http://127.0.0.1:1"), ("ALLOW_INSECURE_HTTP", "1")]).is_ok());
    }
}
