//! Gateway configuration shared by every platform, read through the [`Env`] trait (process
//! environment natively, Worker `vars`/secrets in a Worker). Nothing here is consumer-specific: the
//! same logic fronts an upload relay, a website, a game API, etc.
//!
//! This is the one place the validation rules live. The two former implementations (the Rust
//! `config.rs` and the TypeScript `config.ts`) disagreed in a few places; the stricter rule won in
//! each (listed in `core/README.md`). Platform-only variables (`BIND_ADDR`, `REDIS_URL`,
//! `TRUSTED_PROXY_HOPS`, the connection limits; the Worker's `NONCE_SHARD`, `WORKERS_PLAN`,
//! `PUBLIC_*`, quota guard) are parsed by the platform crate with the helpers below ([`int`],
//! [`boolean`], [`required`]).
//!
//! # Environment variables
//!
//! Every value is validated at startup: a typo (an unknown boolean, a negative or fractional number, a
//! malformed origin) is an error, never a silent fall-back to a weaker mode.
//!
//! Required:
//! - `GATEWAY_ORIGIN` — the canonical public origin of THIS gateway (`https://host`, no path,
//!   lower-case). Signed into every access proof (`access-gate-gateway:access:v3`), so a proof made for another
//!   gateway is useless here.
//! - `NETWORK` — `localnet` | `devnet` | `testnet` | `mainnet`; signed into every access proof.
//! - `UPSTREAM_URL` — base URL of the upstream this gateway protects (trailing `/` stripped).
//! - `SUI_RPC_URL` — Sui fullnode (queried over gRPC-web) for ownership / event / gate queries.
//! - `NFT_TYPE` — the access_gate pass type: `<pkg>::access_gate::AccessNFT` or
//!   `<pkg>::access_gate::SoulboundAccessNFT` (anything else, e.g. a fungible `Coin<T>`, is rejected).
//! - `GATE_ID` — the gate whose passes are accepted (object ID).
//!
//! Optional (with defaults):
//! - `CHALLENGE_TTL_SECS` — nonce lifetime in seconds (default: `300`).
//! - `SINGLE_USE` — `true` to require an on-chain single-use consume (default: `false`).
//! - `GATED_PREAUTH_RATE_LIMIT_PER_MIN` — per-client-IP budget for gated requests, checked before
//!   signature verification, 0 to disable (default: `120`).
//! - `CONSUME_MAX_AGE_SECS` — single-use: oldest consume accepted, seconds since its event
//!   (default: `432000` = 5 days, inside public fullnodes' transaction retention); at most
//!   `REDEMPTION_RETENTION_SECS`.
//! - `RPC_TIMEOUT_SECS` — deadline for each Sui RPC call (default: `15`).
//! - `BODY_READ_TIMEOUT_SECS` — slow-client body limit (default: `30`).
//! - `PUBLIC_PATHS` — comma-separated paths proxied without auth (default: `/v1/tip-config`).
//! - `RATE_LIMIT_PER_MIN` — per-address request budget per minute, 0 to disable (default: `30`).
//! - `CHALLENGE_RATE_LIMIT_PER_MIN` — per-IP budget for the challenge endpoint per minute, 0 to
//!   disable (default: `30`).
//! - `MAX_BODY_BYTES` — request body cap in bytes before proxying (default: `262144`).
//! - `NONCE_MAX_ENTRIES` — hard cap on live nonces / redemptions per store (default: `1000000`).
//! - `OWNERSHIP_CACHE_TTL_MS` — ownership-cache TTL in ms, 0 to disable (default: `0`).
//! - `REDEMPTION_LEASE_TTL_SECS` — single-use: lease window for an in-flight consume-digest
//!   redemption (default: `900`); must exceed `UPSTREAM_TIMEOUT_SECS + BODY_READ_TIMEOUT_SECS`.
//! - `REDEMPTION_RETENTION_SECS` — single-use: how long a committed (spent) consume-digest is
//!   remembered to block re-redemption (default: `2592000` = 30 days).
//! - `UPSTREAM_TIMEOUT_SECS` — whole-request timeout for upstream calls (default: `600`).
//! - `ALLOWED_ORIGINS` — comma-separated canonical browser origins allowed to call the gateway (CORS;
//!   e.g. `https://app.example`). Unset → none: browsers get no `Access-Control-Allow-Origin` grant.
//! - `MAX_RESPONSE_BYTES` — cap on a buffered upstream response (default: `16777216` = 16 MiB).
//! - `ALLOW_INSECURE_HTTP` — `1` permits `http://` for `UPSTREAM_URL` / `SUI_RPC_URL` /
//!   `GATEWAY_ORIGIN` / `ALLOWED_ORIGINS` (localnet or an in-cluster upstream); otherwise all must be
//!   `https://` (default: unset).
//! - `UPSTREAM_AUTH_HEADERS` — JSON array `[{"name":…,"value":…}]` of headers added to every
//!   upstream request (secret).
//! - `SUI_RPC_AUTH_HEADER` — one `Name: value` header added to every Sui RPC call (secret).

use crate::origin::{is_canonical_origin, normalized_origin};
use crate::proof::NETWORKS;

/// Where configuration comes from: environment variables, Worker bindings, a map in a test.
pub trait Env {
    /// The raw value of `key`, or `None` when it is unset.
    fn get(&self, key: &str) -> Option<String>;
}

impl<F: Fn(&str) -> Option<String>> Env for F {
    fn get(&self, key: &str) -> Option<String> {
        self(key)
    }
}

/// An extra header the gateway sends (credentials for the upstream or the RPC).
#[derive(Clone)]
pub struct AuthHeader {
    pub name: String,
    pub value: String,
}

/// The configuration every platform shares.
#[derive(Clone)]
pub struct GatewayConfig {
    /// Canonical origin of this gateway, signed into every access proof.
    pub gateway_origin: String,
    /// The Sui network, signed into every access proof (one of [`NETWORKS`]).
    pub network: String,
    /// Base URL of the upstream this gateway protects (e.g. the stock upload relay).
    pub upstream_url: String,
    /// Sui fullnode (gRPC-web) used for ownership / event / gate queries.
    pub sui_rpc_url: String,
    /// Fully-qualified access-NFT type string to gate on.
    pub nft_type: String,
    /// The gate whose passes are accepted.
    pub gate_id: String,
    /// Challenge validity window.
    pub challenge_ttl_secs: u64,
    /// When true, require an on-chain single-use consume.
    pub single_use: bool,
    /// Paths served WITHOUT auth (proxied straight through), e.g. `/v1/tip-config`.
    pub public_paths: Vec<String>,
    /// Browser origins granted CORS (exact match); empty → none.
    pub allowed_origins: Vec<String>,
    /// Per-address request budget per minute (post-auth).
    pub rate_limit_per_min: u32,
    /// Per-IP request budget for the challenge endpoint per minute (pre-auth).
    pub challenge_rate_limit_per_min: u32,
    /// Per-IP request budget for gated requests per minute, checked before verification.
    pub gated_preauth_rate_limit_per_min: u32,
    /// Maximum request body accepted before proxying (bytes).
    pub max_body_bytes: usize,
    /// Hard cap on live nonces and redemptions in one store (evict-soonest-to-expire beyond it).
    pub nonce_max_entries: usize,
    /// Ownership-cache TTL in ms. **0 = disabled (live check every request)** — the default,
    /// so a gated action is always confirmed on-chain. A small positive value collapses
    /// duplicate lookups under load at the cost of a brief staleness window on NFT
    /// transfer/burn. Never applied to the single-use consume-event check (always live).
    pub ownership_cache_ttl_ms: u64,
    /// Single-use: lease window (secs) for an in-flight consume-digest redemption.
    pub redemption_lease_ttl_secs: u64,
    /// Single-use: retention (secs) of a committed (spent) consume-digest.
    pub redemption_retention_secs: u64,
    /// Single-use: oldest accepted consume (secs since its event); at most the retention.
    pub consume_max_age_secs: u64,
    /// Deadline for each Sui RPC call (secs).
    pub rpc_timeout_secs: u64,
    /// Deadline for reading a client's request body (secs).
    pub body_read_timeout_secs: u64,
    /// Whole-request timeout for upstream calls (secs).
    pub upstream_timeout_secs: u64,
    /// Cap on a buffered upstream response (bytes).
    pub max_response_bytes: usize,
    /// `ALLOW_INSECURE_HTTP=1`: `http://` is accepted where `https://` is otherwise required.
    pub allow_insecure_http: bool,
    /// Headers added to every upstream request (e.g. a Cloudflare Access service token).
    pub upstream_auth_headers: Vec<AuthHeader>,
    /// Header added to every Sui RPC call (authenticated RPC providers).
    pub sui_rpc_auth_header: Option<AuthHeader>,
}

/// Hand-written so logs never carry credentials or the private origin: header values, the upstream URL
/// and the RPC URL are redacted.
impl std::fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self
            .upstream_auth_headers
            .iter()
            .map(|h| h.name.as_str())
            .collect();
        f.debug_struct("GatewayConfig")
            .field("gateway_origin", &self.gateway_origin)
            .field("network", &self.network)
            // The private origin is not logged (audit F26), and an RPC URL may carry a key in its
            // path: neither is printed.
            .field("upstream_url", &"<redacted>")
            .field("sui_rpc_url", &"<redacted>")
            .field("nft_type", &self.nft_type)
            .field("gate_id", &self.gate_id)
            .field("single_use", &self.single_use)
            .field("public_paths", &self.public_paths)
            .field("allowed_origins", &self.allowed_origins)
            .field("upstream_auth_headers", &names)
            .field(
                "sui_rpc_auth_header",
                &self.sui_rpc_auth_header.as_ref().map(|h| h.name.as_str()),
            )
            .field("max_body_bytes", &self.max_body_bytes)
            .finish_non_exhaustive()
    }
}

/// True if `name` is an HTTP field name (RFC 9110 token).
fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Parse `UPSTREAM_AUTH_HEADERS` (JSON array of `{name, value}`). Malformed input is an error so
/// a mistyped secret fails at startup instead of silently dropping the upstream credentials.
pub fn parse_upstream_auth_headers(raw: Option<&str>) -> anyhow::Result<Vec<AuthHeader>> {
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    let err = || {
        anyhow::anyhow!(
            "UPSTREAM_AUTH_HEADERS must be a JSON array of {{\"name\",\"value\"}} objects"
        )
    };
    let v: serde_json::Value = serde_json::from_str(raw).map_err(|_| err())?;
    let items = v.as_array().ok_or_else(err)?;
    items
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let name = h["name"].as_str().filter(|n| is_header_name(n));
            let value = h["value"]
                .as_str()
                .filter(|v| !v.contains('\r') && !v.contains('\n'));
            match (name, value) {
                (Some(name), Some(value)) => Ok(AuthHeader {
                    name: name.to_string(),
                    value: value.to_string(),
                }),
                _ => Err(anyhow::anyhow!(
                    "UPSTREAM_AUTH_HEADERS[{i}] must be {{\"name\": <header name>, \"value\": <string>}}"
                )),
            }
        })
        .collect()
}

/// Parse `SUI_RPC_AUTH_HEADER`: `Name: value`. A bare value is refused (it used to be sent as
/// `Authorization`, a guess the operator could not see), as are a bad header name and line breaks.
pub fn parse_rpc_auth_header(raw: Option<&str>) -> anyhow::Result<Option<AuthHeader>> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    match raw.split_once(':') {
        Some((n, v))
            if is_header_name(n.trim())
                && !v.trim().is_empty()
                && !v.contains('\r')
                && !v.contains('\n') =>
        {
            Ok(Some(AuthHeader {
                name: n.trim().to_string(),
                value: v.trim().to_string(),
            }))
        }
        _ => anyhow::bail!("SUI_RPC_AUTH_HEADER must be \"Name: value\""),
    }
}

/// Require `https://` unless `allow_http` (localnet / in-cluster) permits `http://`; refuse
/// credentials in the URL (userinfo: they have their own redacted channels, `UPSTREAM_AUTH_HEADERS`
/// and `SUI_RPC_AUTH_HEADER`), an empty host, and whitespace, control characters or backslashes.
pub fn check_scheme(var: &str, url: &str, allow_http: bool) -> anyhow::Result<()> {
    if url.starts_with("https://") || (allow_http && url.starts_with("http://")) {
        let after = url.find("://").map_or(0, |i| i + 3);
        let authority = url[after..].split(['/', '?', '#']).next().unwrap_or("");
        if authority.contains('@') {
            anyhow::bail!("{var} must not carry credentials (use the auth header variables)");
        }
        if authority.is_empty() || url.bytes().any(|b| b <= 0x20 || b == 0x7f || b == b'\\') {
            anyhow::bail!("{var} must be a valid http(s) URL");
        }
        Ok(())
    } else if url.starts_with("http://") {
        anyhow::bail!("{var} must use https:// (set ALLOW_INSECURE_HTTP=1 for localnet or an in-cluster upstream)")
    } else {
        anyhow::bail!("{var} must be an http(s) URL")
    }
}

/// The value of a required variable, trimmed; unset or blank is an error.
pub fn required(env: &dyn Env, key: &str) -> anyhow::Result<String> {
    env.get(key)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{key} is required"))
}

/// Strict integer in `[min, max]`: an unset variable is `default`; anything else that is not a plain
/// decimal in range is an error.
pub fn int<T>(env: &dyn Env, key: &str, default: T, min: T, max: T) -> anyhow::Result<T>
where
    T: std::str::FromStr + PartialOrd + std::fmt::Display + Copy,
{
    let Some(raw) = env.get(key) else {
        return Ok(default);
    };
    let raw = raw.trim();
    let bad = || anyhow::anyhow!("{key} must be an integer in [{min}, {max}]");
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let n: T = raw.parse().map_err(|_| bad())?;
    if n < min || n > max {
        return Err(bad());
    }
    Ok(n)
}

/// Strict boolean: exactly `true` or `false`.
pub fn boolean(env: &dyn Env, key: &str, default: bool) -> anyhow::Result<bool> {
    match env.get(key).as_deref() {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => anyhow::bail!("{key} must be \"true\" or \"false\""),
    }
}

/// `PUBLIC_PATHS`: exact absolute paths, free of query, fragment and dot segments.
fn parse_public_paths(raw: &str) -> anyhow::Result<Vec<String>> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|p| {
            let plain = p.starts_with('/')
                && p.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-' | b'/')
                })
                && !p.split('/').any(|seg| seg == ".." || seg == ".");
            if plain {
                Ok(p.to_string())
            } else {
                anyhow::bail!("PUBLIC_PATHS entry is not a plain absolute path: {p}")
            }
        })
        .collect()
}

/// `ALLOWED_ORIGINS`: canonical origins, comma-separated; unset or empty allows none.
fn parse_allowed_origins(raw: &str, allow_http: bool) -> anyhow::Result<Vec<String>> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|o| {
            if is_canonical_origin(o) && (allow_http || o.starts_with("https://")) {
                Ok(o.to_string())
            } else {
                anyhow::bail!("ALLOWED_ORIGINS entry is not a canonical https origin: {o}")
            }
        })
        .collect()
}

/// `ALLOW_INSECURE_HTTP`: `1` (or `0` / empty / unset for off); anything else is an error.
pub fn allow_insecure_http(env: &dyn Env) -> anyhow::Result<bool> {
    match env.get("ALLOW_INSECURE_HTTP").as_deref() {
        None | Some("") | Some("0") => Ok(false),
        Some("1") => Ok(true),
        Some(_) => anyhow::bail!("ALLOW_INSECURE_HTTP must be 1 (or unset)"),
    }
}

impl GatewayConfig {
    /// Load the shared configuration from `env`.
    ///
    /// # Errors
    ///
    /// Returns an error if any required variable is absent or invalid, or any optional one is
    /// malformed or out of range (see the module docs).
    pub fn from_env(env: &dyn Env) -> anyhow::Result<Self> {
        let allow_http = allow_insecure_http(env)?;

        let gateway_origin = required(env, "GATEWAY_ORIGIN")?;
        if !is_canonical_origin(&gateway_origin)
            || (!allow_http && !gateway_origin.starts_with("https://"))
        {
            anyhow::bail!(
                "GATEWAY_ORIGIN must be a canonical https origin (https://host, no path)"
            );
        }
        let network = required(env, "NETWORK")?;
        if !NETWORKS.contains(&network.as_str()) {
            anyhow::bail!("NETWORK must be one of {}", NETWORKS.join(", "));
        }
        let upstream_url = required(env, "UPSTREAM_URL")?
            .trim_end_matches('/')
            .to_string();
        let sui_rpc_url = required(env, "SUI_RPC_URL")?;
        check_scheme("UPSTREAM_URL", &upstream_url, allow_http)?;
        check_scheme("SUI_RPC_URL", &sui_rpc_url, allow_http)?;
        // Compared as origins are (lower-case scheme and host, default port dropped), so a different
        // spelling of this gateway's own address cannot hide a request loop.
        if normalized_origin(&upstream_url) == gateway_origin {
            anyhow::bail!("UPSTREAM_URL must not be this gateway (request loop)");
        }
        let nft_type = required(env, "NFT_TYPE")?;
        if !is_access_gate_pass_type(&nft_type) {
            anyhow::bail!(
                "NFT_TYPE must be <pkg>::access_gate::AccessNFT or <pkg>::access_gate::SoulboundAccessNFT"
            );
        }
        let gate_id = required(env, "GATE_ID")?;
        if !is_object_id(&gate_id) {
            anyhow::bail!("GATE_ID must be a 0x-prefixed object ID");
        }

        let single_use = boolean(env, "SINGLE_USE", false)?;

        let upstream_timeout_secs: u64 = int(env, "UPSTREAM_TIMEOUT_SECS", 600, 1, 3600)?;
        let body_read_timeout_secs: u64 = int(env, "BODY_READ_TIMEOUT_SECS", 30, 1, 3600)?;
        let redemption_lease_ttl_secs: u64 =
            int(env, "REDEMPTION_LEASE_TTL_SECS", 900, 30, 86_400)?;
        // The lease is taken before the body is read and held until the upstream answers, so it
        // must outlive both deadlines (audit F46), or a duplicate could lease the same consume
        // while the first upload is still running.
        if redemption_lease_ttl_secs <= upstream_timeout_secs.saturating_add(body_read_timeout_secs)
        {
            anyhow::bail!(
                "REDEMPTION_LEASE_TTL_SECS must exceed UPSTREAM_TIMEOUT_SECS + BODY_READ_TIMEOUT_SECS (a lease must outlive its whole request)"
            );
        }
        let redemption_retention_secs: u64 = int(
            env,
            "REDEMPTION_RETENTION_SECS",
            2_592_000,
            3600,
            31_536_000,
        )?;
        let consume_max_age_secs: u64 = int(env, "CONSUME_MAX_AGE_SECS", 432_000, 60, 31_536_000)?;
        if consume_max_age_secs > redemption_retention_secs {
            anyhow::bail!(
                "CONSUME_MAX_AGE_SECS must not exceed REDEMPTION_RETENTION_SECS (a spent consume must be remembered while it can be presented)"
            );
        }

        let upstream_auth_headers =
            parse_upstream_auth_headers(env.get("UPSTREAM_AUTH_HEADERS").as_deref())?;
        let sui_rpc_auth_header = parse_rpc_auth_header(env.get("SUI_RPC_AUTH_HEADER").as_deref())?;

        Ok(Self {
            gateway_origin,
            network,
            upstream_url,
            sui_rpc_url,
            nft_type,
            gate_id,
            challenge_ttl_secs: int(env, "CHALLENGE_TTL_SECS", 300, 10, 3600)?,
            single_use,
            public_paths: parse_public_paths(
                &env.get("PUBLIC_PATHS")
                    .unwrap_or_else(|| "/v1/tip-config".to_string()),
            )?,
            allowed_origins: parse_allowed_origins(
                &env.get("ALLOWED_ORIGINS").unwrap_or_default(),
                allow_http,
            )?,
            rate_limit_per_min: int(env, "RATE_LIMIT_PER_MIN", 30, 0, 1_000_000)?,
            challenge_rate_limit_per_min: int(
                env,
                "CHALLENGE_RATE_LIMIT_PER_MIN",
                30,
                0,
                1_000_000,
            )?,
            gated_preauth_rate_limit_per_min: int(
                env,
                "GATED_PREAUTH_RATE_LIMIT_PER_MIN",
                120,
                0,
                1_000_000,
            )?,
            max_body_bytes: int(env, "MAX_BODY_BYTES", 262_144, 1, 1_073_741_824)?,
            nonce_max_entries: int(env, "NONCE_MAX_ENTRIES", 1_000_000, 1, 100_000_000)?,
            ownership_cache_ttl_ms: int(env, "OWNERSHIP_CACHE_TTL_MS", 0, 0, 3_600_000)?,
            redemption_lease_ttl_secs,
            redemption_retention_secs,
            consume_max_age_secs,
            rpc_timeout_secs: int(env, "RPC_TIMEOUT_SECS", 15, 1, 120)?,
            body_read_timeout_secs,
            upstream_timeout_secs,
            max_response_bytes: int(env, "MAX_RESPONSE_BYTES", 16_777_216, 1, 1_073_741_824)?,
            allow_insecure_http: allow_http,
            upstream_auth_headers,
            sui_rpc_auth_header,
        })
    }

    /// Returns `true` if `path` is in the configured public-paths list (proxied without auth,
    /// `GET`/`HEAD` only).
    pub fn is_public_path(&self, path: &str) -> bool {
        self.public_paths.iter().any(|p| p == path)
    }
}

/// `0x` followed by 1–64 hex digits.
pub fn is_object_id(s: &str) -> bool {
    match s.strip_prefix("0x") {
        Some(h) => !h.is_empty() && h.len() <= 64 && h.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

/// `<pkg>::access_gate::AccessNFT` or `<pkg>::access_gate::SoulboundAccessNFT`. Gating on any other
/// type (a fungible `Coin<T>`, an unrelated NFT) would admit holders of objects access_gate never
/// sold, so it is rejected at startup.
pub fn is_access_gate_pass_type(s: &str) -> bool {
    let parts: Vec<&str> = s.split("::").collect();
    parts.len() == 3
        && is_object_id(parts[0])
        && parts[1] == "access_gate"
        && (parts[2] == "AccessNFT" || parts[2] == "SoulboundAccessNFT")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn accepts_only_access_gate_pass_types() {
        assert!(is_access_gate_pass_type("0x1::access_gate::AccessNFT"));
        assert!(is_access_gate_pass_type(
            "0xab::access_gate::SoulboundAccessNFT"
        ));
        for bad in [
            "0x2::coin::Coin<0x2::sui::SUI>",
            "0x1::other::AccessNFT",
            "0x1::access_gate::Gate",
            "AccessNFT",
            "0xzz::access_gate::AccessNFT",
        ] {
            assert!(!is_access_gate_pass_type(bad), "{bad}");
        }
    }

    #[test]
    fn upstream_auth_headers_are_json_only() {
        assert!(parse_upstream_auth_headers(None).unwrap().is_empty());
        assert!(parse_upstream_auth_headers(Some("")).unwrap().is_empty());
        let h = parse_upstream_auth_headers(Some(
            r#"[{"name":"CF-Access-Client-Id","value":"id"},{"name":"CF-Access-Client-Secret","value":"a,b:c"}]"#,
        ))
        .unwrap();
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].value, "id");
        assert_eq!(h[1].value, "a,b:c");
        for bad in [
            "CF-Access-Client-Id: id",
            r#"{"name":"a","value":"b"}"#,
            r#"[{"name":"Bad Name","value":"b"}]"#,
            "[{\"name\":\"X\",\"value\":\"a\\r\\nInjected: 1\"}]",
        ] {
            assert!(parse_upstream_auth_headers(Some(bad)).is_err(), "{bad}");
        }
        // The retired format names the expected one; a bad entry names its index.
        let retired = parse_upstream_auth_headers(Some("CF-Access-Client-Id: abc123"));
        assert!(retired.err().unwrap().to_string().contains("JSON array"));
        let indexed = parse_upstream_auth_headers(Some(r#"[{"name":"Bad Name","value":"b"}]"#));
        assert!(indexed
            .err()
            .unwrap()
            .to_string()
            .contains("UPSTREAM_AUTH_HEADERS[0]"));
    }

    #[test]
    fn rpc_auth_header_forms() {
        let h = parse_rpc_auth_header(Some("X-Api-Key: k:1"))
            .unwrap()
            .unwrap();
        assert_eq!((h.name.as_str(), h.value.as_str()), ("X-Api-Key", "k:1"));
        let h = parse_rpc_auth_header(Some("Authorization: Bearer tok"))
            .unwrap()
            .unwrap();
        assert_eq!(
            (h.name.as_str(), h.value.as_str()),
            ("Authorization", "Bearer tok")
        );
        assert!(parse_rpc_auth_header(Some("")).unwrap().is_none());
        for bad in [
            "Bearer tok",
            "Bad Name: v",
            "X-Key: ",
            "X-Key: a\r\nInjected: 1",
        ] {
            let e = parse_rpc_auth_header(Some(bad)).err().unwrap().to_string();
            assert!(e.contains("SUI_RPC_AUTH_HEADER"), "{bad}: {e}");
        }
    }

    #[test]
    fn urls_must_be_https_unless_allowed() {
        assert!(check_scheme("U", "https://x", false).is_ok());
        assert!(check_scheme("U", "http://x", false).is_err());
        assert!(check_scheme("U", "http://127.0.0.1:9000", true).is_ok());
        assert!(check_scheme("U", "ftp://x", true).is_err());
        assert!(check_scheme("U", "x.example", true).is_err());
    }

    #[test]
    fn urls_must_not_carry_credentials() {
        for bad in [
            "https://user:pass@x.example",
            "https://token@x.example/v1",
            "http://u:p@127.0.0.1:9000",
        ] {
            let e = check_scheme("U", bad, true).unwrap_err().to_string();
            assert!(e.contains("credentials"), "{bad}: {e}");
            assert!(!e.contains("pass") && !e.contains("token@"), "{e}"); // the URL is not echoed
        }
        // An `@` in the path or query is not userinfo.
        assert!(check_scheme("U", "https://x.example/a@b?c=d@e", false).is_ok());
    }

    #[test]
    fn urls_must_have_a_host_and_no_whitespace() {
        // The TypeScript `new URL(...)` refused these; the single implementation does too.
        for bad in [
            "https://",
            "https:///path",
            "https://a b.example",
            "https://a.example/p q",
            "https://a.example\\x",
            "https://a.example/\t",
        ] {
            assert!(check_scheme("U", bad, true).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn debug_redacts_credentials() {
        let mut env = base();
        env.insert(
            "UPSTREAM_AUTH_HEADERS",
            r#"[{"name":"CF-Access-Client-Secret","value":"s3cret"}]"#.into(),
        );
        env.insert(
            "UPSTREAM_URL",
            "https://private-origin.internal.example".into(),
        );
        env.insert("SUI_RPC_URL", "https://rpc.example/KEY123".into());
        let cfg = GatewayConfig::from_env(&|k: &str| env.get(k).cloned()).unwrap();
        let out = format!("{cfg:?}");
        assert!(!out.contains("s3cret"), "{out}");
        assert!(out.contains("CF-Access-Client-Secret"));
        // The private origin and an RPC key in the path are never printed (audit F26).
        assert!(
            !out.contains("private-origin") && !out.contains("KEY123"),
            "{out}"
        );
    }

    #[test]
    fn object_ids_are_0x_hex() {
        assert!(is_object_id("0x2"));
        assert!(is_object_id(&format!("0x{}", "a".repeat(64))));
        assert!(!is_object_id("0x"));
        assert!(!is_object_id("gate"));
        assert!(!is_object_id(&format!("0x{}", "a".repeat(65))));
    }

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

    fn load(extra: &[(&'static str, &str)]) -> anyhow::Result<GatewayConfig> {
        let mut env = base();
        for (k, v) in extra {
            if v == &"<unset>" {
                env.remove(k);
            } else {
                env.insert(k, v.to_string());
            }
        }
        GatewayConfig::from_env(&|k: &str| env.get(k).cloned())
    }

    fn err(extra: &[(&'static str, &str)]) -> String {
        load(extra).unwrap_err().to_string()
    }

    #[test]
    fn defaults_load_and_are_self_consistent() {
        let cfg = load(&[]).unwrap();
        assert_eq!(cfg.gateway_origin, "https://gateway.example.com");
        assert_eq!(cfg.network, "testnet");
        assert!(cfg.allowed_origins.is_empty());
        assert!(cfg.upstream_auth_headers.is_empty());
        assert!(cfg.sui_rpc_auth_header.is_none());
        assert_eq!(cfg.challenge_rate_limit_per_min, 30);
        assert_eq!(cfg.public_paths, vec!["/v1/tip-config"]);
        assert!(cfg.redemption_lease_ttl_secs > cfg.upstream_timeout_secs);
        assert!(cfg.consume_max_age_secs <= cfg.redemption_retention_secs);
        assert_eq!(
            load(&[("CHALLENGE_RATE_LIMIT_PER_MIN", "0")])
                .unwrap()
                .challenge_rate_limit_per_min,
            0
        );
        assert_eq!(
            load(&[("UPSTREAM_URL", "https://relay.example.com///")])
                .unwrap()
                .upstream_url,
            "https://relay.example.com"
        );
    }

    #[test]
    fn audience_binding_inputs_are_required_and_canonical() {
        assert!(err(&[("GATEWAY_ORIGIN", "<unset>")]).contains("GATEWAY_ORIGIN"));
        for bad in [
            "",
            "gateway.example.com",
            "http://gateway.example.com",
            "https://gateway.example.com/",
            "https://Gateway.example.com",
            "https://gateway.example.com:443",
            "https://user@gateway.example.com",
        ] {
            assert!(
                err(&[("GATEWAY_ORIGIN", bad)]).contains("GATEWAY_ORIGIN"),
                "{bad}"
            );
        }
        assert!(err(&[("NETWORK", "testnet2")]).contains("NETWORK"));
        assert!(err(&[("NETWORK", "<unset>")]).contains("NETWORK"));
    }

    #[test]
    fn an_upstream_that_is_the_gateway_is_a_request_loop_however_it_is_spelled() {
        for same in [
            "https://gateway.example.com/relay",
            "https://gateway.example.com",
            "https://GATEWAY.example.com/relay",
            "https://gateway.example.com:443/relay",
            "https://Gateway.Example.COM:443",
        ] {
            assert!(err(&[("UPSTREAM_URL", same)]).contains("loop"), "{same}");
        }
        // A different port or host is a different origin.
        for other in [
            "https://gateway.example.com:8443",
            "https://gateway.example.com.evil.example",
            "https://relay.example.com",
        ] {
            assert!(load(&[("UPSTREAM_URL", other)]).is_ok(), "{other}");
        }
    }

    #[test]
    fn a_typo_never_selects_a_weaker_mode() {
        for bad in ["TRUE", "1", "yes", "true ", ""] {
            assert!(
                err(&[("SINGLE_USE", bad)]).contains("SINGLE_USE"),
                "{bad:?}"
            );
        }
        assert!(load(&[("SINGLE_USE", "true")]).unwrap().single_use);
        assert!(!load(&[("SINGLE_USE", "false")]).unwrap().single_use);
        for (key, bad) in [
            ("MAX_BODY_BYTES", "0"),
            ("MAX_BODY_BYTES", "-1"),
            ("MAX_BODY_BYTES", "1.5"),
            ("MAX_BODY_BYTES", "lots"),
            ("RATE_LIMIT_PER_MIN", "-5"),
            ("NONCE_MAX_ENTRIES", "0"),
            ("CHALLENGE_TTL_SECS", "1"),
            ("UPSTREAM_TIMEOUT_SECS", "0"),
            ("REDEMPTION_LEASE_TTL_SECS", "5"),
            ("RPC_TIMEOUT_SECS", "121"),
            ("OWNERSHIP_CACHE_TTL_MS", ""),
        ] {
            assert!(err(&[(key, bad)]).contains(key), "{key}={bad}");
        }
        assert_eq!(
            load(&[("RATE_LIMIT_PER_MIN", "0")])
                .unwrap()
                .rate_limit_per_min,
            0
        );
        for bad in ["yes", "true", "2"] {
            assert!(err(&[("ALLOW_INSECURE_HTTP", bad)]).contains("ALLOW_INSECURE_HTTP"));
        }
    }

    #[test]
    fn upstream_and_rpc_urls_must_be_https_unless_insecure_is_allowed() {
        assert!(err(&[("UPSTREAM_URL", "http://relay.example.com")]).contains("UPSTREAM_URL"));
        assert!(err(&[("SUI_RPC_URL", "ftp://rpc.example.com")]).contains("SUI_RPC_URL"));
        assert!(err(&[("SUI_RPC_URL", "https://u:p@rpc.example.com")]).contains("SUI_RPC_URL"));
        // The TypeScript Worker let a loopback http URL through without a flag; the single
        // implementation asks for the explicit opt-in everywhere.
        assert!(err(&[("UPSTREAM_URL", "http://127.0.0.1:8080")]).contains("ALLOW_INSECURE_HTTP"));
        let cfg = load(&[
            ("UPSTREAM_URL", "http://127.0.0.1:8080"),
            ("ALLOW_INSECURE_HTTP", "1"),
        ])
        .unwrap();
        assert_eq!(cfg.upstream_url, "http://127.0.0.1:8080");
        assert!(cfg.allow_insecure_http);
    }

    #[test]
    fn origins_and_public_paths_are_validated() {
        assert_eq!(
            load(&[(
                "ALLOWED_ORIGINS",
                " https://a.example , https://b.example:8443 "
            )])
            .unwrap()
            .allowed_origins,
            vec!["https://a.example", "https://b.example:8443"]
        );
        assert_eq!(
            load(&[(
                "ALLOWED_ORIGINS",
                "  https://app.example.com , https://admin.example.com  "
            )])
            .unwrap()
            .allowed_origins,
            vec!["https://app.example.com", "https://admin.example.com"]
        );
        assert!(load(&[("ALLOWED_ORIGINS", "")])
            .unwrap()
            .allowed_origins
            .is_empty());
        for bad in [
            "*",
            "http://a.example",
            "http://localhost:3000",
            "https://a.example/",
            "https://A.example",
            "a.example",
            "https://a.example:443",
        ] {
            assert!(
                err(&[("ALLOWED_ORIGINS", bad)]).contains("ALLOWED_ORIGINS"),
                "{bad}"
            );
        }
        // A loopback http origin needs the same explicit opt-in as the URLs.
        assert!(load(&[
            ("ALLOWED_ORIGINS", "http://localhost:3000"),
            ("ALLOW_INSECURE_HTTP", "1")
        ])
        .is_ok());
        assert_eq!(
            load(&[("PUBLIC_PATHS", "/v1/tip-config, /health")])
                .unwrap()
                .public_paths,
            vec!["/v1/tip-config", "/health"]
        );
        for bad in ["v1/tip-config", "/a/../b", "/a?x=1", "/a#f", "/a b", "/./a"] {
            assert!(
                err(&[("PUBLIC_PATHS", bad)]).contains("PUBLIC_PATHS"),
                "{bad}"
            );
        }
    }

    #[test]
    fn single_use_windows_must_be_consistent() {
        assert!(err(&[
            ("UPSTREAM_TIMEOUT_SECS", "600"),
            ("REDEMPTION_LEASE_TTL_SECS", "600")
        ])
        .contains("exceed UPSTREAM_TIMEOUT_SECS"));
        assert!(err(&[
            ("UPSTREAM_TIMEOUT_SECS", "600"),
            ("REDEMPTION_LEASE_TTL_SECS", "300")
        ])
        .contains("exceed"));
        // The body-read deadline counts too (audit F46): 600 + 400 = 1000 >= 900. The TypeScript
        // Worker only compared the upstream deadline; the stricter rule is the single one.
        assert!(err(&[("BODY_READ_TIMEOUT_SECS", "400")]).contains("BODY_READ_TIMEOUT_SECS"));
        assert!(err(&[
            ("UPSTREAM_TIMEOUT_SECS", "500"),
            ("BODY_READ_TIMEOUT_SECS", "400"),
            ("REDEMPTION_LEASE_TTL_SECS", "900")
        ])
        .contains("BODY_READ_TIMEOUT_SECS"));
        assert!(load(&[
            ("UPSTREAM_TIMEOUT_SECS", "500"),
            ("BODY_READ_TIMEOUT_SECS", "399"),
            ("REDEMPTION_LEASE_TTL_SECS", "900")
        ])
        .is_ok());
        assert!(err(&[
            ("CONSUME_MAX_AGE_SECS", "864000"),
            ("REDEMPTION_RETENTION_SECS", "432000")
        ])
        .contains("CONSUME_MAX_AGE_SECS"));
    }

    #[test]
    fn nft_type_and_gate_id_are_validated() {
        assert_eq!(
            load(&[("NFT_TYPE", "0xab::access_gate::SoulboundAccessNFT")])
                .unwrap()
                .nft_type,
            "0xab::access_gate::SoulboundAccessNFT"
        );
        for t in [
            "0x2::coin::Coin<0x2::sui::SUI>",
            "0x1::other::AccessNFT",
            "0x1::access_gate::Gate",
            "AccessNFT",
        ] {
            assert!(err(&[("NFT_TYPE", t)]).contains("NFT_TYPE"), "{t}");
        }
        assert!(err(&[("GATE_ID", "")]).contains("GATE_ID"));
        assert!(err(&[("GATE_ID", "gate")]).contains("GATE_ID"));
        assert!(err(&[("GATE_ID", "<unset>")]).contains("GATE_ID"));
    }

    #[test]
    fn public_path_matching() {
        let cfg = load(&[]).unwrap();
        assert!(cfg.is_public_path("/v1/tip-config"));
        assert!(!cfg.is_public_path("/v1/blob-upload"));
    }

    #[test]
    fn env_is_any_lookup() {
        let env: &dyn Env = &|k: &str| (k == "X").then(|| "1".to_string());
        assert_eq!(env.get("X").as_deref(), Some("1"));
        assert_eq!(env.get("Y"), None);
        assert_eq!(int(env, "X", 5u32, 0, 9).unwrap(), 1);
        assert_eq!(int(env, "Y", 5u32, 0, 9).unwrap(), 5);
        assert!(boolean(env, "X", false).is_err());
        assert!(required(env, "Y").is_err());
    }
}
