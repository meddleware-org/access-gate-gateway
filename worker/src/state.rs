//! The Worker's [`StateStore`]: nonces, rate windows and redemptions live in the region-sharded
//! Durable Object ([`crate::do_state::NonceRateState`]); this is the client side. Every failure is an
//! `Err` (the core answers 503: fail closed, never a conflict, never unmetered).
//!
//! Routing, parity with the TypeScript Worker: a nonce is `<shard>.<48 hex>` and its `take` goes to
//! the issuing shard; rate windows live in the request's region shard under the keys `chal:<ip>`,
//! `ip:<ip>`, `pre:<ip>` and the bare address; redemptions all go to the fixed shard `redeem`.

use crate::region::{instance_name, shard_of_nonce, REDEEM_SHARD};
use nft_gate_core::redemption::{Commit, Lease};
use nft_gate_core::state::{RateScope, StateStore};
use serde::Deserialize;
use worker::{ObjectNamespace, Stub, Url};

/// Per-request view of the Durable Object state.
pub struct DoState {
    pub ns: ObjectNamespace,
    /// The shard this request's nonce is issued in and its rate windows live in.
    pub region: String,
    pub challenge_ttl_secs: u64,
    pub max_entries: usize,
    pub budgets: Budgets,
    /// Test-only fault injection (feature `test-hooks`, var `TEST_FAIL_STATE`): the Durable Object
    /// operation to fail (`issue`, `take`, `rate`, `lease`, `commit`, `release`) or `all`.
    #[cfg(feature = "test-hooks")]
    pub fail: Option<String>,
}

/// Per-scope budgets (requests per minute; 0 disables).
#[derive(Clone, Copy)]
pub struct Budgets {
    pub challenge: u32,
    pub public: u32,
    pub gated_preauth: u32,
    pub address: u32,
}

#[derive(Deserialize)]
struct Issued {
    #[serde(rename = "expiresAt")]
    expires_at: u64,
}
#[derive(Deserialize)]
struct Ok_ {
    ok: bool,
}
#[derive(Deserialize)]
struct Leased {
    status: String,
    token: Option<String>,
}
#[derive(Deserialize)]
struct Committed {
    result: String,
}

/// 24 random bytes as 48 lower-case hex digits (the challenge nonce body). Fails rather than ever
/// returning predictable bytes.
fn random_hex24() -> anyhow::Result<String> {
    let mut b = [0u8; 24];
    getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("entropy unavailable: {e}"))?;
    Ok(hex(&b))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl DoState {
    fn stub(&self, shard: &str) -> anyhow::Result<Stub> {
        self.ns
            .id_from_name(&instance_name(shard))
            .and_then(|id| id.get_stub())
            .map_err(|e| anyhow::anyhow!("durable object stub: {e}"))
    }

    /// One operation on one shard; the response body is JSON.
    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        shard: &str,
        op: &str,
        params: &[(&str, &str)],
    ) -> anyhow::Result<T> {
        #[cfg(feature = "test-hooks")]
        if self.fail.as_deref().is_some_and(|f| f == "all" || f == op) {
            anyhow::bail!("injected failure of {op}");
        }
        let mut url = Url::parse(&format!("https://do.internal/{op}"))
            .map_err(|e| anyhow::anyhow!("durable object url: {e}"))?;
        {
            let mut q = url.query_pairs_mut();
            for (k, v) in params {
                q.append_pair(k, v);
            }
        }
        let mut resp = self
            .stub(shard)?
            .fetch_with_str(url.as_str())
            .await
            .map_err(|e| anyhow::anyhow!("durable object {op}: {e}"))?;
        if resp.status_code() != 200 {
            anyhow::bail!("durable object {op}: HTTP {}", resp.status_code());
        }
        resp.json()
            .await
            .map_err(|e| anyhow::anyhow!("durable object {op} body: {e}"))
    }

    fn rate_key(scope: RateScope, key: &str) -> String {
        match scope {
            RateScope::Challenge => format!("chal:{key}"),
            RateScope::Public => format!("ip:{key}"),
            RateScope::GatedPreauth => format!("pre:{key}"),
            RateScope::Address => key.to_string(),
        }
    }

    fn budget(&self, scope: RateScope) -> u32 {
        match scope {
            RateScope::Challenge => self.budgets.challenge,
            RateScope::Public => self.budgets.public,
            RateScope::GatedPreauth => self.budgets.gated_preauth,
            RateScope::Address => self.budgets.address,
        }
    }
}

impl StateStore for DoState {
    async fn issue_nonce(&self) -> anyhow::Result<(String, u64)> {
        let nonce = format!("{}.{}", self.region, random_hex24()?);
        let r: Issued = self
            .call(
                &self.region,
                "issue",
                &[
                    ("nonce", &nonce),
                    ("ttl", &self.challenge_ttl_secs.to_string()),
                    ("max", &self.max_entries.to_string()),
                ],
            )
            .await?;
        Ok((nonce, r.expires_at))
    }

    async fn take_nonce(&self, nonce: &str) -> anyhow::Result<bool> {
        // A forged shard tag was never issued here: refuse without touching (or minting) a shard.
        let Some(shard) = shard_of_nonce(nonce) else {
            return Ok(false);
        };
        let r: Ok_ = self.call(shard, "take", &[("nonce", nonce)]).await?;
        Ok(r.ok)
    }

    async fn rate_check(&self, scope: RateScope, key: &str) -> anyhow::Result<bool> {
        let r: Ok_ = self
            .call(
                &self.region,
                "rate",
                &[
                    ("addr", &Self::rate_key(scope, key)),
                    ("max", &self.budget(scope).to_string()),
                ],
            )
            .await?;
        Ok(r.ok)
    }

    async fn try_lease_redemption(&self, key: &str, lease_ttl_secs: u64) -> anyhow::Result<Lease> {
        let r: Leased = self
            .call(
                REDEEM_SHARD,
                "lease",
                &[
                    ("key", key),
                    ("ttl", &lease_ttl_secs.to_string()),
                    ("max", &self.max_entries.to_string()),
                ],
            )
            .await?;
        match (r.status.as_str(), r.token) {
            ("ok", Some(t)) => Ok(Lease::Ok(t)),
            ("leased", _) => Ok(Lease::Leased),
            ("redeemed", _) => Ok(Lease::Redeemed),
            (s, _) => anyhow::bail!("unexpected lease status {s}"),
        }
    }

    async fn commit_redemption(
        &self,
        key: &str,
        token: &str,
        retention_secs: u64,
    ) -> anyhow::Result<Commit> {
        let r: Committed = self
            .call(
                REDEEM_SHARD,
                "commit",
                &[
                    ("key", key),
                    ("token", token),
                    ("retention", &retention_secs.to_string()),
                ],
            )
            .await?;
        match r.result.as_str() {
            "ok" => Ok(Commit::Ok),
            "lost" => Ok(Commit::Lost),
            s => anyhow::bail!("unexpected commit result {s}"),
        }
    }

    async fn release_redemption(&self, key: &str, token: &str) {
        // Best effort: a release that does not happen leaves a lease that self-expires.
        let r: anyhow::Result<Ok_> = self
            .call(REDEEM_SHARD, "release", &[("key", key), ("token", token)])
            .await;
        if let Err(e) = r {
            worker::console_error!("release_redemption failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_keys_are_prefixed_per_scope_like_the_typescript_worker() {
        assert_eq!(DoState::rate_key(RateScope::Challenge, "1.2.3.4"), "chal:1.2.3.4");
        assert_eq!(DoState::rate_key(RateScope::Public, "1.2.3.4"), "ip:1.2.3.4");
        assert_eq!(DoState::rate_key(RateScope::GatedPreauth, "1.2.3.4"), "pre:1.2.3.4");
        assert_eq!(DoState::rate_key(RateScope::Address, "0xabc"), "0xabc");
    }

    #[test]
    fn hex_is_lower_case_and_padded() {
        assert_eq!(hex(&[0, 15, 255]), "000fff");
    }
}
