//! The Worker's [`StateStore`]: nonces, rate windows and redemptions live in the region-sharded
//! Durable Object ([`crate::do_state::NonceRateState`]); this is the client side. Every failure is an
//! `Err` (the core answers 503: fail closed, never a conflict, never unmetered).
//!
//! Routing, parity with the TypeScript Worker: a nonce is `<shard>.<48 hex>` and its `take` goes to
//! the issuing shard; rate windows live in the request's region shard under the keys `chal:<ip>`,
//! `ip:<ip>`, `pre:<ip>` and the bare address; redemptions all go to the fixed shard `redeem`.

use crate::region::{instance_name, shard_of_nonce, REDEEM_SHARD};
use access_gate_gateway_core::redemption::{Commit, Lease};
use access_gate_gateway_core::state::{RateScope, StateStore};
use serde::Deserialize;
use worker::{ObjectNamespace, Stub, Url};

/// Per-request view of the Durable Object state.
pub struct DoState {
    /// The Durable Object namespace.
    pub ns: ObjectNamespace,
    /// The shard this request's nonce is issued in and its rate windows live in.
    pub region: String,
    /// How long an issued nonce is valid.
    pub challenge_ttl_secs: u64,
    /// The cap on live entries per shard.
    pub max_entries: usize,
    /// The per-scope budgets.
    pub budgets: Budgets,
    /// Test-only fault injection (feature `test-hooks`, var `TEST_FAIL_STATE`): the Durable Object
    /// operation to fail (`issue`, `take`, `rate`, `lease`, `commit`, `release`) or `all`.
    #[cfg(feature = "test-hooks")]
    pub fail: Option<String>,
}

/// Per-scope budgets (requests per minute; 0 disables).
#[derive(Clone, Copy)]
pub struct Budgets {
    /// Requests per minute for challenges.
    pub challenge: u32,
    /// For public paths.
    pub public: u32,
    /// For gated requests before authentication.
    pub gated_preauth: u32,
    /// For a verified address.
    pub address: u32,
}

/// The Durable Object's answer to an issue request.
#[derive(Deserialize)]
struct Issued {
    /// When the nonce expires.
    #[serde(rename = "expiresAt")]
    expires_at: u64,
}
/// A yes or no answer.
#[derive(Deserialize)]
struct Ok_ {
    /// Whether the operation succeeded.
    ok: bool,
}
/// The answer to a lease request.
#[derive(Deserialize)]
struct Leased {
    /// `ok`, `leased` or `redeemed`.
    status: String,
    /// The owner token, when granted.
    token: Option<String>,
}
/// The answer to a commit request.
#[derive(Deserialize)]
struct Committed {
    /// `ok` or `lost`.
    result: String,
}

/// 24 random bytes as 48 lower-case hex digits (the challenge nonce body). Fails rather than ever
/// returning predictable bytes.
fn random_hex24() -> anyhow::Result<String> {
    let mut b = [0u8; 24];
    getrandom::getrandom(&mut b).map_err(|e| anyhow::anyhow!("entropy unavailable: {e}"))?;
    Ok(hex(&b))
}

/// Lower-case hex of bytes.
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl DoState {
    /// The stub of the Durable Object for a shard.
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

    /// The rate-table key for a scope and key.
    fn rate_key(scope: RateScope, key: &str) -> String {
        match scope {
            RateScope::Challenge => format!("chal:{key}"),
            RateScope::Public => format!("ip:{key}"),
            RateScope::GatedPreauth => format!("pre:{key}"),
            RateScope::Address => key.to_string(),
        }
    }

    /// The budget of a scope.
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
    /// Issue a challenge nonce and its expiry (epoch seconds) (the nonce carries its shard, so a later take goes to the same Durable Object).
    async fn issue_nonce(&self) -> anyhow::Result<(String, u64)> {
        // The nonce is `<shard>.<random>`: the shard tag lets `take_nonce` find the Durable Object that holds it with no lookup.
        let nonce = format!("{}.{}", self.region, random_hex24()?);
        // Ask the shard for a nonce slot: it stores the nonce and answers with its expiry.
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

    /// Take a nonce exactly once: `true` only for the first take of a live nonce.
    async fn take_nonce(&self, nonce: &str) -> anyhow::Result<bool> {
        // A forged shard tag was never issued here: refuse without touching (or minting) a shard.
        let Some(shard) = shard_of_nonce(nonce) else {
            return Ok(false);
        };
        // The shard that issued the nonce is the only one that can have it.
        let r: Ok_ = self.call(shard, "take", &[("nonce", nonce)]).await?;
        Ok(r.ok)
    }

    /// Count one request against the budget for `scope` and `key`: `false` when the budget is spent.
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

    /// Try to lease the single-use redemption `key` for `lease_ttl_secs`: a fresh lease, or "already leased" or "already redeemed".
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
            // The store answers with a status string; map each to the typed lease and treat anything else as a failure, not a guess.
            ("ok", Some(t)) => Ok(Lease::Ok(t)),
            ("leased", _) => Ok(Lease::Leased),
            ("redeemed", _) => Ok(Lease::Redeemed),
            (s, _) => anyhow::bail!("unexpected lease status {s}"),
        }
    }

    /// Turn the lease held with `token` into a permanent redemption kept for `retention_secs`; `Lost` if the lease is no longer ours.
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
            // `lost` means the lease expired or was taken over before the commit.
            "lost" => Ok(Commit::Lost),
            s => anyhow::bail!("unexpected commit result {s}"),
        }
    }

    /// Give a lease back after a failed upload; a stale token releases nothing.
    async fn release_redemption(&self, key: &str, token: &str) {
        // Best effort: a release that does not happen leaves a lease that self-expires.
        // The release result is only logged: nothing the person did depends on it.
        let r: anyhow::Result<Ok_> = self
            .call(REDEEM_SHARD, "release", &[("key", key), ("token", token)])
            .await;
        if let Err(e) = r {
            worker::console_error!("release_redemption failed: {e}");
        }
    }
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;

    /// Rate keys are prefixed per scope like the typescript worker.
    #[test]
    fn rate_keys_are_prefixed_per_scope_like_the_typescript_worker() {
        assert_eq!(
            DoState::rate_key(RateScope::Challenge, "1.2.3.4"),
            "chal:1.2.3.4"
        );
        assert_eq!(
            DoState::rate_key(RateScope::Public, "1.2.3.4"),
            "ip:1.2.3.4"
        );
        assert_eq!(
            DoState::rate_key(RateScope::GatedPreauth, "1.2.3.4"),
            "pre:1.2.3.4"
        );
        assert_eq!(DoState::rate_key(RateScope::Address, "0xabc"), "0xabc");
    }

    /// Hex is lower case and padded.
    #[test]
    fn hex_is_lower_case_and_padded() {
        assert_eq!(hex(&[0, 15, 255]), "000fff");
    }
}
