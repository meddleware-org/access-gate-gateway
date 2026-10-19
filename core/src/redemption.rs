//! Single-use redemption semantics as a pure state machine over an explicit clock (ms), so the
//! rules live in ONE place and every backend (in-memory, Redis script, Durable Object SQL) can be
//! tested against it. Port of `InMemoryNonceStore::{try_lease,commit,release}_redemption`
//! (`gateway-rust/src/challenge.rs`) and `NonceRateState` (`gateway-workers/src/state/durable_object.ts`).
//! A paid use is never lost to a commit failure (CLAUDE.md, OQ6): the dispatcher releases on any
//! failure; this table only provides compare-and-set transitions on the owner token.

use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Lease {
    Ok(String),
    Leased,
    Redeemed,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Commit {
    Ok,
    Lost,
}

#[derive(Clone, Debug)]
struct Row {
    committed: bool,
    expiry_ms: u64,
    token: String,
}

#[derive(Default)]
pub struct RedemptionTable {
    rows: HashMap<String, Row>,
}

impl RedemptionTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Claim `key`. `new_token` is a fresh random owner token supplied by the platform (core has no RNG).
    pub fn try_lease(
        &mut self,
        key: &str,
        now: u64,
        lease_ttl_secs: u64,
        max_entries: usize,
        new_token: String,
    ) -> Lease {
        self.rows.retain(|_, r| r.expiry_ms > now);
        if let Some(r) = self.rows.get(key) {
            if r.committed {
                return Lease::Redeemed;
            }
            if r.expiry_ms > now {
                return Lease::Leased;
            }
        }
        if self.rows.len() >= max_entries.max(1) {
            // Evict the soonest-to-expire LEASE, never a commit (that would allow re-redemption).
            if let Some(oldest) = self
                .rows
                .iter()
                .filter(|(_, r)| !r.committed)
                .min_by_key(|(_, r)| r.expiry_ms)
                .map(|(k, _)| k.clone())
            {
                self.rows.remove(&oldest);
            }
        }
        self.rows.insert(
            key.to_string(),
            Row {
                committed: false,
                expiry_ms: now.saturating_add(lease_ttl_secs.saturating_mul(1000)),
                token: new_token.clone(),
            },
        );
        Lease::Ok(new_token)
    }

    pub fn commit(&mut self, key: &str, token: &str, now: u64, retention_secs: u64) -> Commit {
        match self.rows.get_mut(key) {
            Some(r) if !r.committed && r.token == token && r.expiry_ms > now => {
                r.committed = true;
                r.expiry_ms = now.saturating_add(retention_secs.saturating_mul(1000));
                r.token.clear();
                Commit::Ok
            }
            _ => Commit::Lost,
        }
    }

    pub fn release(&mut self, key: &str, token: &str) {
        if self
            .rows
            .get(key)
            .is_some_and(|r| !r.committed && r.token == token)
        {
            self.rows.remove(key);
        }
    }
}

/// Nonce table: issue / take-once with a hard cap (evict soonest-to-expire). Mirrors the DO's
/// `issue` + `takeIfValid` (present => gone, valid iff unexpired).
#[derive(Default)]
pub struct NonceTable {
    rows: HashMap<String, u64>,
}

impl NonceTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn issue(&mut self, nonce: String, now: u64, ttl_secs: u64, max_entries: usize) -> u64 {
        self.rows.retain(|_, e| *e > now);
        if self.rows.len() >= max_entries.max(1) {
            if let Some(oldest) = self
                .rows
                .iter()
                .min_by_key(|(_, e)| **e)
                .map(|(k, _)| k.clone())
            {
                self.rows.remove(&oldest);
            }
        }
        let expiry = now.saturating_add(ttl_secs.saturating_mul(1000));
        self.rows.insert(nonce, expiry);
        expiry
    }

    pub fn take_if_valid(&mut self, nonce: &str, now: u64) -> bool {
        match self.rows.remove(nonce) {
            Some(expiry) => expiry > now,
            None => false,
        }
    }

    /// Drop expired nonces (the periodic prune of a long-lived process).
    pub fn prune(&mut self, now: u64) {
        self.rows.retain(|_, e| *e > now);
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// Fixed 60 s window per key (mirrors `rateCheck`). Returns true if the request is allowed.
#[derive(Default)]
pub struct RateTable {
    rows: HashMap<String, (u64, u64)>,
}

impl RateTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check(&mut self, key: &str, now: u64, max_per_min: u64) -> bool {
        if max_per_min == 0 {
            return true;
        }
        let (mut start, mut count) = (now, 0);
        if let Some(&(s, c)) = self.rows.get(key) {
            if now.saturating_sub(s) < 60_000 {
                start = s;
                count = c;
            }
        }
        if count >= max_per_min {
            return false;
        }
        self.rows.insert(key.to_string(), (start, count + 1));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_commit_release_semantics() {
        let mut t = RedemptionTable::new();
        let tok = match t.try_lease("d", 0, 900, 10, "T1".into()) {
            Lease::Ok(t) => t,
            o => panic!("{o:?}"),
        };
        assert_eq!(t.try_lease("d", 1, 900, 10, "T2".into()), Lease::Leased);
        // wrong token cannot commit or release
        assert_eq!(t.commit("d", "nope", 2, 100), Commit::Lost);
        t.release("d", "nope");
        assert_eq!(t.try_lease("d", 3, 900, 10, "T3".into()), Lease::Leased);
        assert_eq!(t.commit("d", &tok, 4, 100), Commit::Ok);
        assert_eq!(t.try_lease("d", 5, 900, 10, "T4".into()), Lease::Redeemed);
        // a commit is retained, then forgotten
        assert!(matches!(
            t.try_lease("d", 100_000 + 5, 900, 10, "T5".into()),
            Lease::Ok(_)
        ));
    }

    #[test]
    fn expired_lease_is_reclaimable_and_old_holder_loses() {
        let mut t = RedemptionTable::new();
        let a = match t.try_lease("d", 0, 1, 10, "A".into()) {
            Lease::Ok(t) => t,
            _ => unreachable!(),
        };
        let b = match t.try_lease("d", 2_000, 1, 10, "B".into()) {
            Lease::Ok(t) => t,
            _ => unreachable!(),
        };
        assert_eq!(t.commit("d", &a, 2_001, 10), Commit::Lost);
        t.release("d", &a); // must not clear B
        assert_eq!(t.commit("d", &b, 2_002, 10), Commit::Ok);
    }

    #[test]
    fn release_makes_the_consume_retryable() {
        let mut t = RedemptionTable::new();
        let a = match t.try_lease("d", 0, 900, 10, "A".into()) {
            Lease::Ok(t) => t,
            _ => unreachable!(),
        };
        t.release("d", &a);
        assert!(matches!(
            t.try_lease("d", 1, 900, 10, "B".into()),
            Lease::Ok(_)
        ));
    }

    #[test]
    fn cap_evicts_leases_never_commits() {
        let mut t = RedemptionTable::new();
        let a = match t.try_lease("a", 0, 900, 2, "A".into()) {
            Lease::Ok(t) => t,
            _ => unreachable!(),
        };
        assert_eq!(t.commit("a", &a, 1, 900), Commit::Ok);
        let _ = t.try_lease("b", 2, 900, 2, "B".into());
        let _ = t.try_lease("c", 3, 900, 2, "C".into()); // evicts the lease b, not the commit a
        assert_eq!(t.try_lease("a", 4, 900, 2, "X".into()), Lease::Redeemed);
    }

    #[test]
    fn nonce_is_single_use_and_expires() {
        let mut n = NonceTable::new();
        n.issue("x".into(), 0, 1, 10);
        assert!(n.take_if_valid("x", 500));
        assert!(!n.take_if_valid("x", 501));
        n.issue("y".into(), 0, 1, 10);
        assert!(!n.take_if_valid("y", 1_000)); // expired exactly at expiry
    }

    #[test]
    fn rate_window() {
        let mut r = RateTable::new();
        assert!(r.check("k", 0, 2));
        assert!(r.check("k", 1, 2));
        assert!(!r.check("k", 2, 2));
        assert!(r.check("k", 60_001, 2));
        assert!(r.check("z", 0, 0));
    }
}
