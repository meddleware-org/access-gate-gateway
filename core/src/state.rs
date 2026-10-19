//! The state ports of the gateway and their in-memory implementation.
//!
//! A gateway keeps three kinds of state: single-use **nonces** (a challenge is consumed exactly
//! once), per-key **rate** windows, and single-use **redemptions** (a lease / commit / release
//! protocol on the permanent on-chain consume digest). [`StateStore`] is the one interface the
//! orchestration ([`crate::gateway`]) uses for all three; each platform supplies a backend:
//!
//! | Platform | Backend |
//! | --- | --- |
//! | gateway-rust, one replica | [`MemoryState`] (the pure tables in [`crate::redemption`]) |
//! | gateway-rust, scaled out | Redis/Dragonfly (nonce + redemption), [`MemoryRates`] |
//! | Cloudflare Worker | a SQLite-backed Durable Object that runs the same rules in SQL |
//!
//! [`Clock`] and [`Rng`] are the two things the core is not allowed to reach for itself
//! (`SystemTime::now` panics on `wasm32-unknown-unknown`, and a Worker has no OS entropy source).

use crate::redemption::{Commit, Lease, NonceTable, RateTable, RedemptionTable};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Milliseconds since the Unix epoch. Must never go backwards within a process (a wall clock that
/// can step is anchored to a monotonic one by the platform), because expiries are compared to it.
pub trait Clock {
    fn now_ms(&self) -> u64;
}

/// A cryptographically secure random source (OS entropy natively, `crypto.getRandomValues` in a Worker).
pub trait Rng {
    fn fill(&self, buf: &mut [u8]);
}

/// A 24-byte random value as 48 lower-case hex digits: the challenge nonce and the redemption owner
/// token. ASCII by contract (the client's `decodeAccessProof` enforces ASCII), 192 bits of entropy.
pub fn random_hex24<R: Rng + ?Sized>(rng: &R) -> String {
    let mut buf = [0u8; 24];
    rng.fill(&mut buf);
    hex::encode(buf)
}

/// Which rate budget a check is charged to. The budgets themselves belong to the platform's store:
/// they are configuration, and the Durable Object keeps its own windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateScope {
    /// `GET /v1/challenge`, per client IP: issuing a nonce writes state.
    Challenge,
    /// A read-only public path, per client IP.
    Public,
    /// A gated request, per client IP, BEFORE signature verification (it costs CPU and a store call).
    GatedPreauth,
    /// A verified request, per wallet address.
    Address,
}

/// Everything the orchestration needs from the platform's state.
///
/// Every fallible method fails **closed**: an `Err` is answered `503` by the orchestration (never a
/// conflict, never an implicit success). [`StateStore::release_redemption`] and
/// [`StateStore::rate_check`] cannot fail: a release that does not happen leaves a lease that
/// self-expires, and a limiter that cannot answer is the platform's call (the native one is in memory).
#[allow(async_fn_in_trait)]
pub trait StateStore {
    /// Issue a fresh single-use nonce. Returns `(nonce, expires_at_unix_ms)`; an `Err` when the
    /// backend cannot record it (a nonce that could never verify must not be handed out).
    async fn issue_nonce(&self) -> anyhow::Result<(String, u64)>;
    /// Consume `nonce` exactly once; `Ok(true)` iff it was issued, unexpired and unused.
    async fn take_nonce(&self, nonce: &str) -> anyhow::Result<bool>;
    /// Charge one request to `key` under `scope`; `false` when the budget for the minute is spent.
    async fn rate_check(&self, scope: RateScope, key: &str) -> bool;
    /// Claim the consume digest `key` for an in-flight upload (see [`RedemptionTable::try_lease`]).
    async fn try_lease_redemption(&self, key: &str, lease_ttl_secs: u64) -> anyhow::Result<Lease>;
    /// Mark `key` spent (retained `retention_secs`) iff `token` still owns an unexpired lease.
    async fn commit_redemption(
        &self,
        key: &str,
        token: &str,
        retention_secs: u64,
    ) -> anyhow::Result<Commit>;
    /// Release the lease on `key` iff `token` still owns it. Never clears a commit.
    async fn release_redemption(&self, key: &str, token: &str);
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock cannot leave a table half-updated (each operation is a few
    // plain map calls), so the data behind a poisoned lock is still consistent.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Nonces and redemptions in process memory: the pure tables of [`crate::redemption`] behind a lock.
/// Correct at one replica only; a second replica has its own tables.
pub struct MemoryStore<C: Clock, R: Rng> {
    clock: C,
    rng: R,
    challenge_ttl_secs: u64,
    max_entries: usize,
    nonces: Mutex<NonceTable>,
    redemptions: Mutex<RedemptionTable>,
}

impl<C: Clock, R: Rng> MemoryStore<C, R> {
    /// `max_entries` is a hard cap on live nonces and on live redemptions (the soonest-to-expire
    /// lease or nonce is evicted beyond it; a commit never is).
    pub fn new(clock: C, rng: R, challenge_ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            clock,
            rng,
            challenge_ttl_secs,
            max_entries: max_entries.max(1),
            nonces: Mutex::new(NonceTable::new()),
            redemptions: Mutex::new(RedemptionTable::new()),
        }
    }

    pub fn issue_nonce(&self) -> (String, u64) {
        let nonce = random_hex24(&self.rng);
        let now = self.clock.now_ms();
        let expires_at = locked(&self.nonces).issue(
            nonce.clone(),
            now,
            self.challenge_ttl_secs,
            self.max_entries,
        );
        (nonce, expires_at)
    }

    pub fn take_nonce(&self, nonce: &str) -> bool {
        locked(&self.nonces).take_if_valid(nonce, self.clock.now_ms())
    }

    pub fn try_lease_redemption(&self, key: &str, lease_ttl_secs: u64) -> Lease {
        let token = random_hex24(&self.rng);
        locked(&self.redemptions).try_lease(
            key,
            self.clock.now_ms(),
            lease_ttl_secs,
            self.max_entries,
            token,
        )
    }

    pub fn commit_redemption(&self, key: &str, token: &str, retention_secs: u64) -> Commit {
        locked(&self.redemptions).commit(key, token, self.clock.now_ms(), retention_secs)
    }

    pub fn release_redemption(&self, key: &str, token: &str) {
        locked(&self.redemptions).release(key, token);
    }

    /// Drop expired nonces (the periodic prune that bounds memory independent of issue cadence).
    pub fn prune(&self) {
        locked(&self.nonces).prune(self.clock.now_ms());
    }

    /// Live nonce count.
    pub fn nonce_count(&self) -> usize {
        locked(&self.nonces).len()
    }
}

/// Per-scope budgets (requests per minute, `0` = unlimited).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateBudgets {
    /// Per client IP: `GET /v1/challenge` AND public paths (one shared bucket per IP, as gateway-rust
    /// has always done).
    pub ip: u32,
    /// Per client IP for gated requests, before verification.
    pub gated_preauth: u32,
    /// Per verified address.
    pub address: u32,
}

/// Fixed 60-second windows per key, in process memory.
pub struct MemoryRates<C: Clock> {
    clock: C,
    budgets: RateBudgets,
    ip: Mutex<RateTable>,
    preauth: Mutex<RateTable>,
    address: Mutex<RateTable>,
}

impl<C: Clock> MemoryRates<C> {
    pub fn new(clock: C, budgets: RateBudgets) -> Self {
        Self {
            clock,
            budgets,
            ip: Mutex::new(RateTable::new()),
            preauth: Mutex::new(RateTable::new()),
            address: Mutex::new(RateTable::new()),
        }
    }

    /// Charge one request; `false` when the key's budget for the current window is spent.
    pub fn check(&self, scope: RateScope, key: &str) -> bool {
        let (table, budget) = match scope {
            RateScope::Challenge | RateScope::Public => (&self.ip, self.budgets.ip),
            RateScope::GatedPreauth => (&self.preauth, self.budgets.gated_preauth),
            RateScope::Address => (&self.address, self.budgets.address),
        };
        locked(table).check(key, self.clock.now_ms(), u64::from(budget))
    }
}

/// The whole [`StateStore`] in memory: what a single-replica gateway runs and what tests use.
pub struct MemoryState<C: Clock + Clone, R: Rng> {
    pub store: MemoryStore<C, R>,
    pub rates: MemoryRates<C>,
}

impl<C: Clock + Clone, R: Rng> MemoryState<C, R> {
    pub fn new(
        clock: C,
        rng: R,
        challenge_ttl_secs: u64,
        max_entries: usize,
        budgets: RateBudgets,
    ) -> Self {
        Self {
            store: MemoryStore::new(clock.clone(), rng, challenge_ttl_secs, max_entries),
            rates: MemoryRates::new(clock, budgets),
        }
    }
}

impl<C: Clock + Clone, R: Rng> StateStore for MemoryState<C, R> {
    async fn issue_nonce(&self) -> anyhow::Result<(String, u64)> {
        Ok(self.store.issue_nonce())
    }

    async fn take_nonce(&self, nonce: &str) -> anyhow::Result<bool> {
        Ok(self.store.take_nonce(nonce))
    }

    async fn rate_check(&self, scope: RateScope, key: &str) -> bool {
        self.rates.check(scope, key)
    }

    async fn try_lease_redemption(&self, key: &str, lease_ttl_secs: u64) -> anyhow::Result<Lease> {
        Ok(self.store.try_lease_redemption(key, lease_ttl_secs))
    }

    async fn commit_redemption(
        &self,
        key: &str,
        token: &str,
        retention_secs: u64,
    ) -> anyhow::Result<Commit> {
        Ok(self.store.commit_redemption(key, token, retention_secs))
    }

    async fn release_redemption(&self, key: &str, token: &str) {
        self.store.release_redemption(key, token);
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// A clock the test moves by hand.
    #[derive(Clone, Default)]
    pub struct ManualClock(pub Rc<Cell<u64>>);

    impl ManualClock {
        pub fn advance(&self, ms: u64) {
            self.0.set(self.0.get() + ms);
        }
    }

    impl Clock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.0.get()
        }
    }

    /// A counter, not randomness: deterministic tokens for assertions.
    #[derive(Default)]
    pub struct CountingRng(pub Cell<u8>);

    impl Rng for CountingRng {
        fn fill(&self, buf: &mut [u8]) {
            let n = self.0.get().wrapping_add(1);
            self.0.set(n);
            buf.fill(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    fn store(ttl: u64, cap: usize) -> (ManualClock, MemoryStore<ManualClock, CountingRng>) {
        let clock = ManualClock::default();
        let s = MemoryStore::new(clock.clone(), CountingRng::default(), ttl, cap);
        (clock, s)
    }

    #[test]
    fn nonce_valid_once_then_used() {
        let (_, s) = store(300, 100);
        let (nonce, _) = s.issue_nonce();
        assert_eq!(nonce.len(), 48);
        assert!(s.take_nonce(&nonce));
        assert!(!s.take_nonce(&nonce)); // already used
        assert!(!s.take_nonce("never-issued"));
    }

    #[test]
    fn nonce_expires_and_reports_its_expiry() {
        let (clock, s) = store(1, 100);
        clock.advance(5_000);
        let (nonce, expires_at) = s.issue_nonce();
        assert_eq!(expires_at, 6_000);
        clock.advance(1_000);
        assert!(!s.take_nonce(&nonce)); // expired exactly at its expiry
        let (zero, _) = store(0, 100).1.issue_nonce();
        assert!(!store(0, 100).1.take_nonce(&zero));
    }

    #[test]
    fn hard_cap_bounds_memory_and_prune_drops_expired() {
        let (_, s) = store(300, 4);
        for _ in 0..20 {
            s.issue_nonce();
        }
        assert!(
            s.nonce_count() <= 4,
            "entry count must stay within the hard cap"
        );
        let (clock, s) = store(1, 100);
        s.issue_nonce();
        clock.advance(2_000);
        s.prune();
        assert_eq!(s.nonce_count(), 0);
    }

    fn lease(s: &MemoryStore<ManualClock, CountingRng>, key: &str, ttl: u64) -> String {
        match s.try_lease_redemption(key, ttl) {
            Lease::Ok(t) => t,
            other => panic!("expected a lease, got {other:?}"),
        }
    }

    #[test]
    fn redemption_lease_commit_blocks_reuse() {
        let (_, s) = store(300, 100);
        let token = lease(&s, "0xd", 120);
        assert_eq!(s.try_lease_redemption("0xd", 120), Lease::Leased);
        assert_eq!(s.commit_redemption("0xd", &token, 3600), Commit::Ok);
        assert_eq!(s.try_lease_redemption("0xd", 120), Lease::Redeemed);
    }

    #[test]
    fn redemption_release_allows_retry_and_never_clears_a_commit() {
        let (_, s) = store(300, 100);
        let token = lease(&s, "0xd", 120);
        s.release_redemption("0xd", &token); // upload failed
        let token = lease(&s, "0xd", 120); // retry with the same consume
        s.commit_redemption("0xd", &token, 3600);
        s.release_redemption("0xd", &token); // a no-op on a committed key
        assert_eq!(s.try_lease_redemption("0xd", 120), Lease::Redeemed);
    }

    #[test]
    fn an_expired_lease_is_reclaimable_and_its_stale_holder_loses() {
        let (clock, s) = store(300, 100);
        let stale = lease(&s, "0xd", 0); // lapses at once
        let fresh = lease(&s, "0xd", 120); // reclaimed, not stuck
        assert_ne!(stale, fresh);
        s.release_redemption("0xd", &stale); // must not clear the newer lease
        assert_eq!(s.try_lease_redemption("0xd", 120), Lease::Leased);
        assert_eq!(s.commit_redemption("0xd", &stale, 3600), Commit::Lost);
        assert_eq!(s.commit_redemption("0xd", &fresh, 3600), Commit::Ok);
        assert_eq!(s.try_lease_redemption("0xd", 120), Lease::Redeemed);
        // A commit after the lease lapsed is lost.
        let token = lease(&s, "0xe", 1);
        clock.advance(1_000);
        assert_eq!(s.commit_redemption("0xe", &token, 3600), Commit::Lost);
    }

    #[test]
    fn rate_windows_are_per_scope_and_zero_disables() {
        let clock = ManualClock::default();
        let rates = MemoryRates::new(
            clock.clone(),
            RateBudgets {
                ip: 3,
                gated_preauth: 1,
                address: 0,
            },
        );
        assert!(rates.check(RateScope::Challenge, "a"));
        assert!(rates.check(RateScope::Public, "a")); // one bucket per IP for both
        assert!(rates.check(RateScope::Challenge, "a"));
        assert!(!rates.check(RateScope::Challenge, "a")); // 4th within the window
        assert!(rates.check(RateScope::Challenge, "b")); // independent key
        assert!(rates.check(RateScope::GatedPreauth, "a"));
        assert!(!rates.check(RateScope::GatedPreauth, "a"));
        for _ in 0..100 {
            assert!(rates.check(RateScope::Address, "x")); // 0 disables
        }
        clock.advance(60_000);
        assert!(rates.check(RateScope::Challenge, "a")); // a new window
    }

    #[test]
    fn memory_state_is_a_state_store() {
        let state = MemoryState::new(
            ManualClock::default(),
            CountingRng::default(),
            300,
            100,
            RateBudgets {
                ip: 30,
                gated_preauth: 30,
                address: 30,
            },
        );
        pollster::block_on(async {
            let (nonce, _) = state.issue_nonce().await.unwrap();
            assert!(state.take_nonce(&nonce).await.unwrap());
            assert!(!state.take_nonce(&nonce).await.unwrap());
            assert!(state.rate_check(RateScope::Address, "k").await);
        });
    }
}
