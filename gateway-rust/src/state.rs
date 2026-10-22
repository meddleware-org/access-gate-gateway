//! The native platform ports: the system clock and OS entropy, and [`NativeState`], the
//! [`StateStore`] the shared orchestration (`nft_gate_core::gateway`) talks to. It composes the nonce /
//! redemption backend chosen at startup ([`NonceStore`]: memory or Redis) with the in-memory rate
//! windows, so the gateway's state rules are the core's, whichever backend holds the bytes.

use crate::challenge::NonceStore;
use nft_gate_core::redemption::{Commit, Lease};
use nft_gate_core::state::{Clock, MemoryRates, RateScope, Rng, StateStore};
use rand_core::{OsRng, RngCore};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Wall-clock milliseconds since the Unix epoch (for values shown to clients and handed to Redis).
pub fn wall_ms() -> u64 {
    unix_ms(SystemTime::now())
}

/// `t` as Unix milliseconds. A clock set before 1970 reads as `0` and is logged, never a panic (with
/// `panic = "abort"` a panic here would restart the process on every call, and a restart empties the
/// in-memory stores): every expiry then runs from epoch 0, which is wrong but fails no request open.
fn unix_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or_else(
        |e| {
            tracing::error!(
                behind_by_secs = e.duration().as_secs(),
                "the system clock is before 1970-01-01; using 0 as the wall time"
            );
            0
        },
        |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
    )
}

/// Unix milliseconds that never go backwards: the wall time at startup plus the monotonic time since,
/// so a stepped system clock cannot make a nonce, lease or rate window outlive (or cut short) its TTL.
#[derive(Clone, Copy)]
pub struct SystemClock {
    wall_at_start: u64,
    start: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            wall_at_start: wall_ms(),
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        self.wall_at_start
            .saturating_add(self.start.elapsed().as_millis() as u64)
    }
}

/// Operating-system entropy.
pub struct OsRngSource;

impl Rng for OsRngSource {
    fn fill(&self, buf: &mut [u8]) {
        OsRng.fill_bytes(buf);
    }
}

/// The per-request view of the server's state: the nonce / redemption backend plus the rate windows.
pub struct NativeState<'a> {
    pub store: &'a NonceStore,
    pub rates: &'a MemoryRates<SystemClock>,
}

impl StateStore for NativeState<'_> {
    async fn issue_nonce(&self) -> anyhow::Result<(String, u64)> {
        self.store.issue().await
    }

    async fn take_nonce(&self, nonce: &str) -> anyhow::Result<bool> {
        self.store.take_if_valid(nonce).await
    }

    async fn rate_check(&self, scope: RateScope, key: &str) -> anyhow::Result<bool> {
        Ok(self.rates.check(scope, key))
    }

    async fn try_lease_redemption(&self, key: &str, lease_ttl_secs: u64) -> anyhow::Result<Lease> {
        self.store.try_lease_redemption(key, lease_ttl_secs).await
    }

    async fn commit_redemption(
        &self,
        key: &str,
        token: &str,
        retention_secs: u64,
    ) -> anyhow::Result<Commit> {
        self.store
            .commit_redemption(key, token, retention_secs)
            .await
    }

    async fn release_redemption(&self, key: &str, token: &str) {
        self.store.release_redemption(key, token).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_reads_unix_time_and_never_goes_backwards() {
        let c = SystemClock::new();
        let a = c.now_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let b = c.now_ms();
        assert!(b >= a + 5, "{a} -> {b}");
        assert!(a.abs_diff(wall_ms()) < 1000, "anchored to the wall clock");
    }

    #[test]
    fn a_clock_before_1970_reads_as_zero_instead_of_panicking() {
        use std::time::Duration;
        assert_eq!(unix_ms(UNIX_EPOCH - Duration::from_secs(5)), 0);
        assert_eq!(unix_ms(UNIX_EPOCH), 0);
        assert_eq!(unix_ms(UNIX_EPOCH + Duration::from_millis(1_234)), 1_234);
    }

    #[test]
    fn the_os_source_fills_with_entropy() {
        let (mut x, mut y) = ([0u8; 24], [0u8; 24]);
        OsRngSource.fill(&mut x);
        OsRngSource.fill(&mut y);
        assert_ne!(x, y);
        assert_ne!(x, [0u8; 24]);
    }
}
