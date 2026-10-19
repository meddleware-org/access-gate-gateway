//! The SQLite-backed Durable Object `NonceRateState`: nonce store, rate windows and redemption
//! leases. Same class name, same tables, same statements as `gateway-workers/src/state/durable_object.ts`
//! (a deploy over the live script keeps its data); `core/tests/scenario.json` pins the rules, run
//! against this SQL by `tests/` and against the pure state machines by `core/tests/scenario.rs`.
//!
//! The DO is single-threaded and every operation below is one synchronous section (no `.await`
//! between the read and the write), so each is atomic (the Redis `GETDEL` analogue). workers-rs
//! Durable Objects speak `fetch` only (no RPC methods), so an operation is an internal HTTP request to
//! the stub, answered with a small JSON body.

use serde::Deserialize;
use worker::*;

#[durable_object]
pub struct NonceRateState {
    sql: SqlStorage,
}

#[derive(Deserialize)]
struct Expiry {
    expiry: f64,
}
#[derive(Deserialize)]
struct RateRow {
    start: f64,
    count: f64,
}
#[derive(Deserialize)]
struct Count {
    c: f64,
}
#[derive(Deserialize)]
struct RedRow {
    state: String,
    expiry: f64,
}
#[derive(Deserialize)]
struct ColName {
    name: String,
}

fn sv<T: Into<SqlStorageValue>>(v: T) -> SqlStorageValue {
    v.into()
}

/// 16 random bytes as hex: the owner token of a lease.
fn random_token() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|e| Error::RustError(format!("entropy: {e}")))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// What a lease attempt returned.
enum LeaseOutcome {
    Ok(String),
    Leased,
    Redeemed,
}

impl NonceRateState {
    fn exec(&self, q: &str, b: Vec<SqlStorageValue>) -> Result<SqlCursor> {
        self.sql.exec(q, b)
    }

    fn count(&self, q: &str) -> Result<i64> {
        let c: Count = self.exec(q, vec![])?.one()?;
        Ok(c.c as i64)
    }

    /// Store a fresh nonce with a hard entry cap (evict soonest-to-expire). Returns the expiry (ms).
    fn issue(&self, nonce: &str, now: i64, ttl_secs: i64, max_entries: i64) -> Result<i64> {
        let expiry = now.saturating_add(ttl_secs.saturating_mul(1000));
        // Prune expired first (bounded growth independent of issue cadence).
        self.exec("DELETE FROM nonces WHERE expiry <= ?", vec![sv(now)])?;
        if self.count("SELECT COUNT(*) AS c FROM nonces")? >= max_entries.max(1) {
            self.exec(
                "DELETE FROM nonces WHERE nonce = (SELECT nonce FROM nonces ORDER BY expiry ASC LIMIT 1)",
                vec![],
            )?;
        }
        self.exec(
            "INSERT OR REPLACE INTO nonces (nonce, expiry) VALUES (?, ?)",
            vec![sv(nonce), sv(expiry)],
        )?;
        Ok(expiry)
    }

    /// Atomically consume a nonce: true iff present and unexpired. Deletes on read (single use).
    fn take_if_valid(&self, nonce: &str, now: i64) -> Result<bool> {
        let rows: Vec<Expiry> = self
            .exec("SELECT expiry FROM nonces WHERE nonce = ?", vec![sv(nonce)])?
            .to_array()?;
        let Some(r) = rows.first() else {
            return Ok(false);
        };
        // Consume unconditionally (present means gone), so it can never be replayed.
        self.exec("DELETE FROM nonces WHERE nonce = ?", vec![sv(nonce)])?;
        Ok(r.expiry as i64 > now)
    }

    /// Fixed 60 s window per key; `max_per_min == 0` disables limiting.
    fn rate_check(&self, addr: &str, max_per_min: i64, now: i64) -> Result<bool> {
        if max_per_min == 0 {
            return Ok(true);
        }
        let rows: Vec<RateRow> = self
            .exec("SELECT start, count FROM rate WHERE addr = ?", vec![sv(addr)])?
            .to_array()?;
        let (mut start, mut count) = (now, 0i64);
        if let Some(r) = rows.first() {
            if now - (r.start as i64) < 60_000 {
                start = r.start as i64;
                count = r.count as i64;
            }
        }
        if count >= max_per_min {
            return Ok(false);
        }
        // Windows older than a minute are dead weight: sweep them now and then so the table is
        // bounded by the keys seen in the last minute rather than every key ever seen.
        if js_sys::Math::random() < 0.02 {
            self.exec("DELETE FROM rate WHERE start < ?", vec![sv(now - 60_000)])?;
        }
        self.exec(
            "INSERT OR REPLACE INTO rate (addr, start, count) VALUES (?, ?, ?)",
            vec![sv(addr), sv(start), sv(count + 1)],
        )?;
        Ok(true)
    }

    /// Claim `key` for an in-flight upload: `redeemed` if committed, `leased` if an unexpired lease
    /// is held, else `ok` with the owner token of a fresh lease. An expired lease is reclaimable.
    fn lease(&self, key: &str, now: i64, ttl_secs: i64, max_entries: i64) -> Result<LeaseOutcome> {
        // Bounded growth: drop expired leases and lapsed committed rows before inserting.
        self.exec(
            "DELETE FROM redemptions WHERE state = 'leased' AND expiry <= ?",
            vec![sv(now)],
        )?;
        self.exec(
            "DELETE FROM redemptions WHERE state = 'committed' AND expiry <= ?",
            vec![sv(now)],
        )?;
        let rows: Vec<RedRow> = self
            .exec(
                "SELECT state, expiry, token FROM redemptions WHERE key = ?",
                vec![sv(key)],
            )?
            .to_array()?;
        if let Some(r) = rows.first() {
            if r.state == "committed" {
                return Ok(LeaseOutcome::Redeemed);
            }
            if r.state == "leased" && r.expiry as i64 > now {
                return Ok(LeaseOutcome::Leased);
            }
        }
        if self.count("SELECT COUNT(*) AS c FROM redemptions")? >= max_entries.max(1) {
            // Evict the soonest-to-expire leased row (never a committed one: that would allow reuse).
            self.exec(
                "DELETE FROM redemptions WHERE key = (SELECT key FROM redemptions WHERE state = 'leased' ORDER BY expiry ASC LIMIT 1)",
                vec![],
            )?;
        }
        let token = random_token()?;
        self.exec(
            "INSERT OR REPLACE INTO redemptions (key, state, expiry, token) VALUES (?, 'leased', ?, ?)",
            vec![
                sv(key),
                sv(now.saturating_add(ttl_secs.saturating_mul(1000))),
                sv(token.as_str()),
            ],
        )?;
        Ok(LeaseOutcome::Ok(token))
    }

    /// Mark `key` redeemed (retained `retention_secs`) iff `token` still owns an unexpired lease.
    fn commit(&self, key: &str, token: &str, now: i64, retention_secs: i64) -> Result<bool> {
        let live = self
            .exec(
                "SELECT 1 AS x FROM redemptions WHERE key = ? AND state = 'leased' AND token = ? AND expiry > ?",
                vec![sv(key), sv(token), sv(now)],
            )?
            .raw()
            .count();
        if live == 0 {
            return Ok(false);
        }
        self.exec(
            "UPDATE redemptions SET state = 'committed', expiry = ?, token = NULL WHERE key = ? AND state = 'leased' AND token = ?",
            vec![
                sv(now.saturating_add(retention_secs.saturating_mul(1000))),
                sv(key),
                sv(token),
            ],
        )?;
        Ok(true)
    }

    /// Release the lease on `key` iff `token` owns it, so the consume can be retried at once.
    fn release(&self, key: &str, token: &str) -> Result<()> {
        self.exec(
            "DELETE FROM redemptions WHERE key = ? AND state = 'leased' AND token = ?",
            vec![sv(key), sv(token)],
        )?;
        Ok(())
    }

    /// Create the tables; add the owner-token column to a `redemptions` table that predates it.
    fn migrate(&self) -> Result<()> {
        for q in [
            "CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expiry INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS rate (addr TEXT PRIMARY KEY, start INTEGER NOT NULL, count INTEGER NOT NULL)",
            // `state` is 'leased' (an in-flight upload holds the consume) or 'committed' (the use was
            // spent on a successful upload). `expiry` is the lease deadline / committed retention
            // deadline (unix ms). `token` is the random owner of a lease: commit and release compare
            // it, so a request whose lease lapsed cannot touch a newer holder's row.
            "CREATE TABLE IF NOT EXISTS redemptions (key TEXT PRIMARY KEY, state TEXT NOT NULL, expiry INTEGER NOT NULL, token TEXT)",
        ] {
            self.exec(q, vec![])?;
        }
        // Tables created before owner tokens existed lack the column; add it (idempotent).
        let cols: Vec<ColName> = self
            .exec("PRAGMA table_info('redemptions')", vec![])?
            .to_array()?;
        if !cols.iter().any(|c| c.name == "token") {
            self.exec("ALTER TABLE redemptions ADD COLUMN token TEXT", vec![])?;
        }
        Ok(())
    }

    fn dispatch(&self, op: &str, q: &std::collections::HashMap<String, String>, now: i64) -> Result<serde_json::Value> {
        let get = |k: &str| q.get(k).map_or("", String::as_str);
        let int = |k: &str, d: i64| q.get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
        Ok(match op {
            "issue" => serde_json::json!({
                "expiresAt": self.issue(get("nonce"), now, int("ttl", 300), int("max", 1_000_000))?
            }),
            "take" => serde_json::json!({ "ok": self.take_if_valid(get("nonce"), now)? }),
            "rate" => serde_json::json!({ "ok": self.rate_check(get("addr"), int("max", 30), now)? }),
            "lease" => {
                match self.lease(get("key"), now, int("ttl", 900), int("max", 1_000_000))? {
                    LeaseOutcome::Ok(t) => serde_json::json!({ "status": "ok", "token": t }),
                    LeaseOutcome::Leased => serde_json::json!({ "status": "leased" }),
                    LeaseOutcome::Redeemed => serde_json::json!({ "status": "redeemed" }),
                }
            }
            "commit" => {
                let ok = self.commit(get("key"), get("token"), now, int("retention", 2_592_000))?;
                serde_json::json!({ "result": if ok { "ok" } else { "lost" } })
            }
            "release" => {
                self.release(get("key"), get("token"))?;
                serde_json::json!({ "ok": true })
            }
            // Test-only (feature `test-hooks`): raw SQL and a re-run of the schema setup, to prove the
            // upgrade of a table that predates the owner-token column.
            #[cfg(feature = "test-hooks")]
            "sql" => {
                let rows: Vec<serde_json::Value> = self.exec(get("q"), vec![])?.to_array()?;
                serde_json::json!({ "rows": rows })
            }
            #[cfg(feature = "test-hooks")]
            "migrate" => {
                self.migrate()?;
                serde_json::json!({ "ok": true })
            }
            _ => return Err(Error::RustError("unknown op".into())),
        })
    }
}

impl DurableObject for NonceRateState {
    fn new(state: State, _env: Env) -> Self {
        let this = Self {
            sql: state.storage().sql(),
        };
        // A failure here leaves the tables missing; every operation then errors and the Worker
        // answers 503 (fail closed) instead of running without state.
        if let Err(e) = this.migrate() {
            console_error!("durable object schema setup failed: {e}");
        }
        this
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let q: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
        let op = url.path().trim_start_matches('/');
        // The clock is the platform's. Only the test-hooks build lets a scenario pin it.
        #[cfg(feature = "test-hooks")]
        let now = q
            .get("now")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(js_sys::Date::now() as i64);
        #[cfg(not(feature = "test-hooks"))]
        let now = js_sys::Date::now() as i64;
        match self.dispatch(op, &q, now) {
            Ok(body) => Response::from_json(&body),
            Err(e) => {
                console_error!("durable object op {op} failed: {e}");
                Ok(Response::from_json(&serde_json::json!({ "error": "state" }))?.with_status(500))
            }
        }
    }
}
