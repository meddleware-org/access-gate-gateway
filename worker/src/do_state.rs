//! SQLite-backed Durable Object: nonce store + rate limiter + redemption (lease / commit /
//! release with compare-and-set tokens). Same tables and the same statements as
//! `gateway-workers/src/state/durable_object.ts`; the state machine is also implemented purely in
//! `nft_gate_core::redemption`, and `scripts/differential.mjs` + `core/tests` run one scenario file
//! through both. The DO is single-threaded and every operation below is a synchronous section (no
//! `.await` between the read and the write), so each is atomic — the Redis-GETDEL analogue.
//!
//! workers-rs Durable Objects speak `fetch` only (no RPC methods), so operations are internal
//! HTTP requests to the stub.
use serde::Deserialize;
use worker::*;

#[durable_object]
pub struct NonceRateState {
    sql: SqlStorage,
    test_clock: bool,
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
    #[allow(dead_code)]
    token: Option<String>,
}

fn sv<T: Into<SqlStorageValue>>(v: T) -> SqlStorageValue {
    v.into()
}

fn random_token() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("crypto.getRandomValues");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl NonceRateState {
    fn exec(&self, q: &str, b: Vec<SqlStorageValue>) -> Result<SqlCursor> {
        self.sql.exec(q, b)
    }

    fn issue(&self, nonce: &str, now: i64, ttl_secs: i64, max_entries: i64) -> Result<i64> {
        let expiry = now + ttl_secs * 1000;
        self.exec("DELETE FROM nonces WHERE expiry <= ?", vec![sv(now)])?;
        let c: Count = self
            .exec("SELECT COUNT(*) AS c FROM nonces", vec![])?
            .one()?;
        if c.c as i64 >= max_entries.max(1) {
            self.exec("DELETE FROM nonces WHERE nonce = (SELECT nonce FROM nonces ORDER BY expiry ASC LIMIT 1)", vec![])?;
        }
        self.exec(
            "INSERT OR REPLACE INTO nonces (nonce, expiry) VALUES (?, ?)",
            vec![sv(nonce), sv(expiry)],
        )?;
        Ok(expiry)
    }

    fn take_if_valid(&self, nonce: &str, now: i64) -> Result<bool> {
        let rows: Vec<Expiry> = self
            .exec("SELECT expiry FROM nonces WHERE nonce = ?", vec![sv(nonce)])?
            .to_array()?;
        let Some(r) = rows.first() else {
            return Ok(false);
        };
        self.exec("DELETE FROM nonces WHERE nonce = ?", vec![sv(nonce)])?;
        Ok(r.expiry as i64 > now)
    }

    fn rate_check(&self, addr: &str, max_per_min: i64, now: i64) -> Result<bool> {
        if max_per_min == 0 {
            return Ok(true);
        }
        let rows: Vec<RateRow> = self
            .exec(
                "SELECT start, count FROM rate WHERE addr = ?",
                vec![sv(addr)],
            )?
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
        self.exec(
            "INSERT OR REPLACE INTO rate (addr, start, count) VALUES (?, ?, ?)",
            vec![sv(addr), sv(start), sv(count + 1)],
        )?;
        Ok(true)
    }

    /// `Some(token)` = ok, `None` + status string otherwise.
    fn lease(
        &self,
        key: &str,
        now: i64,
        ttl_secs: i64,
        max_entries: i64,
    ) -> Result<(&'static str, Option<String>)> {
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
                return Ok(("redeemed", None));
            }
            if r.state == "leased" && r.expiry as i64 > now {
                return Ok(("leased", None));
            }
        }
        let c: Count = self
            .exec("SELECT COUNT(*) AS c FROM redemptions", vec![])?
            .one()?;
        if c.c as i64 >= max_entries.max(1) {
            self.exec("DELETE FROM redemptions WHERE key = (SELECT key FROM redemptions WHERE state = 'leased' ORDER BY expiry ASC LIMIT 1)", vec![])?;
        }
        let token = random_token();
        self.exec(
            "INSERT OR REPLACE INTO redemptions (key, state, expiry, token) VALUES (?, 'leased', ?, ?)",
            vec![sv(key), sv(now + ttl_secs * 1000), sv(token.as_str())],
        )?;
        Ok(("ok", Some(token)))
    }

    fn commit(&self, key: &str, token: &str, now: i64, retention_secs: i64) -> Result<bool> {
        let cur = self
            .exec("SELECT 1 AS x FROM redemptions WHERE key = ? AND state = 'leased' AND token = ? AND expiry > ?", vec![sv(key), sv(token), sv(now)])?
            .raw()
            .count();
        if cur == 0 {
            return Ok(false);
        }
        self.exec(
            "UPDATE redemptions SET state = 'committed', expiry = ?, token = NULL WHERE key = ? AND state = 'leased' AND token = ?",
            vec![sv(now + retention_secs * 1000), sv(key), sv(token)],
        )?;
        Ok(true)
    }

    fn release(&self, key: &str, token: &str) -> Result<()> {
        self.exec(
            "DELETE FROM redemptions WHERE key = ? AND state = 'leased' AND token = ?",
            vec![sv(key), sv(token)],
        )?;
        Ok(())
    }
}

impl DurableObject for NonceRateState {
    fn new(state: State, env: Env) -> Self {
        let sql = state.storage().sql();
        for q in [
            "CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expiry INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS rate (addr TEXT PRIMARY KEY, start INTEGER NOT NULL, count INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS redemptions (key TEXT PRIMARY KEY, state TEXT NOT NULL, expiry INTEGER NOT NULL, token TEXT)",
        ] {
            sql.exec(q, None).expect("schema");
        }
        let test_clock = env
            .var("TEST_CLOCK")
            .map(|v| v.to_string() == "1")
            .unwrap_or(false);
        Self { sql, test_clock }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        let get = |k: &str| q.get(k).cloned().unwrap_or_default();
        let int = |k: &str, d: i64| q.get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
        // Deterministic scenarios may pin the clock (only when TEST_CLOCK=1; never in production).
        let now = if self.test_clock && q.contains_key("now") {
            int("now", 0)
        } else {
            js_sys::Date::now() as i64
        };
        let op = url.path().rsplit('/').next().unwrap_or("");
        let body = match op {
            "issue" => {
                serde_json::json!({ "expiresAt": self.issue(&get("nonce"), now, int("ttl", 300), int("max", 1_000_000))? })
            }
            "take" => serde_json::json!({ "ok": self.take_if_valid(&get("nonce"), now)? }),
            "rate" => {
                serde_json::json!({ "ok": self.rate_check(&get("addr"), int("max", 30), now)? })
            }
            "lease" => {
                let (status, token) =
                    self.lease(&get("key"), now, int("ttl", 900), int("max", 1_000_000))?;
                serde_json::json!({ "status": status, "token": token })
            }
            "commit" => {
                serde_json::json!({ "result": if self.commit(&get("key"), &get("token"), now, int("retention", 2_592_000))? { "ok" } else { "lost" } })
            }
            "release" => {
                self.release(&get("key"), &get("token"))?;
                serde_json::json!({ "ok": true })
            }
            _ => return Response::error("unknown op", 404),
        };
        Response::from_json(&body)
    }
}

/// `/do/<shard>/<op>?…`: route to the DO instance `nonce:<shard>`.
pub async fn route(req: Request, env: Env) -> Result<Response> {
    let url = req.url()?;
    let mut parts = url.path().trim_start_matches("/do/").splitn(2, '/');
    let shard = parts.next().unwrap_or("g");
    let op = parts.next().unwrap_or("");
    let ns = env.durable_object("NONCE_STATE")?;
    let stub = ns.id_from_name(&format!("nonce:{shard}"))?.get_stub()?;
    let mut inner = Url::parse("https://do.internal/")?;
    inner.set_path(op);
    inner.set_query(url.query());
    stub.fetch_with_str(inner.as_str()).await
}
