//! The request orchestration: the one implementation of what the gateway does with a request, as a
//! state machine over traits. A platform supplies only I/O:
//!
//! | Port | Role | gateway-rust | Cloudflare Worker |
//! | --- | --- | --- | --- |
//! | [`StateStore`] | nonces, rate windows, redemptions | memory or Redis | Durable Object |
//! | [`ChainQuery`] | Sui reads | [`crate::chain::SuiRpc`] over hyper | the same over `fetch` |
//! | [`Upstream`] | move the request to the protected origin | buffered hyper client | streamed `fetch` |
//!
//! The platform turns its native request into a [`RequestHead`] (the few fields the decision reads) plus
//! its own opaque request value `U::Request`, calls [`Gateway::handle`], and renders the returned
//! [`Reply`]: a gateway-generated [`JsonReply`], or the upstream's own response untouched. `/healthz`,
//! CORS and the platform's connection limits stay in the adapter; everything else is here.
//!
//! Order of work (a request that fails a step never reaches the next):
//!
//! 1. loop guard (`Via` already names this gateway) → 508, before any state is touched;
//! 2. `GET /v1/challenge` → per-IP rate limit (429), issue a nonce (503 when the store cannot record it);
//! 3. a public path → `GET`/`HEAD` only (405 + `Allow`), per-IP rate limit, forward;
//! 4. a method that is not forwardable → 405;
//! 5. no access proof → 401;
//! 6. per-IP pre-auth rate limit (429), BEFORE the signature work;
//! 7. verification ([`crate::decision`]) → 403 / 502 (chain) / 503 (state);
//! 8. per-address rate limit (429);
//! 9. ownership mode: forward. Single-use mode: [`Gateway::redeem_and_forward`].

use crate::config::GatewayConfig;
use crate::decision::{verify_access_request, ChainQuery, Denied, VerifyParams};
use crate::forward::is_forwarded_method;
use crate::headers::{extract_proof_token, via_is_looped};
use crate::redemption::{Commit, Lease};
use crate::state::{RateScope, StateStore};
use serde_json::{json, Value};

/// What the decision reads from a request. The platform derives it once; the request itself (with its
/// body) travels separately as [`Upstream::Request`].
#[derive(Debug, Clone, Default)]
pub struct RequestHead {
    /// The method as received (`GET`, `POST`, ...).
    pub method: String,
    /// The path, without the query string.
    pub path: String,
    /// The `Authorization` header value, if any.
    pub authorization: Option<String>,
    /// The `X-Access-Proof` header value, if any.
    pub x_access_proof: Option<String>,
    /// Every `Via` field value joined with `,`, if any.
    pub via: Option<String>,
    /// The rate-limit key for the client (see [`crate::net::client_ip`]); never an authenticator.
    pub client_ip: String,
}

/// An answer the gateway generates itself (as opposed to an upstream's response).
#[derive(Debug, Clone, PartialEq)]
pub struct JsonReply {
    /// The HTTP status.
    pub status: u16,
    /// The JSON body: `{"error": reason}`, `{"error", "code"}`, or `{"nonce", "expiresAt"}`.
    pub body: Value,
    /// An `Allow` header to send with it (405 on a public path).
    pub allow: Option<&'static str>,
    /// Operator-only detail for the log (a store or commit failure). Never sent to the client.
    pub diag: Option<String>,
}

impl JsonReply {
    /// A reply with a status and a JSON body, no `Allow` header and no diagnostic.
    fn new(status: u16, body: Value) -> Self {
        Self {
            status,
            body,
            allow: None,
            diag: None,
        }
    }

    /// `{"error": reason}`.
    pub fn error(status: u16, reason: &str) -> Self {
        Self::new(status, json!({ "error": reason }))
    }

    /// `{"error": reason, "code": code}`: the machine-readable code a client can act on.
    pub fn coded(status: u16, reason: &str, code: &str) -> Self {
        Self::new(status, json!({ "error": reason, "code": code }))
    }

    /// Attach operator-only detail for the log.
    fn with_diag(mut self, diag: String) -> Self {
        self.diag = Some(diag);
        self
    }
}

/// The outcome of [`Gateway::handle`].
#[derive(Debug)]
pub enum Reply<R> {
    /// The gateway answered itself.
    Json(JsonReply),
    /// The upstream's response, to be returned to the client (after the platform's response-header
    /// policy, which its [`Upstream`] already applied).
    Upstream(R),
}

/// Why a request is being forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardKind {
    /// An unauthenticated read-only public path (a platform may cache it).
    Public,
    /// A request that passed verification.
    Gated,
}

/// Move a request to the protected origin and bring the answer back.
///
/// The implementation owns everything about moving bytes: [`crate::forward::preflight`] (method, path,
/// declared size), the body read and its cap, the request/response header policy
/// ([`crate::headers`]), the configured upstream credentials, redirects ([`crate::forward::is_redirect`]
/// is a 502), timeouts (504) and the `Via: 1.1 access-gate-gateway` marker. A failure is returned as a response
/// with the refusal's status ([`crate::forward`]), never as a panic.
#[allow(async_fn_in_trait)]
pub trait Upstream {
    /// The platform's request, body included.
    type Request;
    /// The platform's response, body included (or streaming).
    type Response;

    /// Send the request to the protected origin and return its answer (or a refusal with the status the failure calls for).
    async fn forward(&self, req: Self::Request, kind: ForwardKind) -> Self::Response;

    /// The HTTP status of `resp`: a 2xx commits a single-use redemption, anything else releases it.
    fn status(&self, resp: &Self::Response) -> u16;
}

/// The gateway for one deployment: configuration plus its three ports. Cheap to build per request.
pub struct Gateway<'a, S, C, U> {
    /// The deployment's configuration.
    pub cfg: &'a GatewayConfig,
    /// The nonce, redemption and rate state.
    pub state: &'a S,
    /// The chain queries.
    pub chain: &'a C,
    /// The upstream the request is forwarded to.
    pub upstream: &'a U,
}

/// Map a denial to its reply: a chain error is 502, an unavailable store 503, anything else 403.
fn denied_reply(d: &Denied) -> JsonReply {
    let status = match d {
        Denied::ChainError => 502,
        Denied::StateUnavailable => 503,
        _ => 403,
    };
    JsonReply::error(status, d.reason())
}

/// A 429 reply.
fn rate_limited() -> JsonReply {
    JsonReply::error(429, "rate limit exceeded")
}

/// A 503 reply that hides the cause from the client and keeps it for the log.
fn unavailable(what: &str, e: &anyhow::Error) -> JsonReply {
    JsonReply::error(503, "gateway state unavailable").with_diag(format!("{what}: {e}"))
}

impl<S: StateStore, C: ChainQuery, U: Upstream> Gateway<'_, S, C, U> {
    /// Charge one request to a rate budget: 429 when the budget is spent, 503 when the store cannot
    /// answer (a request is never waved through unmetered).
    async fn charge(&self, scope: RateScope, key: &str) -> Result<(), JsonReply> {
        match self.state.rate_check(scope, key).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(rate_limited()),
            Err(e) => Err(unavailable("rate check failed", &e)),
        }
    }

    /// Handle one request. See the module docs for the order of work.
    pub async fn handle(&self, head: &RequestHead, req: U::Request) -> Reply<U::Response> {
        let cfg = self.cfg;
        // Shorthand for "answer from the gateway itself, do not forward".
        let json = |r: JsonReply| Reply::Json(r);

        // A request that already carries this gateway's own `Via` entry has looped back through it
        // (the upstream resolves to this gateway): refuse it before any nonce, rate-limit or
        // redemption work. `/healthz` and CORS preflights are answered before this point.
        if via_is_looped(head.via.as_deref().unwrap_or("")) {
            return json(JsonReply::error(508, "loop detected"));
        }

        // Step 2: the challenge endpoint. Only GET issues a nonce; any other method on this path is treated as a gated request below.
        if head.method == "GET" && head.path == "/v1/challenge" {
            if let Err(r) = self.charge(RateScope::Challenge, &head.client_ip).await {
                return json(r);
            }
            // Issue a nonce whose lifetime the store owns; a store failure is a 503 and never a made-up nonce.
            return json(match self.state.issue_nonce().await {
                Ok((nonce, expires_at)) => {
                    JsonReply::new(200, json!({ "nonce": nonce, "expiresAt": expires_at }))
                }
                Err(e) => unavailable("nonce issue failed", &e),
            });
        }

        // Public passthrough (e.g. /v1/tip-config): read-only. A body-carrying method would reach the
        // upstream with no proof, so only GET/HEAD are forwarded. Rate-limit per IP first.
        if cfg.is_public_path(&head.path) {
            // Safe methods only: the upstream would otherwise receive a write with no proof.
            if head.method != "GET" && head.method != "HEAD" {
                let mut r = JsonReply::error(405, "method not allowed");
                // A 405 must say what is allowed (RFC 9110 section 15.5.6).
                r.allow = Some("GET, HEAD");
                return json(r);
            }
            if let Err(r) = self.charge(RateScope::Public, &head.client_ip).await {
                return json(r);
            }
            // The public marker tells the upstream adapter not to attach the gated credentials.
            return Reply::Upstream(self.upstream.forward(req, ForwardKind::Public).await);
        }

        // Step 4: anything outside the forwarded set (for example DELETE) is refused before the proof is even read.
        if !is_forwarded_method(&head.method) {
            return json(JsonReply::error(405, "method not allowed"));
        }

        // The proof comes from `Authorization: Bearer` first, then `X-Access-Proof` for clients that cannot set `Authorization`.
        let Some(token) = extract_proof_token(
            head.authorization.as_deref(),
            head.x_access_proof.as_deref(),
        ) else {
            // No proof is a 401 (not a 403): the client has not tried to authenticate yet.
            return json(JsonReply::error(401, "missing access proof"));
        };

        // Verification costs CPU and a store call per request, so bound it per client first.
        if let Err(r) = self.charge(RateScope::GatedPreauth, &head.client_ip).await {
            return json(r);
        }

        // Step 6: verify the proof (signature, nonce, ownership, and the consume transaction in single-use mode).
        let verified =
            match verify_access_request(&VerifyParams::from(cfg), self.state, &token, self.chain)
                .await
            {
                Ok(v) => v,
                // Every denial is mapped in one place (`denied_reply`) so the status for each failure cannot drift.
                Err(d) => return json(denied_reply(&d)),
            };
        // Step 7: a second budget per verified address, so one wallet cannot use many IPs to get around the per-IP limit.
        if let Err(r) = self.charge(RateScope::Address, &verified.address).await {
            return json(r);
        }
        match verified.redemption_key {
            // Single-use mode: the consume digest is the redemption key.
            Some(key) => self.redeem_and_forward(&key, req).await,
            // Reusable mode: ownership alone is enough; nothing is leased.
            None => Reply::Upstream(self.upstream.forward(req, ForwardKind::Gated).await),
        }
    }

    /// Single-use: the permanent on-chain consume digest is the one-time token. Lease it (the lease
    /// returns an owner token), proxy, then COMMIT on a successful upload or RELEASE on failure, both
    /// presenting the token, so an interrupted upload leaves the consume redeemable, a duplicate can't
    /// double-spend it, and a request whose lease lapsed can never clear or overwrite a newer holder's.
    /// The lease outlives the body-read and upstream deadlines together (checked at startup). A commit
    /// that fails, or finds its lease lost, is a 502 (never success) and releases the lease so the same
    /// consume can be retried: a paid use is never lost to a commit failure (OQ6). A store error is a
    /// 503 (never a conflict).
    pub async fn redeem_and_forward(&self, key: &str, req: U::Request) -> Reply<U::Response> {
        let cfg = self.cfg;
        let token = match self
            .state
            .try_lease_redemption(key, cfg.redemption_lease_ttl_secs)
            .await
        {
            // The lease could not be asked for: that is an outage (503), so the consume stays unspent.
            Err(e) => return Reply::Json(unavailable("redemption store failed", &e)),
            // The consume was already used for an upload: a permanent 409 with the code `redeemed`.
            Ok(Lease::Redeemed) => {
                return Reply::Json(JsonReply::coded(
                    409,
                    "this consume has already been redeemed for an upload",
                    "redeemed",
                ))
            }
            // Another upload holds the lease right now: a 409 with the code `leased` that the client may retry later.
            Ok(Lease::Leased) => {
                return Reply::Json(JsonReply::coded(
                    409,
                    "an upload for this consume is already in progress",
                    "leased",
                ))
            }
            // We hold the lease; the owner token is what lets only this request commit or release it.
            Ok(Lease::Ok(token)) => token,
        };
        let resp = self.upstream.forward(req, ForwardKind::Gated).await;
        // Only a 2xx counts as a finished upload; a redirect or an error gives the lease back.
        if !(200..300).contains(&self.upstream.status(&resp)) {
            self.state.release_redemption(key, &token).await;
            return Reply::Upstream(resp);
        }
        match self
            .state
            .commit_redemption(key, &token, cfg.redemption_retention_secs)
            .await
        {
            // Committed: the digest is now spent for the retention period, and the upstream answer goes back unchanged.
            Ok(Commit::Ok) => Reply::Upstream(resp),
            // The lease lapsed while the upload ran, so another request may hold it: report a failure, and do not release a lease that is no longer ours.
            Ok(Commit::Lost) => Reply::Json(
                JsonReply::error(502, "redemption lease lost")
                    .with_diag("redemption lease lost before commit".to_string()),
            ),
            Err(e) => {
                self.state.release_redemption(key, &token).await;
                Reply::Json(
                    // The upstream succeeded but the store refused the commit: release the lease so the paid use can be retried, and say 502, not success.
                    JsonReply::error(502, "redemption commit failed")
                        .with_diag(format!("commit_redemption failed: {e}")),
                )
            }
        }
    }
}

/// Unit tests for the gateway pipeline, driven through in-memory fakes of the state store, the chain and the upstream.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The shared conformance vectors: the same file the Worker and the TypeScript twin are checked against, so a change in one place fails in all.
    const VECTORS: &str = include_str!("../../conformance/vectors.json");
    /// The transaction digest the single-use golden proof names; the fake chain asserts it is the digest it is asked about.
    const DIGEST: &str = "5Wq9tE4gXz8hEvFhYt8KkTJb2Pp6qXqj8cRk3xN1mYdL";
    /// The nonce the golden proofs were signed over; the fake store logs it when it is taken.
    const NONCE: &str = "GOLDEN-NONCE-123";

    /// The `(proof token, address)` of the named golden signature scheme in the shared vectors.
    fn golden(name: &str) -> (String, String) {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let s = v["signatures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["scheme"] == name)
            .unwrap();
        (
            s["proofToken"].as_str().unwrap().to_string(),
            s["address"].as_str().unwrap().to_string(),
        )
    }

    /// A gateway configuration built from a fixed environment (reserved `.example` hosts), with single-use redemption on or off.
    fn cfg(single_use: bool) -> GatewayConfig {
        // The fixed environment: any key not listed is unset, so every default the configuration applies is the one under test.
        let env = |k: &str| {
            Some(
                match k {
                    "GATEWAY_ORIGIN" => "https://gateway.example",
                    "NETWORK" => "testnet",
                    "UPSTREAM_URL" => "https://relay.example",
                    "SUI_RPC_URL" => "https://rpc.example",
                    "NFT_TYPE" => "0x1::access_gate::AccessNFT",
                    "GATE_ID" => {
                        "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
                    }
                    "SINGLE_USE" if single_use => "true",
                    _ => return None,
                }
                .to_string(),
            )
        };
        GatewayConfig::from_env(&env).unwrap()
    }

    /// What a [`Fake`] store was asked to do, in order.
    #[derive(Default)]
    struct Fake {
        /// Every call the gateway made, in order, as short strings the tests compare.
        calls: Mutex<Vec<String>>,
        /// Whether the next `take_nonce` finds a live nonce; taking it clears the flag, so a nonce is single-use like the real store.
        nonce_valid: Mutex<bool>,
        /// The answer for the next lease request; `None` means a fresh lease.
        lease: Mutex<Option<anyhow::Result<Lease>>>,
        /// The answer for the next commit; `None` means it succeeds.
        commit: Mutex<Option<anyhow::Result<Commit>>>,
        /// The one rate scope that answers "over the limit"; every other scope passes.
        deny_scope: Mutex<Option<RateScope>>,
        /// When set, issuing or taking a nonce fails like a store that is down.
        fail_nonce: bool,
        /// When set, the rate check fails like a store that is down.
        fail_rate: bool,
    }

    impl Fake {
        /// A fake with a live nonce and every other answer at its default.
        fn new() -> Self {
            let f = Self::default();
            *f.nonce_valid.lock().unwrap() = true;
            f
        }
        /// Record one call.
        fn log(&self, s: impl Into<String>) {
            self.calls.lock().unwrap().push(s.into());
        }
        /// A copy of the calls recorded so far.
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl StateStore for Fake {
        /// Issue a fixed nonce, or fail when the store is set to be down.
        async fn issue_nonce(&self) -> anyhow::Result<(String, u64)> {
            self.log("issue");
            if self.fail_nonce {
                anyhow::bail!("store down");
            }
            Ok(("n0nce".to_string(), 1234))
        }
        /// Take the nonce once: the second take answers "not valid", as the real store does.
        async fn take_nonce(&self, nonce: &str) -> anyhow::Result<bool> {
            self.log(format!("take:{nonce}"));
            if self.fail_nonce {
                anyhow::bail!("store down");
            }
            Ok(std::mem::take(&mut *self.nonce_valid.lock().unwrap()))
        }
        /// Allow every scope except the one the test denied.
        async fn rate_check(&self, scope: RateScope, key: &str) -> anyhow::Result<bool> {
            self.log(format!("rate:{scope:?}:{key}"));
            if self.fail_rate {
                anyhow::bail!("store down");
            }
            Ok(*self.deny_scope.lock().unwrap() != Some(scope))
        }
        /// Hand out the scripted lease, or a fresh one with the token `tok`.
        async fn try_lease_redemption(&self, key: &str, ttl: u64) -> anyhow::Result<Lease> {
            self.log(format!("lease:{key}:{ttl}"));
            self.lease
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Ok(Lease::Ok("tok".into())))
        }
        /// Answer the scripted commit, or succeed.
        async fn commit_redemption(
            &self,
            key: &str,
            token: &str,
            ret: u64,
        ) -> anyhow::Result<Commit> {
            self.log(format!("commit:{key}:{token}:{ret}"));
            self.commit.lock().unwrap().take().unwrap_or(Ok(Commit::Ok))
        }
        /// Record the release; the tests assert when it happens and when it must not.
        async fn release_redemption(&self, key: &str, token: &str) {
            self.log(format!("release:{key}:{token}"));
        }
    }

    /// A fake chain whose two answers are set per test.
    struct Chain {
        /// The answer to "does this address own the NFT".
        owns: anyhow::Result<bool>,
        /// The answer to "is there a matching consume transaction".
        consume: anyhow::Result<bool>,
    }

    impl Chain {
        /// A chain where the address owns the NFT and the consume is found.
        fn ok() -> Self {
            Self {
                owns: Ok(true),
                consume: Ok(true),
            }
        }
    }

    impl ChainQuery for Chain {
        /// Answer the scripted ownership result (an `Err` is copied, because the stored one is borrowed).
        async fn owns_nft(&self, _: &str, _: &str, _: Option<&str>) -> anyhow::Result<bool> {
            self.owns
                .as_ref()
                .map(|b| *b)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        /// Answer the scripted consume result, after checking the gateway asked about the golden digest and the fully qualified event type.
        async fn consume_tx_valid(
            &self,
            digest: &str,
            _: &str,
            event: &str,
            _: Option<&str>,
            _: u64,
        ) -> anyhow::Result<bool> {
            assert_eq!(digest, DIGEST);
            assert_eq!(
                event,
                "0x0000000000000000000000000000000000000000000000000000000000000001::access_gate::AccessConsumedEvent"
            );
            self.consume
                .as_ref()
                .map(|b| *b)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
        /// This chain never pauses the gate.
        async fn gate_access_blocked(&self, _: &str) -> anyhow::Result<bool> {
            Ok(false)
        }
    }

    /// A fake upstream: it records what was forwarded and answers with a fixed status.
    struct Up {
        status: u16,
        /// Each request the gateway forwarded, with whether it was a public or a gated one.
        seen: Mutex<Vec<(String, ForwardKind)>>,
    }

    impl Up {
        /// An upstream that answers every forwarded request with `status`.
        fn new(status: u16) -> Self {
            Self {
                status,
                seen: Mutex::new(Vec::new()),
            }
        }
        /// A copy of what was forwarded so far.
        fn seen(&self) -> Vec<(String, ForwardKind)> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Upstream for Up {
        /// The request is a plain string here: the tests only check it is passed through untouched.
        type Request = String;
        /// The response is the status plus an echo of the request.
        type Response = (u16, String);
        /// Record the request and answer with the configured status.
        async fn forward(&self, req: String, kind: ForwardKind) -> (u16, String) {
            self.seen.lock().unwrap().push((req.clone(), kind));
            (self.status, format!("upstream:{req}"))
        }
        /// The status of a fake response.
        fn status(&self, resp: &(u16, String)) -> u16 {
            resp.0
        }
    }

    /// A request head with a documentation-range client address and no credentials.
    fn head(method: &str, path: &str) -> RequestHead {
        RequestHead {
            method: method.into(),
            path: path.into(),
            client_ip: "203.0.113.9".into(),
            ..RequestHead::default()
        }
    }

    /// The same head carrying `token` as a bearer credential.
    fn with_token(mut h: RequestHead, token: &str) -> RequestHead {
        h.authorization = Some(format!("Bearer {token}"));
        h
    }

    /// Run one request through a gateway built from the fakes, without an async runtime of its own.
    fn run(
        cfg: &GatewayConfig,
        state: &Fake,
        chain: &Chain,
        up: &Up,
        h: &RequestHead,
    ) -> Reply<(u16, String)> {
        let g = Gateway {
            cfg,
            state,
            chain,
            upstream: up,
        };
        pollster::block_on(g.handle(h, "req".to_string()))
    }

    /// The gateway's own JSON answer; panics if the request reached the upstream instead.
    fn json_of(r: Reply<(u16, String)>) -> JsonReply {
        match r {
            Reply::Json(j) => j,
            Reply::Upstream(u) => panic!("expected a gateway answer, got upstream {u:?}"),
        }
    }

    /// Assert a JSON error with this status and reason, and return it for further checks.
    fn assert_error(r: Reply<(u16, String)>, status: u16, reason: &str) -> JsonReply {
        let j = json_of(r);
        assert_eq!(j.status, status, "{j:?}");
        assert_eq!(j.body["error"], reason, "{j:?}");
        j
    }

    /// A request that already passed through this gateway (its name is in `Via`) is refused with 508 before any state is touched.
    #[test]
    fn a_looped_request_is_a_508_before_any_state_is_touched() {
        let (cfg, state, up) = (cfg(false), Fake::new(), Up::new(200));
        for (method, path) in [
            ("GET", "/v1/challenge"),
            ("GET", "/v1/tip-config"),
            ("POST", "/v1/x"),
        ] {
            let mut h = head(method, path);
            // A `Via` list that names this gateway means the request came back to us: refuse it rather than forward it in a loop.
            h.via = Some("1.1 google, 1.1 access-gate-gateway".into());
            assert_error(
                run(&cfg, &state, &Chain::ok(), &up, &h),
                508,
                "loop detected",
            );
        }
        // Refused before any work: no store call and nothing forwarded.
        assert!(state.calls().is_empty() && up.seen().is_empty());
        // A foreign Via passes.
        let mut h = head("GET", "/v1/challenge");
        h.via = Some("1.1 google".into());
        assert_eq!(
            json_of(run(&cfg, &state, &Chain::ok(), &up, &h)).status,
            200
        );
    }

    /// The challenge endpoint is metered per client IP, then issues a nonce; only GET issues.
    #[test]
    fn the_challenge_is_rate_limited_per_ip_then_issued() {
        let (cfg, state, up) = (cfg(false), Fake::new(), Up::new(200));
        let j = json_of(run(
            &cfg,
            &state,
            &Chain::ok(),
            &up,
            &head("GET", "/v1/challenge"),
        ));
        assert_eq!(
            (j.status, &j.body),
            (200, &json!({"nonce": "n0nce", "expiresAt": 1234}))
        );
        // The per-IP challenge budget is charged first, then the nonce is issued, in that order.
        assert_eq!(state.calls(), ["rate:Challenge:203.0.113.9", "issue"]);

        // Now the challenge budget is spent: the next challenge request gets a 429.
        *state.deny_scope.lock().unwrap() = Some(RateScope::Challenge);
        assert_error(
            run(
                &cfg,
                &state,
                &Chain::ok(),
                &up,
                &head("GET", "/v1/challenge"),
            ),
            429,
            "rate limit exceeded",
        );
        // Only GET issues; any other method falls through to the gated path (no proof: 401).
        assert_error(
            run(
                &cfg,
                &state,
                &Chain::ok(),
                &up,
                &head("POST", "/v1/challenge"),
            ),
            401,
            "missing access proof",
        );
    }

    /// A store that cannot record the nonce is a 503 whose cause stays in the operator diagnostic, never in the client body.
    #[test]
    fn a_store_that_cannot_record_the_nonce_is_a_503_with_operator_detail() {
        let cfg = cfg(false);
        let state = Fake {
            fail_nonce: true,
            ..Fake::new()
        };
        let j = assert_error(
            run(
                &cfg,
                &state,
                &Chain::ok(),
                &Up::new(200),
                &head("GET", "/v1/challenge"),
            ),
            503,
            "gateway state unavailable",
        );
        // The operator diagnostic keeps the cause for the log.
        assert!(j.diag.unwrap().contains("store down"));
        assert!(!j.body.to_string().contains("store down")); // never in the client body
    }

    /// If the rate store is down the request is refused (503), never let through unmetered, on every path.
    #[test]
    fn a_rate_store_that_cannot_answer_is_a_503_never_an_unmetered_pass() {
        let cfg = cfg(false);
        let state = Fake {
            fail_rate: true,
            ..Fake::new()
        };
        let up = Up::new(200);
        for (m, p) in [
            ("GET", "/v1/challenge"),
            ("GET", "/v1/tip-config"),
            ("POST", "/v1/upload"),
        ] {
            let h = with_token(head(m, p), "x");
            let j = assert_error(
                run(&cfg, &state, &Chain::ok(), &up, &h),
                503,
                "gateway state unavailable",
            );
            assert!(j.diag.unwrap().contains("rate check failed: store down"));
        }
        assert!(up.seen().is_empty()); // nothing was forwarded
    }

    /// Public paths take GET and HEAD only, are rate limited, and are forwarded without a proof.
    #[test]
    fn public_paths_are_read_only_rate_limited_and_forwarded_without_a_proof() {
        let (cfg, state, up) = (cfg(false), Fake::new(), Up::new(200));
        let r = run(
            &cfg,
            &state,
            &Chain::ok(),
            &up,
            &head("GET", "/v1/tip-config"),
        );
        assert!(matches!(r, Reply::Upstream((200, _))));
        // A public request is forwarded with the public marker, so the upstream credentials for gated requests are not attached.
        assert_eq!(up.seen(), [("req".to_string(), ForwardKind::Public)]);
        assert!(matches!(
            run(
                &cfg,
                &state,
                &Chain::ok(),
                &up,
                &head("HEAD", "/v1/tip-config")
            ),
            Reply::Upstream(_)
        ));
        // A body-carrying method never reaches the upstream, and is refused before the rate limit.
        let before = state.calls().len();
        let j = assert_error(
            run(
                &cfg,
                &state,
                &Chain::ok(),
                &up,
                &head("POST", "/v1/tip-config"),
            ),
            405,
            "method not allowed",
        );
        // The 405 names the methods that are allowed, as HTTP requires.
        assert_eq!(j.allow, Some("GET, HEAD"));
        // The refused POST touched no store: the method check comes before the rate limit.
        assert_eq!(state.calls().len(), before);
        // Exhaust the public budget: the next public GET is refused and not forwarded.
        *state.deny_scope.lock().unwrap() = Some(RateScope::Public);
        assert_error(
            run(
                &cfg,
                &state,
                &Chain::ok(),
                &up,
                &head("GET", "/v1/tip-config"),
            ),
            429,
            "rate limit exceeded",
        );
        // Only the two earlier requests (GET and HEAD) ever reached the upstream.
        assert_eq!(up.seen().len(), 2);
    }

    /// Gated requests are refused cheaply (method, then missing proof, then the pre-auth rate limit) before any nonce or chain work.
    #[test]
    fn gated_requests_are_refused_before_any_verification_work() {
        let (cfg, state, up) = (cfg(false), Fake::new(), Up::new(200));
        assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &head("DELETE", "/v1/x")),
            405,
            "method not allowed",
        );
        assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &head("POST", "/v1/x")),
            401,
            "missing access proof",
        );
        assert!(
            state.calls().is_empty(),
            "no state is touched: {:?}",
            state.calls()
        );
        // The pre-authentication budget stops an attacker spending nonces and chain queries with junk proofs.
        *state.deny_scope.lock().unwrap() = Some(RateScope::GatedPreauth);
        // A token that is not valid base64 or JSON: it is only looked at once the rate limit passes.
        let h = with_token(head("POST", "/v1/x"), "!!!");
        assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &h),
            429,
            "rate limit exceeded",
        );
        assert_eq!(state.calls(), ["rate:GatedPreauth:203.0.113.9"]); // the nonce is never consumed
                                                                      // A malformed proof reaches verification: 403.
                                                                      // Lift the limit so the same request now reaches verification.
        *state.deny_scope.lock().unwrap() = None;
        assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &h),
            403,
            "malformed access proof",
        );
        // X-Access-Proof is the fallback header.
        let mut h = head("POST", "/v1/x");
        h.x_access_proof = Some("!!!".into());
        assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &h),
            403,
            "malformed access proof",
        );
        assert!(up.seen().is_empty());
    }

    /// The happy path: a valid proof from an owner is forwarded, and the per-address budget is charged only after verification.
    #[test]
    fn an_owner_with_a_valid_proof_is_forwarded_after_the_address_rate_limit() {
        // The golden proof is a real signature over the challenge message, so this test exercises the full verification path.
        let (token, address) = golden("ed25519");
        let (cfg, state, up) = (cfg(false), Fake::new(), Up::new(200));
        let h = with_token(head("POST", "/v1/blob-upload-relay"), &token);
        let r = run(&cfg, &state, &Chain::ok(), &up, &h);
        assert!(
            matches!(&r, Reply::Upstream((200, body)) if body == "upstream:req"),
            "{r:?}"
        );
        assert_eq!(
            state.calls(),
            [
                // Order matters: the cheap per-IP check, then the nonce, then the per-address budget on the verified address.
                "rate:GatedPreauth:203.0.113.9".to_string(),
                format!("take:{NONCE}"),
                format!("rate:Address:{address}"),
            ]
        );
        assert_eq!(up.seen(), [("req".to_string(), ForwardKind::Gated)]);

        // The address budget is charged to the verified (normalised) address.
        let state = Fake::new();
        // With the address budget spent the owner is refused even though the proof is valid.
        *state.deny_scope.lock().unwrap() = Some(RateScope::Address);
        assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &h),
            429,
            "rate limit exceeded",
        );
    }

    /// Every way a proof can fail maps to one status: a refusal is 403, a broken dependency is 502 or 503.
    #[test]
    fn denials_map_to_403_and_failures_to_502_or_503() {
        let (token, _) = golden("ed25519");
        let (cfg, up) = (cfg(false), Up::new(200));
        let h = with_token(head("POST", "/v1/x"), &token);
        // Case 1: the chain says this address does not hold the NFT.
        // not an owner
        let chain = Chain {
            owns: Ok(false),
            consume: Ok(true),
        };
        assert_error(
            run(&cfg, &Fake::new(), &chain, &up, &h),
            403,
            "address does not hold the required access NFT",
        );
        // a replayed / expired nonce
        let state = Fake::new();
        *state.nonce_valid.lock().unwrap() = false;
        assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &h),
            403,
            "challenge nonce invalid, expired, or already used",
        );
        // the chain is down: a 502, still denied
        let chain = Chain {
            owns: Err(anyhow::anyhow!("rpc down")),
            consume: Ok(true),
        };
        assert_error(
            run(&cfg, &Fake::new(), &chain, &up, &h),
            502,
            "on-chain verification failed",
        );
        // the state store is down while consuming the nonce: a 503, never a conflict
        let state = Fake {
            fail_nonce: true,
            ..Fake::new()
        };
        assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &h),
            503,
            "gateway state unavailable",
        );
        assert!(up.seen().is_empty());
        // a signature made for another gateway is useless here
        // The gateway origin is part of the signed message, so a proof made for another gateway cannot be replayed here.
        let mut other = cfg.clone();
        other.gateway_origin = "https://other.example".into();
        assert_error(
            run(&other, &Fake::new(), &Chain::ok(), &up, &h),
            403,
            "signature does not recover address",
        );
    }

    /// A gated request carrying the golden single-use proof, which names a consume transaction.
    fn single_use_head() -> RequestHead {
        let (token, _) = golden("ed25519 single-use");
        with_token(head("POST", "/v1/blob-upload-relay"), &token)
    }

    /// Single use: lease the consume, forward, then commit; nothing is released on success.
    #[test]
    fn single_use_leases_forwards_and_commits() {
        let (cfg, state, up) = (cfg(true), Fake::new(), Up::new(200));
        let r = run(&cfg, &state, &Chain::ok(), &up, &single_use_head());
        assert!(matches!(r, Reply::Upstream((200, _))));
        let calls = state.calls();
        assert_eq!(
            // The last two calls are the lease and then the commit; the earlier ones are the checks already covered above.
            &calls[calls.len() - 2..],
            [
                format!("lease:{DIGEST}:{}", cfg.redemption_lease_ttl_secs),
                format!("commit:{DIGEST}:tok:{}", cfg.redemption_retention_secs),
            ]
        );
        // A successful use is never released.
        assert!(!calls.iter().any(|c| c.starts_with("release")));
    }

    /// A consume that is already redeemed or being redeemed is a coded 409 and never reaches the upstream.
    #[test]
    fn a_spent_or_in_flight_consume_is_a_coded_409_that_never_reaches_the_upstream() {
        let (cfg, up) = (cfg(true), Up::new(200));
        for (lease, code, text) in [
            // Each lease answer maps to a stable machine-readable `code` that clients branch on.
            (Lease::Redeemed, "redeemed", "already been redeemed"),
            (Lease::Leased, "leased", "already in progress"),
        ] {
            let state = Fake::new();
            *state.lease.lock().unwrap() = Some(Ok(lease));
            let j = json_of(run(&cfg, &state, &Chain::ok(), &up, &single_use_head()));
            assert_eq!(j.status, 409);
            // The code is part of the public contract (see the shared vectors).
            assert_eq!(j.body["code"], code);
            assert!(j.body["error"].as_str().unwrap().contains(text));
        }
        assert!(up.seen().is_empty());
    }

    /// A failed upload (any non-2xx, redirects included) gives the lease back so the paid use is not lost.
    #[test]
    fn a_failed_upload_releases_the_consume_and_passes_the_upstream_failure_on() {
        let (cfg, state, up) = (cfg(true), Fake::new(), Up::new(500));
        let r = run(&cfg, &state, &Chain::ok(), &up, &single_use_head());
        assert!(matches!(r, Reply::Upstream((500, _))));
        let calls = state.calls();
        // The release is the last thing the gateway does, with the token it was leased.
        assert_eq!(calls.last().unwrap(), &format!("release:{DIGEST}:tok"));
        // A failed upload is never committed as a use.
        assert!(!calls.iter().any(|c| c.starts_with("commit")));
        // A redirect or any non-2xx counts as failure too.
        let state = Fake::new();
        let r = run(
            &cfg,
            &state,
            &Chain::ok(),
            &Up::new(302),
            &single_use_head(),
        );
        assert!(matches!(r, Reply::Upstream((302, _))));
        assert!(state.calls().last().unwrap().starts_with("release"));
    }

    /// If the lease expired before the commit the answer is a 502, not a success, and there is nothing to release.
    #[test]
    fn a_lease_lost_before_the_commit_is_a_502_not_a_success() {
        let (cfg, up) = (cfg(true), Up::new(200));
        let state = Fake::new();
        *state.commit.lock().unwrap() = Some(Ok(Commit::Lost));
        let j = assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &single_use_head()),
            502,
            "redemption lease lost",
        );
        // The reason is kept for the operator log.
        assert!(j.diag.is_some());
        // Nothing to release: the lease is not ours any more.
        assert!(!state.calls().iter().any(|c| c.starts_with("release")));
    }

    /// A commit that errors releases the lease so the person can retry.
    #[test]
    fn a_commit_that_errors_releases_the_lease_so_the_paid_use_is_not_lost() {
        let (cfg, up) = (cfg(true), Up::new(200));
        let state = Fake::new();
        // The store fails at the commit, after the upstream already answered.
        *state.commit.lock().unwrap() = Some(Err(anyhow::anyhow!("redis gone")));
        let j = assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &single_use_head()),
            502,
            "redemption commit failed",
        );
        // The cause is in the operator diagnostic.
        assert!(j.diag.unwrap().contains("redis gone"));
        assert_eq!(
            state.calls().last().unwrap(),
            &format!("release:{DIGEST}:tok")
        );
    }

    /// A store error while leasing is a 503, never reported as a spent consume (409).
    #[test]
    fn a_store_error_on_the_lease_is_a_503_never_a_conflict() {
        let (cfg, up) = (cfg(true), Up::new(200));
        let state = Fake::new();
        // The store fails when leasing: this is an outage, not a conflict.
        *state.lease.lock().unwrap() = Some(Err(anyhow::anyhow!("redis gone")));
        let j = assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &single_use_head()),
            503,
            "gateway state unavailable",
        );
        // The diagnostic says which store call failed.
        assert!(j.diag.unwrap().contains("redemption store failed"));
        assert!(up.seen().is_empty());
    }

    /// If no matching consume transaction exists, the lease is never requested and nothing is forwarded.
    #[test]
    fn a_failed_consume_never_reaches_the_lease_or_the_upstream() {
        let (cfg, state, up) = (cfg(true), Fake::new(), Up::new(200));
        let chain = Chain {
            owns: Ok(true),
            consume: Ok(false),
        };
        assert_error(
            run(&cfg, &state, &chain, &up, &single_use_head()),
            403,
            "no matching single-use consume for this address",
        );
        assert!(!state.calls().iter().any(|c| c.starts_with("lease")));
        assert!(up.seen().is_empty());
    }

    /// A chain whose gate is paused with `pause_blocks_access`.
    struct Paused;

    impl ChainQuery for Paused {
        /// A paused gate still reports ownership: only the pause check may refuse the request.
        async fn owns_nft(&self, _: &str, _: &str, _: Option<&str>) -> anyhow::Result<bool> {
            Ok(true)
        }
        /// The consume is valid here, so the pause check is the only thing that can refuse.
        async fn consume_tx_valid(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: u64,
        ) -> anyhow::Result<bool> {
            Ok(true)
        }
        /// This chain always reports the gate as paused (`pause_blocks_access`).
        async fn gate_access_blocked(&self, _: &str) -> anyhow::Result<bool> {
            Ok(true)
        }
    }

    /// The outcomes `conformance/vectors.json` `responses` names, each driven to the answer the gateway
    /// really produces. A vector outcome without an arm here fails the test, and so does an arm without
    /// a vector, so the shared contract and this gateway cannot drift apart unnoticed.
    const DRIVEN: [&str; 16] = [
        "missing-proof",
        "bad-proof",
        "bad-signature",
        "nonce-invalid",
        "not-owner",
        "consume-missing",
        "gate-paused",
        "chain-error",
        "state-unavailable",
        "rate-limited",
        "method-not-allowed",
        "loop-detected",
        "consume-redeemed",
        "consume-leased",
        "commit-failed",
        "lease-lost",
    ];

    /// Drive the gateway into the named outcome from the shared vectors and return its answer.
    fn answer(outcome: &str) -> JsonReply {
        let up = Up::new(200);
        let (token, _) = golden("ed25519");
        // A fresh owner request each time, because `RequestHead` is consumed by value in some arms.
        let owner = || with_token(head("POST", "/v1/x"), &token);
        // Most outcomes start from a healthy chain and break one thing.
        let ok = Chain::ok();
        match outcome {
            "missing-proof" => json_of(run(
                &cfg(false),
                &Fake::new(),
                &ok,
                &up,
                &head("POST", "/v1/x"),
            )),
            "bad-proof" => json_of(run(
                &cfg(false),
                &Fake::new(),
                &ok,
                &up,
                &with_token(head("POST", "/v1/x"), "!!!"),
            )),
            "bad-signature" => {
                let mut other = cfg(false);
                other.gateway_origin = "https://other.example".into();
                json_of(run(&other, &Fake::new(), &ok, &up, &owner()))
            }
            "nonce-invalid" => {
                let state = Fake::new();
                *state.nonce_valid.lock().unwrap() = false;
                json_of(run(&cfg(false), &state, &ok, &up, &owner()))
            }
            "not-owner" => {
                let chain = Chain {
                    owns: Ok(false),
                    consume: Ok(true),
                };
                json_of(run(&cfg(false), &Fake::new(), &chain, &up, &owner()))
            }
            "consume-missing" => {
                let chain = Chain {
                    owns: Ok(true),
                    consume: Ok(false),
                };
                json_of(run(
                    &cfg(true),
                    &Fake::new(),
                    &chain,
                    &up,
                    &single_use_head(),
                ))
            }
            // The gate is paused on chain: owners are refused although they hold the NFT.
            "gate-paused" => {
                let g = Gateway {
                    cfg: &cfg(false),
                    state: &Fake::new(),
                    chain: &Paused,
                    upstream: &up,
                };
                json_of(pollster::block_on(g.handle(&owner(), "req".to_string())))
            }
            "chain-error" => {
                let chain = Chain {
                    owns: Err(anyhow::anyhow!("rpc down")),
                    consume: Ok(true),
                };
                json_of(run(&cfg(false), &Fake::new(), &chain, &up, &owner()))
            }
            "state-unavailable" => {
                let state = Fake {
                    fail_nonce: true,
                    ..Fake::new()
                };
                json_of(run(&cfg(false), &state, &ok, &up, &owner()))
            }
            "rate-limited" => {
                let state = Fake::new();
                *state.deny_scope.lock().unwrap() = Some(RateScope::Address);
                json_of(run(&cfg(false), &state, &ok, &up, &owner()))
            }
            "method-not-allowed" => json_of(run(
                &cfg(false),
                &Fake::new(),
                &ok,
                &up,
                &head("DELETE", "/v1/x"),
            )),
            "loop-detected" => {
                let mut h = head("POST", "/v1/x");
                h.via = Some("1.1 access-gate-gateway".into());
                json_of(run(&cfg(false), &Fake::new(), &ok, &up, &h))
            }
            "consume-redeemed" | "consume-leased" => {
                let state = Fake::new();
                *state.lease.lock().unwrap() = Some(Ok(if outcome == "consume-redeemed" {
                    Lease::Redeemed
                } else {
                    Lease::Leased
                }));
                json_of(run(&cfg(true), &state, &ok, &up, &single_use_head()))
            }
            "commit-failed" => {
                let state = Fake::new();
                *state.commit.lock().unwrap() = Some(Err(anyhow::anyhow!("redis gone")));
                json_of(run(&cfg(true), &state, &ok, &up, &single_use_head()))
            }
            "lease-lost" => {
                let state = Fake::new();
                *state.commit.lock().unwrap() = Some(Ok(Commit::Lost));
                json_of(run(&cfg(true), &state, &ok, &up, &single_use_head()))
            }
            // An outcome in the vectors that this test cannot produce is a failure, so the vectors cannot gain an untested case.
            other => panic!(
                "conformance `responses` names an outcome this gateway cannot drive: {other}"
            ),
        }
    }

    /// Every response case in the shared vectors is what the gateway answers, and the set of outcomes matches `DRIVEN` both ways.
    #[test]
    fn the_shared_response_vectors_are_what_the_gateway_answers() {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        let responses = &v["responses"];
        let cases = responses["cases"].as_array().unwrap();
        // The outcomes the vectors name, compared with the driven set after the loop.
        let mut seen: Vec<&str> = Vec::new();
        for c in cases {
            let outcome = c["outcome"].as_str().unwrap();
            let reply = answer(outcome);
            // A case carries a `code` only for conflicts; the other bodies are just `{ error }`.
            let expected = match c.get("code") {
                Some(code) => json!({ "error": c["error"], "code": code }),
                None => json!({ "error": c["error"] }),
            };
            assert_eq!(
                (u64::from(reply.status), &reply.body),
                (c["status"].as_u64().unwrap(), &expected),
                "{outcome}"
            );
            seen.push(outcome);
        }
        let mut driven = DRIVEN.to_vec();
        driven.sort_unstable();
        seen.sort_unstable();
        // Both directions: a vector without a driver and a driver without a vector fail.
        assert_eq!(seen, driven, "vector outcomes and driven outcomes differ");
        // The vectors' own tables agree with what the code emits: a 409 always carries a known code.
        let codes: Vec<&str> = responses["conflictCodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        assert_eq!(codes, ["redeemed", "leased"]);
        for c in cases.iter().filter(|c| c["status"] == 409) {
            assert!(codes.contains(&c["code"].as_str().unwrap()));
        }
        // The vectors also pin the two statuses that are not tied to a single case.
        assert_eq!(responses["statuses"]["loopDetected"], 508);
        assert_eq!(responses["statuses"]["methodNotAllowed"], 405);
    }
}
