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
    pub status: u16,
    /// The JSON body: `{"error": reason}`, `{"error", "code"}`, or `{"nonce", "expiresAt"}`.
    pub body: Value,
    /// An `Allow` header to send with it (405 on a public path).
    pub allow: Option<&'static str>,
    /// Operator-only detail for the log (a store or commit failure). Never sent to the client.
    pub diag: Option<String>,
}

impl JsonReply {
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
/// is a 502), timeouts (504) and the `Via: 1.1 nft-gate` marker. A failure is returned as a response
/// with the refusal's status ([`crate::forward`]), never as a panic.
#[allow(async_fn_in_trait)]
pub trait Upstream {
    /// The platform's request, body included.
    type Request;
    /// The platform's response, body included (or streaming).
    type Response;

    async fn forward(&self, req: Self::Request, kind: ForwardKind) -> Self::Response;

    /// The HTTP status of `resp`: a 2xx commits a single-use redemption, anything else releases it.
    fn status(&self, resp: &Self::Response) -> u16;
}

/// The gateway for one deployment: configuration plus its three ports. Cheap to build per request.
pub struct Gateway<'a, S, C, U> {
    pub cfg: &'a GatewayConfig,
    pub state: &'a S,
    pub chain: &'a C,
    pub upstream: &'a U,
}

fn denied_reply(d: &Denied) -> JsonReply {
    let status = match d {
        Denied::ChainError => 502,
        Denied::StateUnavailable => 503,
        _ => 403,
    };
    JsonReply::error(status, d.reason())
}

fn rate_limited() -> JsonReply {
    JsonReply::error(429, "rate limit exceeded")
}

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
        let json = |r: JsonReply| Reply::Json(r);

        // A request that already carries this gateway's own `Via` entry has looped back through it
        // (the upstream resolves to this gateway): refuse it before any nonce, rate-limit or
        // redemption work. `/healthz` and CORS preflights are answered before this point.
        if via_is_looped(head.via.as_deref().unwrap_or("")) {
            return json(JsonReply::error(508, "loop detected"));
        }

        if head.method == "GET" && head.path == "/v1/challenge" {
            if let Err(r) = self.charge(RateScope::Challenge, &head.client_ip).await {
                return json(r);
            }
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
            if head.method != "GET" && head.method != "HEAD" {
                let mut r = JsonReply::error(405, "method not allowed");
                r.allow = Some("GET, HEAD");
                return json(r);
            }
            if let Err(r) = self.charge(RateScope::Public, &head.client_ip).await {
                return json(r);
            }
            return Reply::Upstream(self.upstream.forward(req, ForwardKind::Public).await);
        }

        if !is_forwarded_method(&head.method) {
            return json(JsonReply::error(405, "method not allowed"));
        }

        let Some(token) = extract_proof_token(
            head.authorization.as_deref(),
            head.x_access_proof.as_deref(),
        ) else {
            return json(JsonReply::error(401, "missing access proof"));
        };

        // Verification costs CPU and a store call per request, so bound it per client first.
        if let Err(r) = self.charge(RateScope::GatedPreauth, &head.client_ip).await {
            return json(r);
        }

        let verified =
            match verify_access_request(&VerifyParams::from(cfg), self.state, &token, self.chain)
                .await
            {
                Ok(v) => v,
                Err(d) => return json(denied_reply(&d)),
            };
        if let Err(r) = self.charge(RateScope::Address, &verified.address).await {
            return json(r);
        }
        match verified.redemption_key {
            Some(key) => self.redeem_and_forward(&key, req).await,
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
            Err(e) => return Reply::Json(unavailable("redemption store failed", &e)),
            Ok(Lease::Redeemed) => {
                return Reply::Json(JsonReply::coded(
                    409,
                    "this consume has already been redeemed for an upload",
                    "redeemed",
                ))
            }
            Ok(Lease::Leased) => {
                return Reply::Json(JsonReply::coded(
                    409,
                    "an upload for this consume is already in progress",
                    "leased",
                ))
            }
            Ok(Lease::Ok(token)) => token,
        };
        let resp = self.upstream.forward(req, ForwardKind::Gated).await;
        if !(200..300).contains(&self.upstream.status(&resp)) {
            self.state.release_redemption(key, &token).await;
            return Reply::Upstream(resp);
        }
        match self
            .state
            .commit_redemption(key, &token, cfg.redemption_retention_secs)
            .await
        {
            Ok(Commit::Ok) => Reply::Upstream(resp),
            Ok(Commit::Lost) => Reply::Json(
                JsonReply::error(502, "redemption lease lost")
                    .with_diag("redemption lease lost before commit".to_string()),
            ),
            Err(e) => {
                self.state.release_redemption(key, &token).await;
                Reply::Json(
                    JsonReply::error(502, "redemption commit failed")
                        .with_diag(format!("commit_redemption failed: {e}")),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const VECTORS: &str = include_str!("../../conformance/vectors.json");
    const DIGEST: &str = "5Wq9tE4gXz8hEvFhYt8KkTJb2Pp6qXqj8cRk3xN1mYdL";
    const NONCE: &str = "GOLDEN-NONCE-123";

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

    fn cfg(single_use: bool) -> GatewayConfig {
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
        calls: Mutex<Vec<String>>,
        nonce_valid: Mutex<bool>,
        lease: Mutex<Option<anyhow::Result<Lease>>>,
        commit: Mutex<Option<anyhow::Result<Commit>>>,
        deny_scope: Mutex<Option<RateScope>>,
        fail_nonce: bool,
        fail_rate: bool,
    }

    impl Fake {
        fn new() -> Self {
            let f = Self::default();
            *f.nonce_valid.lock().unwrap() = true;
            f
        }
        fn log(&self, s: impl Into<String>) {
            self.calls.lock().unwrap().push(s.into());
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl StateStore for Fake {
        async fn issue_nonce(&self) -> anyhow::Result<(String, u64)> {
            self.log("issue");
            if self.fail_nonce {
                anyhow::bail!("store down");
            }
            Ok(("n0nce".to_string(), 1234))
        }
        async fn take_nonce(&self, nonce: &str) -> anyhow::Result<bool> {
            self.log(format!("take:{nonce}"));
            if self.fail_nonce {
                anyhow::bail!("store down");
            }
            Ok(std::mem::take(&mut *self.nonce_valid.lock().unwrap()))
        }
        async fn rate_check(&self, scope: RateScope, key: &str) -> anyhow::Result<bool> {
            self.log(format!("rate:{scope:?}:{key}"));
            if self.fail_rate {
                anyhow::bail!("store down");
            }
            Ok(*self.deny_scope.lock().unwrap() != Some(scope))
        }
        async fn try_lease_redemption(&self, key: &str, ttl: u64) -> anyhow::Result<Lease> {
            self.log(format!("lease:{key}:{ttl}"));
            self.lease
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Ok(Lease::Ok("tok".into())))
        }
        async fn commit_redemption(
            &self,
            key: &str,
            token: &str,
            ret: u64,
        ) -> anyhow::Result<Commit> {
            self.log(format!("commit:{key}:{token}:{ret}"));
            self.commit.lock().unwrap().take().unwrap_or(Ok(Commit::Ok))
        }
        async fn release_redemption(&self, key: &str, token: &str) {
            self.log(format!("release:{key}:{token}"));
        }
    }

    struct Chain {
        owns: anyhow::Result<bool>,
        consume: anyhow::Result<bool>,
    }

    impl Chain {
        fn ok() -> Self {
            Self {
                owns: Ok(true),
                consume: Ok(true),
            }
        }
    }

    impl ChainQuery for Chain {
        async fn owns_nft(&self, _: &str, _: &str, _: Option<&str>) -> anyhow::Result<bool> {
            self.owns
                .as_ref()
                .map(|b| *b)
                .map_err(|e| anyhow::anyhow!("{e}"))
        }
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
        async fn gate_access_blocked(&self, _: &str) -> anyhow::Result<bool> {
            Ok(false)
        }
    }

    /// Records what was forwarded and answers with `status`.
    struct Up {
        status: u16,
        seen: Mutex<Vec<(String, ForwardKind)>>,
    }

    impl Up {
        fn new(status: u16) -> Self {
            Self {
                status,
                seen: Mutex::new(Vec::new()),
            }
        }
        fn seen(&self) -> Vec<(String, ForwardKind)> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Upstream for Up {
        type Request = String;
        type Response = (u16, String);
        async fn forward(&self, req: String, kind: ForwardKind) -> (u16, String) {
            self.seen.lock().unwrap().push((req.clone(), kind));
            (self.status, format!("upstream:{req}"))
        }
        fn status(&self, resp: &(u16, String)) -> u16 {
            resp.0
        }
    }

    fn head(method: &str, path: &str) -> RequestHead {
        RequestHead {
            method: method.into(),
            path: path.into(),
            client_ip: "203.0.113.9".into(),
            ..RequestHead::default()
        }
    }

    fn with_token(mut h: RequestHead, token: &str) -> RequestHead {
        h.authorization = Some(format!("Bearer {token}"));
        h
    }

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

    fn json_of(r: Reply<(u16, String)>) -> JsonReply {
        match r {
            Reply::Json(j) => j,
            Reply::Upstream(u) => panic!("expected a gateway answer, got upstream {u:?}"),
        }
    }

    fn assert_error(r: Reply<(u16, String)>, status: u16, reason: &str) -> JsonReply {
        let j = json_of(r);
        assert_eq!(j.status, status, "{j:?}");
        assert_eq!(j.body["error"], reason, "{j:?}");
        j
    }

    #[test]
    fn a_looped_request_is_a_508_before_any_state_is_touched() {
        let (cfg, state, up) = (cfg(false), Fake::new(), Up::new(200));
        for (method, path) in [
            ("GET", "/v1/challenge"),
            ("GET", "/v1/tip-config"),
            ("POST", "/v1/x"),
        ] {
            let mut h = head(method, path);
            h.via = Some("1.1 google, 1.1 nft-gate".into());
            assert_error(
                run(&cfg, &state, &Chain::ok(), &up, &h),
                508,
                "loop detected",
            );
        }
        assert!(state.calls().is_empty() && up.seen().is_empty());
        // A foreign Via passes.
        let mut h = head("GET", "/v1/challenge");
        h.via = Some("1.1 google".into());
        assert_eq!(
            json_of(run(&cfg, &state, &Chain::ok(), &up, &h)).status,
            200
        );
    }

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
        assert_eq!(state.calls(), ["rate:Challenge:203.0.113.9", "issue"]);

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
        assert!(j.diag.unwrap().contains("store down"));
        assert!(!j.body.to_string().contains("store down")); // never in the client body
    }

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
        assert_eq!(j.allow, Some("GET, HEAD"));
        assert_eq!(state.calls().len(), before);
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
        assert_eq!(up.seen().len(), 2);
    }

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
        *state.deny_scope.lock().unwrap() = Some(RateScope::GatedPreauth);
        let h = with_token(head("POST", "/v1/x"), "!!!");
        assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &h),
            429,
            "rate limit exceeded",
        );
        assert_eq!(state.calls(), ["rate:GatedPreauth:203.0.113.9"]); // the nonce is never consumed
                                                                      // A malformed proof reaches verification: 403.
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

    #[test]
    fn an_owner_with_a_valid_proof_is_forwarded_after_the_address_rate_limit() {
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
                "rate:GatedPreauth:203.0.113.9".to_string(),
                format!("take:{NONCE}"),
                format!("rate:Address:{address}"),
            ]
        );
        assert_eq!(up.seen(), [("req".to_string(), ForwardKind::Gated)]);

        // The address budget is charged to the verified (normalised) address.
        let state = Fake::new();
        *state.deny_scope.lock().unwrap() = Some(RateScope::Address);
        assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &h),
            429,
            "rate limit exceeded",
        );
    }

    #[test]
    fn denials_map_to_403_and_failures_to_502_or_503() {
        let (token, _) = golden("ed25519");
        let (cfg, up) = (cfg(false), Up::new(200));
        let h = with_token(head("POST", "/v1/x"), &token);
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
        let mut other = cfg.clone();
        other.gateway_origin = "https://other.example".into();
        assert_error(
            run(&other, &Fake::new(), &Chain::ok(), &up, &h),
            403,
            "signature does not recover address",
        );
    }

    fn single_use_head() -> RequestHead {
        let (token, _) = golden("ed25519 single-use");
        with_token(head("POST", "/v1/blob-upload-relay"), &token)
    }

    #[test]
    fn single_use_leases_forwards_and_commits() {
        let (cfg, state, up) = (cfg(true), Fake::new(), Up::new(200));
        let r = run(&cfg, &state, &Chain::ok(), &up, &single_use_head());
        assert!(matches!(r, Reply::Upstream((200, _))));
        let calls = state.calls();
        assert_eq!(
            &calls[calls.len() - 2..],
            [
                format!("lease:{DIGEST}:{}", cfg.redemption_lease_ttl_secs),
                format!("commit:{DIGEST}:tok:{}", cfg.redemption_retention_secs),
            ]
        );
        assert!(!calls.iter().any(|c| c.starts_with("release")));
    }

    #[test]
    fn a_spent_or_in_flight_consume_is_a_coded_409_that_never_reaches_the_upstream() {
        let (cfg, up) = (cfg(true), Up::new(200));
        for (lease, code, text) in [
            (Lease::Redeemed, "redeemed", "already been redeemed"),
            (Lease::Leased, "leased", "already in progress"),
        ] {
            let state = Fake::new();
            *state.lease.lock().unwrap() = Some(Ok(lease));
            let j = json_of(run(&cfg, &state, &Chain::ok(), &up, &single_use_head()));
            assert_eq!(j.status, 409);
            assert_eq!(j.body["code"], code);
            assert!(j.body["error"].as_str().unwrap().contains(text));
        }
        assert!(up.seen().is_empty());
    }

    #[test]
    fn a_failed_upload_releases_the_consume_and_passes_the_upstream_failure_on() {
        let (cfg, state, up) = (cfg(true), Fake::new(), Up::new(500));
        let r = run(&cfg, &state, &Chain::ok(), &up, &single_use_head());
        assert!(matches!(r, Reply::Upstream((500, _))));
        let calls = state.calls();
        assert_eq!(calls.last().unwrap(), &format!("release:{DIGEST}:tok"));
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
        assert!(j.diag.is_some());
        // Nothing to release: the lease is not ours any more.
        assert!(!state.calls().iter().any(|c| c.starts_with("release")));
    }

    #[test]
    fn a_commit_that_errors_releases_the_lease_so_the_paid_use_is_not_lost() {
        let (cfg, up) = (cfg(true), Up::new(200));
        let state = Fake::new();
        *state.commit.lock().unwrap() = Some(Err(anyhow::anyhow!("redis gone")));
        let j = assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &single_use_head()),
            502,
            "redemption commit failed",
        );
        assert!(j.diag.unwrap().contains("redis gone"));
        assert_eq!(
            state.calls().last().unwrap(),
            &format!("release:{DIGEST}:tok")
        );
    }

    #[test]
    fn a_store_error_on_the_lease_is_a_503_never_a_conflict() {
        let (cfg, up) = (cfg(true), Up::new(200));
        let state = Fake::new();
        *state.lease.lock().unwrap() = Some(Err(anyhow::anyhow!("redis gone")));
        let j = assert_error(
            run(&cfg, &state, &Chain::ok(), &up, &single_use_head()),
            503,
            "gateway state unavailable",
        );
        assert!(j.diag.unwrap().contains("redemption store failed"));
        assert!(up.seen().is_empty());
    }

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
}
