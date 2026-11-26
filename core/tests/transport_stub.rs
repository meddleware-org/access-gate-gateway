//! Item 5 of the spike: the chain logic runs behind `Transport`, with no hyper and no tokio. A
//! scripted in-memory transport drives `SuiRpc` through GetTransaction (with the NOT_FOUND retry
//! policy) and ListOwnedObjects (pagination), and the full `verify_access_request` decision.
use access_gate_gateway_core::chain::SuiRpc;
use access_gate_gateway_core::decision::{
    verify_access_request, ChainQuery, Denied, NonceTake, VerifyParams,
};
use access_gate_gateway_core::grpc::{frame, ProtoWriter, Transport};
use std::cell::RefCell;
use std::collections::VecDeque;

/// The pretend current time, in epoch milliseconds.
const NOW: u64 = 1_800_000_000_000;
/// The gate id the stub chain data names.
const GATE: &str = "0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
/// The pass type the stub chain data names.
const NFT: &str = "0xabc::access_gate::SoulboundAccessNFT";

/// One scripted answer of the stub transport.
enum Reply {
    /// A well-formed gRPC-web response carrying this protobuf message.
    Grpc(Vec<u8>),
    /// An empty body with this `grpc-status` header (a gRPC error).
    Status(&'static str),
    /// A transport failure, as a 503 from the node.
    HttpError,
}

/// A transport that answers from a script and records what it was asked.
struct Scripted {
    /// The answers still to give, in order.
    replies: RefCell<VecDeque<Reply>>,
    /// Each URL called, to assert the right RPC method was used.
    urls: RefCell<Vec<String>>,
    /// Each sleep requested, to assert the retry delay without waiting.
    sleeps: RefCell<Vec<u64>>,
}

impl Scripted {
    /// A transport with this script.
    fn new(r: Vec<Reply>) -> Self {
        Self {
            replies: RefCell::new(r.into()),
            urls: Default::default(),
            sleeps: Default::default(),
        }
    }
}

impl Transport for &Scripted {
    /// Answer the next scripted reply (failing the test if the script ran out) and record the URL.
    async fn post_grpc_web(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<(Option<String>, Vec<u8>)> {
        // The client must send an uncompressed data frame (flag byte 0).
        assert_eq!(body[0], 0, "uncompressed data frame");
        self.urls.borrow_mut().push(url.to_string());
        match self
            .replies
            .borrow_mut()
            .pop_front()
            .expect("unscripted call")
        {
            Reply::Grpc(msg) => {
                let mut b = frame(&msg);
                // A success trailer frame follows the data frame, as a real node sends.
                let trailer = b"grpc-status:0\r\n";
                b.push(0x80);
                b.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
                b.extend_from_slice(trailer);
                Ok((None, b))
            }
            Reply::Status(s) => Ok((Some(s.to_string()), vec![])),
            // A transport error, which the chain code must surface (and not turn into "not found").
            Reply::HttpError => anyhow::bail!("HTTP 503"),
        }
    }
    /// Record the sleep instead of waiting.
    async fn sleep_ms(&self, ms: u64) {
        self.sleeps.borrow_mut().push(ms);
    }
    /// The fixed pretend time.
    fn now_ms(&self) -> u64 {
        NOW
    }
}

/// A protobuf message with one string field.
fn s(field: u32, v: &str) -> Vec<u8> {
    let mut w = ProtoWriter::new();
    w.string_field(field, v);
    w.into_bytes()
}
/// A protobuf `Value` holding a string (field 3).
fn string_value(v: &str) -> Vec<u8> {
    s(3, v)
}
/// A protobuf `Value` holding a struct of the named values.
fn struct_of(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut st = ProtoWriter::new();
    for (k, v) in entries {
        let mut e = ProtoWriter::new();
        e.string_field(1, k);
        e.bytes_field(2, v);
        st.bytes_field(1, &e.into_bytes());
    }
    let mut value = ProtoWriter::new();
    value.bytes_field(5, &st.into_bytes());
    value.into_bytes()
}

/// GetTransactionResponse with a successful tx holding one AccessConsumedEvent from `sender`.
fn consume_tx(sender: &str) -> Vec<u8> {
    let mut ev = ProtoWriter::new();
    ev.string_field(3, sender);
    ev.string_field(4, "0x0000000000000000000000000000000000000000000000000000000000000abc::access_gate::AccessConsumedEvent");
    ev.bytes_field(
        6,
        &struct_of(&[
            ("gate_id", string_value(GATE)),
            ("timestamp_ms", string_value(&(NOW - 1000).to_string())),
        ]),
    );
    let mut events = ProtoWriter::new();
    events.bytes_field(3, &ev.into_bytes());
    let mut status = ProtoWriter::new();
    status.uint_field(1, 1);
    let mut effects = ProtoWriter::new();
    effects.bytes_field(4, &status.into_bytes());
    let mut tx = ProtoWriter::new();
    tx.bytes_field(4, &effects.into_bytes());
    tx.bytes_field(5, &events.into_bytes());
    let mut resp = ProtoWriter::new();
    resp.bytes_field(1, &tx.into_bytes());
    resp.into_bytes()
}

/// A `GetObject` response for a gate whose JSON has the two pause flags.
fn gate_object(paused: bool, blocks: bool) -> Vec<u8> {
    let b = |v: bool| {
        let mut w = ProtoWriter::new();
        w.uint_field(4, u64::from(v));
        w.into_bytes()
    };
    let json = struct_of(&[
        ("paused", b(paused)),
        ("policy", struct_of(&[("pause_blocks_access", b(blocks))])),
    ]);
    let mut obj = ProtoWriter::new();
    obj.bytes_field(100, &json);
    let mut resp = ProtoWriter::new();
    resp.bytes_field(1, &obj.into_bytes());
    resp.into_bytes()
}

/// A `ListOwnedObjects` page with this many usable passes and an optional next-page token.
fn list_page(passes: usize, next: Option<&[u8]>) -> Vec<u8> {
    let mut resp = ProtoWriter::new();
    for _ in 0..passes {
        let json = struct_of(&[(
            "data",
            struct_of(&[
                ("gate_id", string_value(GATE)),
                (
                    "variant",
                    struct_of(&[("@variant", string_value("UnlimitedPass"))]),
                ),
            ]),
        )]);
        let mut o = ProtoWriter::new();
        o.bytes_field(100, &json);
        resp.bytes_field(1, &o.into_bytes());
    }
    if let Some(t) = next {
        resp.bytes_field(2, t);
    }
    resp.into_bytes()
}

/// Get transaction retries only not found then succeeds.
#[test]
fn get_transaction_retries_only_not_found_then_succeeds() {
    let t = Scripted::new(vec![
        Reply::Status("5"),
        Reply::Status("5"),
        Reply::Grpc(consume_tx("0x1")),
    ]);
    let rpc = SuiRpc::new(&t, "https://fullnode.example:443/".into(), 0, 15_000);
    let ok = pollster::block_on(rpc.consume_tx_valid(
        "d",
        "0x1",
        "0xabc::access_gate::AccessConsumedEvent",
        Some(GATE),
        3600,
    ))
    .unwrap();
    assert!(ok);
    assert_eq!(*t.sleeps.borrow(), vec![500, 500]);
    assert_eq!(
        t.urls.borrow()[0],
        "https://fullnode.example:443/sui.rpc.v2.LedgerService/GetTransaction"
    );
}

/// Not found four times is a clean false and other failures are errors.
#[test]
fn not_found_four_times_is_a_clean_false_and_other_failures_are_errors() {
    let t = Scripted::new(vec![
        Reply::Status("5"),
        Reply::Status("5"),
        Reply::Status("5"),
        Reply::Status("5"),
    ]);
    let rpc = SuiRpc::new(&t, "https://f".into(), 0, 15_000);
    assert!(!pollster::block_on(rpc.consume_tx_valid(
        "d",
        "0x1",
        "0xabc::access_gate::AccessConsumedEvent",
        None,
        3600
    ))
    .unwrap());
    assert_eq!(t.sleeps.borrow().len(), 3);
    let t = Scripted::new(vec![Reply::HttpError]);
    let rpc = SuiRpc::new(&t, "https://f".into(), 0, 15_000);
    assert!(pollster::block_on(rpc.consume_tx_valid(
        "d",
        "0x1",
        "0xabc::access_gate::AccessConsumedEvent",
        None,
        3600
    ))
    .is_err());
    assert!(t.sleeps.borrow().is_empty());
}

/// List owned objects paginates.
#[test]
fn list_owned_objects_paginates() {
    let t = Scripted::new(vec![
        Reply::Grpc(list_page(0, Some(b"tok"))),
        Reply::Grpc(list_page(1, None)),
    ]);
    let rpc = SuiRpc::new(&t, "https://f".into(), 0, 15_000);
    assert!(pollster::block_on(rpc.owns_nft("0x1", NFT, Some(GATE))).unwrap());
    assert_eq!(t.urls.borrow().len(), 2);
    assert!(t.urls.borrow()[1].ends_with("sui.rpc.v2.StateService/ListOwnedObjects"));
}

/// A nonce store holding one nonce that can be taken once.
struct Nonces(RefCell<bool>);
impl NonceTake for Nonces {
    /// Take the nonce: true the first time, false after.
    async fn take_if_valid(&self, _n: &str) -> anyhow::Result<bool> {
        Ok(self.0.replace(false))
    }
}

/// Verification parameters for the test gateway, in single-use mode.
fn params() -> VerifyParams {
    VerifyParams {
        single_use: true,
        gateway_origin: "https://gateway.example".into(),
        gate_id: GATE.into(),
        network: "testnet".into(),
        nft_type: NFT.into(),
        consume_max_age_secs: 3600,
    }
}

/// Full single use decision over a stub transport.
#[test]
fn full_single_use_decision_over_a_stub_transport() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../conformance/vectors.json")).unwrap();
    let vec = v["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["scheme"] == "ed25519 single-use")
        .unwrap();
    let token = vec["proofToken"].as_str().unwrap();
    let addr = vec["address"].as_str().unwrap();

    // Allowed: gate not paused, consume found.
    let t = Scripted::new(vec![
        Reply::Grpc(gate_object(false, true)),
        Reply::Grpc(consume_tx(addr)),
    ]);
    let rpc = SuiRpc::new(&t, "https://f".into(), 0, 15_000);
    let r = pollster::block_on(verify_access_request(
        &params(),
        &Nonces(RefCell::new(true)),
        token,
        &rpc,
    ))
    .unwrap();
    assert_eq!(r.address, addr);
    assert_eq!(
        r.redemption_key.as_deref(),
        Some("5Wq9tE4gXz8hEvFhYt8KkTJb2Pp6qXqj8cRk3xN1mYdL")
    );

    // Replayed nonce is refused before any chain call.
    let t = Scripted::new(vec![]);
    let rpc = SuiRpc::new(&t, "https://f".into(), 0, 15_000);
    let r = pollster::block_on(verify_access_request(
        &params(),
        &Nonces(RefCell::new(false)),
        token,
        &rpc,
    ));
    assert_eq!(r.unwrap_err(), Denied::NonceInvalid);
    assert!(t.urls.borrow().is_empty());

    // Paused + blocks access: GatePaused; chain failure: ChainError (fail closed).
    let t = Scripted::new(vec![Reply::Grpc(gate_object(true, true))]);
    let rpc = SuiRpc::new(&t, "https://f".into(), 0, 15_000);
    let r = pollster::block_on(verify_access_request(
        &params(),
        &Nonces(RefCell::new(true)),
        token,
        &rpc,
    ));
    assert_eq!(r.unwrap_err(), Denied::GatePaused);
    let t = Scripted::new(vec![Reply::HttpError]);
    let rpc = SuiRpc::new(&t, "https://f".into(), 0, 15_000);
    let r = pollster::block_on(verify_access_request(
        &params(),
        &Nonces(RefCell::new(true)),
        token,
        &rpc,
    ));
    assert_eq!(r.unwrap_err(), Denied::ChainError);

    // Consume sent by someone else: ConsumeMissing.
    let t = Scripted::new(vec![
        Reply::Grpc(gate_object(false, true)),
        Reply::Grpc(consume_tx("0xdead")),
    ]);
    let rpc = SuiRpc::new(&t, "https://f".into(), 0, 15_000);
    let r = pollster::block_on(verify_access_request(
        &params(),
        &Nonces(RefCell::new(true)),
        token,
        &rpc,
    ));
    assert_eq!(r.unwrap_err(), Denied::ConsumeMissing);
}

/// A transport with a clock the test moves; every call answers one usable pass.
struct Clocked {
    now: std::cell::Cell<u64>,
    calls: std::cell::Cell<usize>,
}

impl Transport for &Clocked {
    /// Answer with one page holding a usable pass, and count the call.
    async fn post_grpc_web(
        &self,
        _url: &str,
        _body: Vec<u8>,
    ) -> anyhow::Result<(Option<String>, Vec<u8>)> {
        // Count the calls: the cache test asserts how many reached the node.
        self.calls.set(self.calls.get() + 1);
        let mut b = frame(&list_page(1, None));
        let trailer = b"grpc-status:0\r\n";
        b.push(0x80);
        b.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
        b.extend_from_slice(trailer);
        Ok((None, b))
    }
    // No retries happen here, so there is nothing to wait for.
    /// No retry happens here, so there is nothing to wait for.
    async fn sleep_ms(&self, _ms: u64) {}
    /// The clock the test moves.
    fn now_ms(&self) -> u64 {
        self.now.get()
    }
}

/// The ownership cache serves within the ttl and expires.
#[test]
fn the_ownership_cache_serves_within_the_ttl_and_expires() {
    let t = Clocked {
        now: 1_000.into(),
        calls: 0.into(),
    };
    let rpc = SuiRpc::new(&t, "https://f".into(), 1_000, 15_000);
    let owns = |a: &str| pollster::block_on(rpc.owns_nft(a, NFT, Some(GATE))).unwrap();
    assert!(owns("0x1"));
    assert!(owns("0x1"));
    assert_eq!(t.calls.get(), 1, "the second lookup is a cache hit");
    t.now.set(2_001); // past the TTL
    assert!(owns("0x1"));
    assert_eq!(t.calls.get(), 2, "an expired entry is looked up again");
}

/// The ownership cache stays bounded.
#[test]
fn the_ownership_cache_stays_bounded() {
    let t = Clocked {
        now: 1_000.into(),
        calls: 0.into(),
    };
    let rpc = SuiRpc::new(&t, "https://f".into(), 3_600_000, 15_000);
    let owns = |a: &str| pollster::block_on(rpc.owns_nft(a, NFT, Some(GATE))).unwrap();
    // More distinct addresses than the cache holds; each lookup is one millisecond later, so the
    // first entry is the oldest.
    for i in 0..10_050u64 {
        t.now.set(1_000 + i);
        owns(&format!("0x{i:x}"));
    }
    let before = t.calls.get();
    owns("0x0"); // the oldest was dropped past the bound: looked up again
    assert_eq!(t.calls.get(), before + 1);
    owns("0x2741"); // a recent one (10049) is still cached
    assert_eq!(t.calls.get(), before + 1);
}
