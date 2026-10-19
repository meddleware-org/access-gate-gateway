//! Production [`ChainQuery`]: the chain logic moved to `nft-gate-core::chain` (generic over a
//! `Transport`, shared with the Cloudflare Worker); this module binds it to the hyper client.

pub use nft_gate_core::chain::*;
#[allow(unused_imports)]
pub use nft_gate_core::decision::ChainQuery;

use crate::config::AuthHeader;
use crate::grpc::HyperTransport;
use crate::http_client::HttpClient;
use std::time::Duration;

#[cfg(test)]
#[allow(unused_imports)]
use crate::grpc::{
    field_bytes, field_str, value_as_bool, value_field, value_find_string, Field, GrpcStatus,
    ProtoReader, ProtoWriter, GRPC_NOT_FOUND,
};

#[cfg(test)]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
#[cfg(test)]
#[allow(unused_imports)]
use crate::http_client::TimedOut;
#[cfg(test)]
#[allow(unused_imports)]
use crate::verify::{normalize_address, normalize_move_type};

/// The native chain client.
pub type SuiRpc = nft_gate_core::chain::SuiRpc<HyperTransport>;

/// Create a new client. `rpc_url` is the full-node origin; `cache_ttl_ms` `0` disables the ownership cache.
pub fn new_sui_rpc(
    client: HttpClient,
    rpc_url: String,
    cache_ttl_ms: u64,
    auth: Option<AuthHeader>,
    timeout: Duration,
) -> SuiRpc {
    nft_gate_core::chain::SuiRpc::new(
        HyperTransport::new(client, auth, timeout),
        rpc_url,
        cache_ttl_ms,
        timeout.as_millis() as u64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::ProtoWriter;
    use crate::testkit::{gate_json, string_struct, string_value, struct_of, Reply, Stub};

    const NOW: u64 = 1_800_000_000_000;
    const MAX_AGE: u64 = 3600;

    /// An event / NFT json with a gate id (and, for events, a recent timestamp).
    fn json_gate(gate: &str) -> Vec<u8> {
        string_struct(&[
            ("gate_id", gate),
            ("timestamp_ms", &(NOW - 1000).to_string()),
        ])
    }

    fn event(etype: &str, sender: &str, gate: &str) -> Vec<u8> {
        let mut ev = ProtoWriter::new();
        ev.string_field(3, sender); // sender
        ev.string_field(4, etype); // event_type
        ev.bytes_field(6, &json_gate(gate)); // json
        ev.into_bytes()
    }

    /// A `GetTransactionResponse { transaction { effects { status { success } } events { events } } }`;
    /// `success` is the effects status (`None` leaves the status out altogether).
    fn tx_response_with_status(events: &[Vec<u8>], success: Option<bool>) -> Vec<u8> {
        let mut te = ProtoWriter::new();
        for e in events {
            te.bytes_field(EVENTS_EVENTS, e);
        }
        let mut tx = ProtoWriter::new();
        if let Some(ok) = success {
            let mut status = ProtoWriter::new();
            status.uint_field(STATUS_SUCCESS, u64::from(ok));
            let mut effects = ProtoWriter::new();
            effects.bytes_field(EFFECTS_STATUS, &status.into_bytes());
            tx.bytes_field(EXECUTED_EFFECTS, &effects.into_bytes());
        }
        tx.bytes_field(EXECUTED_EVENTS, &te.into_bytes());
        let mut resp = ProtoWriter::new();
        resp.bytes_field(RESP_TRANSACTION, &tx.into_bytes());
        resp.into_bytes()
    }

    /// A successful transaction carrying `events`.
    fn tx_response(events: &[Vec<u8>]) -> Vec<u8> {
        tx_response_with_status(events, Some(true))
    }

    const CONSUMED: &str = "0xabc::access_gate::AccessConsumedEvent";
    const OWNER: &str = "0xa11ce";
    const GATE: &str = "0x6a7e";

    #[test]
    fn matches_a_valid_consume_for_sender_and_gate() {
        let resp = tx_response(&[event(CONSUMED, OWNER, GATE)]);
        assert!(response_has_consume(
            &resp,
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        ));
        assert!(response_has_consume(
            &resp, OWNER, CONSUMED, None, NOW, MAX_AGE
        ));
    }

    #[test]
    fn rejects_wrong_sender_gate_or_event_type() {
        let resp = tx_response(&[event(CONSUMED, OWNER, GATE)]);
        assert!(!response_has_consume(
            &resp,
            "0xa77ac",
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        )); // wrong sender
        assert!(!response_has_consume(
            &resp,
            OWNER,
            CONSUMED,
            Some("0xbad"),
            NOW,
            MAX_AGE
        )); // wrong gate
        let other = tx_response(&[event("0xabc::access_gate::PurchasedEvent", OWNER, GATE)]);
        assert!(!response_has_consume(
            &other,
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        )); // wrong event
    }

    #[test]
    fn rejects_a_look_alike_package_consume_event() {
        // Any package can declare `access_gate::AccessConsumedEvent`; only the configured one counts.
        let forged = tx_response(&[event(
            "0xbad::access_gate::AccessConsumedEvent",
            OWNER,
            GATE,
        )]);
        assert!(!response_has_consume(
            &forged,
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        ));
    }

    #[test]
    fn compares_types_and_ids_in_normalised_form() {
        let long_type = format!("0x{}abc::access_gate::AccessConsumedEvent", "0".repeat(61));
        let long_owner = format!("0x{}a11ce", "0".repeat(59));
        let resp = tx_response(&[event(&long_type, &long_owner, "0x06A7E")]);
        assert!(response_has_consume(
            &resp,
            "0xA11CE",
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        ));
    }

    #[test]
    fn rejects_when_no_events() {
        assert!(!response_has_consume(
            &tx_response(&[]),
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        ));
        assert!(!response_has_consume(
            &[],
            OWNER,
            CONSUMED,
            None,
            NOW,
            MAX_AGE
        )); // empty/failed tx
    }

    #[test]
    fn owned_response_matches_gate() {
        // ListOwnedObjectsResponse { objects: [ Object { json } ] }
        let mut obj = ProtoWriter::new();
        obj.bytes_field(OBJECT_JSON, &nft_json(&[("@variant", "UnlimitedPass")]));
        let mut resp = ProtoWriter::new();
        resp.bytes_field(LOO_OBJECTS, &obj.into_bytes());
        let bytes = resp.into_bytes();
        assert!(response_has_owned(&bytes, Some(GATE)));
        assert!(response_has_owned(&bytes, None));
        assert!(!response_has_owned(&bytes, Some("0x07e4")));
        assert!(!response_has_owned(&[], Some(GATE)));
    }

    #[test]
    fn build_get_transaction_encodes_digest_and_mask() {
        let req = build_get_transaction("DIGEST123");
        assert_eq!(field_str(&req, REQ_DIGEST), Some("DIGEST123"));
        let mask = field_bytes(&req, REQ_READ_MASK).unwrap();
        let paths: Vec<&str> = ProtoReader::new(mask)
            .filter_map(|f| match f {
                Field::Len(FIELDMASK_PATHS, p) => std::str::from_utf8(p).ok(),
                _ => None,
            })
            .collect();
        assert_eq!(paths, ["effects.status", "events"]);
    }

    #[test]
    fn only_a_successful_transaction_can_be_a_consume() {
        let ev = event(CONSUMED, OWNER, GATE);
        let check =
            |resp: &[u8]| response_has_consume(resp, OWNER, CONSUMED, Some(GATE), NOW, MAX_AGE);
        assert!(check(&tx_response_with_status(
            std::slice::from_ref(&ev),
            Some(true)
        )));
        // A reported failure, a missing status and a missing effects block all fail closed, even
        // with a matching event in the response (audit F21).
        assert!(!check(&tx_response_with_status(
            std::slice::from_ref(&ev),
            Some(false)
        )));
        assert!(!check(&tx_response_with_status(&[ev], None)));
        // `ExecutionStatus` without its `success` field (an error-only status) is not success.
        let mut status = ProtoWriter::new();
        status.string_field(2, "error");
        let mut effects = ProtoWriter::new();
        effects.bytes_field(EFFECTS_STATUS, &status.into_bytes());
        let mut tx = ProtoWriter::new();
        tx.bytes_field(EXECUTED_EFFECTS, &effects.into_bytes());
        let mut te = ProtoWriter::new();
        te.bytes_field(EVENTS_EVENTS, &event(CONSUMED, OWNER, GATE));
        tx.bytes_field(EXECUTED_EVENTS, &te.into_bytes());
        let mut resp = ProtoWriter::new();
        resp.bytes_field(RESP_TRANSACTION, &tx.into_bytes());
        assert!(!check(&resp.into_bytes()));
    }

    #[test]
    fn build_list_owned_encodes_the_page_token_only_when_continuing() {
        let first = build_list_owned("0xa", "0x1::access_gate::AccessNFT", None);
        assert_eq!(field_str(&first, LOO_OWNER), Some("0xa"));
        assert_eq!(
            field_str(&first, LOO_OBJECT_TYPE),
            Some("0x1::access_gate::AccessNFT")
        );
        assert!(field_bytes(&first, LOO_PAGE_TOKEN).is_none());
        let next = build_list_owned("0xa", "0x1::access_gate::AccessNFT", Some(b"\x01tok"));
        assert_eq!(field_bytes(&next, LOO_PAGE_TOKEN), Some(&b"\x01tok"[..]));
    }

    // ── hermetic gRPC-web fixtures: SuiRpc against a scripted local node ──────────────────────
    // These pin the wire format with LITERAL field numbers (not the constants above), so a changed
    // constant fails here, and they need no network and no historic transaction (audit F45).

    const PASS_TYPE: &str = "0xabc::access_gate::SoulboundAccessNFT";

    fn rpc_for(stub: &Stub) -> SuiRpc {
        new_sui_rpc(
            HttpClient::new().unwrap(),
            stub.url.clone(),
            0,
            None,
            Duration::from_secs(5),
        )
    }

    /// A `ListOwnedObjectsResponse` of `variants` passes, with an optional next-page token.
    fn owned_page(variants: &[&[(&str, &str)]], next: Option<&[u8]>) -> Vec<u8> {
        let mut resp = ProtoWriter::new();
        for v in variants {
            let mut obj = ProtoWriter::new();
            obj.bytes_field(100, &nft_json(v)); // Object.json = 100
            resp.bytes_field(1, &obj.into_bytes()); // objects = 1
        }
        if let Some(t) = next {
            resp.bytes_field(2, t); // next_page_token = 2
        }
        resp.into_bytes()
    }

    const EXHAUSTED: &[(&str, &str)] = &[("@variant", "SingleUse"), ("uses_remaining", "0")];
    const UNLIMITED: &[(&str, &str)] = &[("@variant", "UnlimitedPass")];

    /// The request fields of a `ListOwnedObjects` call, read with literal field numbers.
    fn list_request(body: &[u8]) -> (String, u64, Option<Vec<u8>>, String) {
        let msg = crate::grpc::unframe_request_for_test(body);
        let page_size = ProtoReader::new(&msg)
            .find_map(|f| match f {
                Field::Varint(2, n) => Some(n),
                _ => None,
            })
            .unwrap();
        (
            field_str(&msg, 1).unwrap().to_string(),
            page_size,
            field_bytes(&msg, 3).map(<[u8]>::to_vec),
            field_str(&msg, 5).unwrap().to_string(),
        )
    }

    #[tokio::test]
    async fn ownership_is_read_across_pages_until_a_usable_pass() {
        // Page 1: only an exhausted receipt, more to read. Page 2: a usable pass (audit F17).
        let stub = Stub::spawn(|seen| match list_request(&seen.body).2.as_deref() {
            None => Reply::grpc(&owned_page(&[EXHAUSTED], Some(b"page-2"))),
            Some(b"page-2") => Reply::grpc(&owned_page(&[EXHAUSTED, UNLIMITED], None)),
            Some(other) => panic!("unexpected token {other:?}"),
        })
        .await;
        let rpc = rpc_for(&stub);
        assert!(rpc
            .owns_nft("0xa11ce", PASS_TYPE, Some(GATE))
            .await
            .unwrap());
        let calls = stub.seen_at("/sui.rpc.v2.StateService/ListOwnedObjects");
        assert_eq!(calls.len(), 2);
        let (owner, size, token, ty) = list_request(&calls[0].body);
        assert_eq!(
            (owner.as_str(), size, token, ty.as_str()),
            ("0xa11ce", 50, None, PASS_TYPE)
        );
        assert_eq!(
            list_request(&calls[1].body).2.as_deref(),
            Some(&b"page-2"[..])
        );
    }

    #[tokio::test]
    async fn a_pass_on_the_first_page_stops_the_scan() {
        let stub = Stub::spawn(|_| Reply::grpc(&owned_page(&[UNLIMITED], Some(b"more")))).await;
        assert!(rpc_for(&stub)
            .owns_nft("0xa11ce", PASS_TYPE, Some(GATE))
            .await
            .unwrap());
        assert_eq!(stub.seen().len(), 1);
    }

    #[tokio::test]
    async fn the_last_page_without_a_usable_pass_is_not_ownership() {
        let stub = Stub::spawn(|seen| match list_request(&seen.body).2 {
            None => Reply::grpc(&owned_page(&[EXHAUSTED], Some(b"p2"))),
            Some(_) => Reply::grpc(&owned_page(&[EXHAUSTED], Some(b""))), // empty token = end
        })
        .await;
        assert!(!rpc_for(&stub)
            .owns_nft("0xa11ce", PASS_TYPE, Some(GATE))
            .await
            .unwrap());
        assert_eq!(stub.seen().len(), 2);
    }

    #[tokio::test]
    async fn an_endless_list_is_an_error_after_the_page_bound() {
        // Every page names a next page and holds nothing usable: past MAX_OWNED_PAGES the answer
        // is an error (502, denied), never a silent "no" or "yes".
        let stub = Stub::spawn(|_| Reply::grpc(&owned_page(&[EXHAUSTED], Some(b"again")))).await;
        let err = rpc_for(&stub)
            .owns_nft("0xa11ce", PASS_TYPE, Some(GATE))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("pages"), "{err}");
        assert_eq!(stub.seen().len(), MAX_OWNED_PAGES);
    }

    #[tokio::test]
    async fn a_node_error_on_a_later_page_fails_the_check() {
        let stub = Stub::spawn(|seen| match list_request(&seen.body).2 {
            None => Reply::grpc(&owned_page(&[EXHAUSTED], Some(b"p2"))),
            Some(_) => Reply::grpc_status(14), // UNAVAILABLE
        })
        .await;
        assert!(rpc_for(&stub)
            .owns_nft("0xa11ce", PASS_TYPE, Some(GATE))
            .await
            .is_err());
    }

    /// Fields of a `GetTransaction` request, read with literal field numbers.
    fn get_tx_request(body: &[u8]) -> (String, Vec<String>) {
        let msg = crate::grpc::unframe_request_for_test(body);
        let mask = field_bytes(&msg, 2).unwrap();
        let paths = ProtoReader::new(mask)
            .filter_map(|f| match f {
                Field::Len(1, p) => Some(String::from_utf8(p.to_vec()).unwrap()),
                _ => None,
            })
            .collect();
        (field_str(&msg, 1).unwrap().to_string(), paths)
    }

    /// A node answering `GetTransaction` with a canned response, and recording the request.
    async fn tx_node(response: Vec<u8>) -> Stub {
        Stub::spawn(move |_| Reply::grpc(&response)).await
    }

    #[tokio::test]
    async fn consume_verification_reads_a_response_in_the_pinned_wire_format() {
        // The response is built with literal field numbers: GetTransactionResponse.transaction = 1,
        // ExecutedTransaction.effects = 4 { status = 4 { success = 1 } }, .events = 5 { events = 3 }.
        let json = string_struct(&[("gate_id", GATE), ("timestamp_ms", &now_ms().to_string())]);
        let mut ev = ProtoWriter::new();
        ev.string_field(3, OWNER);
        ev.string_field(4, CONSUMED);
        ev.bytes_field(6, &json);
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
        let stub = tx_node(resp.into_bytes()).await;
        let rpc = rpc_for(&stub);
        let digest = "5Wq9tE4gXz8hEvFhYt8KkTJb2Pp6qXqj8cRk3xN1mYdL";
        assert!(rpc
            .consume_tx_valid(digest, OWNER, CONSUMED, Some(GATE), 3600)
            .await
            .unwrap());
        // Other sender, gate and a look-alike package are refused against the same response.
        assert!(!rpc
            .consume_tx_valid(digest, "0x01", CONSUMED, Some(GATE), 3600)
            .await
            .unwrap());
        assert!(!rpc
            .consume_tx_valid(digest, OWNER, CONSUMED, Some("0xdead"), 3600)
            .await
            .unwrap());
        assert!(!rpc
            .consume_tx_valid(
                digest,
                OWNER,
                "0xbad::access_gate::AccessConsumedEvent",
                Some(GATE),
                3600
            )
            .await
            .unwrap());
        // The request names the digest (field 1) and masks to exactly what is read (field 2).
        let first = &stub.seen_at("/sui.rpc.v2.LedgerService/GetTransaction")[0];
        let (d, paths) = get_tx_request(&first.body);
        assert_eq!(d, digest);
        assert_eq!(paths, ["effects.status", "events"]);
    }

    #[tokio::test]
    async fn a_failed_transaction_with_a_matching_event_is_not_a_consume() {
        let ev = event(CONSUMED, OWNER, GATE);
        let stub = tx_node(tx_response_with_status(&[ev], Some(false))).await;
        assert!(!rpc_for(&stub)
            .consume_tx_valid("DIGEST", OWNER, CONSUMED, Some(GATE), 3600)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn only_not_found_is_retried_and_ends_as_denied() {
        let stub = Stub::spawn(|_| Reply::grpc_status(GRPC_NOT_FOUND)).await;
        let ok = rpc_for(&stub)
            .consume_tx_valid("DIGEST", OWNER, CONSUMED, Some(GATE), 3600)
            .await
            .unwrap();
        assert!(!ok);
        assert_eq!(stub.seen().len(), TX_FETCH_ATTEMPTS as usize);
        // Any other status is a chain error at once: no retries.
        let stub = Stub::spawn(|_| Reply::grpc_status(14)).await;
        assert!(rpc_for(&stub)
            .consume_tx_valid("DIGEST", OWNER, CONSUMED, Some(GATE), 3600)
            .await
            .is_err());
        assert_eq!(stub.seen().len(), 1);
    }

    #[tokio::test]
    async fn gate_read_uses_the_pinned_get_object_wire_format() {
        // GetObjectRequest { object_id = 1; read_mask = 3 }, GetObjectResponse { object = 1 { json = 100 } }.
        let mut obj = ProtoWriter::new();
        obj.bytes_field(100, &gate_json(true, Some(true)));
        let mut resp = ProtoWriter::new();
        resp.bytes_field(1, &obj.into_bytes());
        let body = resp.into_bytes();
        let stub = Stub::spawn(move |_| Reply::grpc(&body)).await;
        assert!(rpc_for(&stub).gate_access_blocked("0x6a7e").await.unwrap());
        let req = crate::grpc::unframe_request_for_test(&stub.seen()[0].body);
        assert_eq!(field_str(&req, 1), Some("0x6a7e"));
        assert_eq!(field_str(field_bytes(&req, 3).unwrap(), 1), Some("json"));
    }

    #[test]
    fn old_or_future_or_missing_timestamps_are_not_recent() {
        let at = |ms: u64| string_struct(&[("timestamp_ms", &ms.to_string())]);
        assert!(event_is_recent(&at(NOW - 60_000), NOW, MAX_AGE));
        assert!(!event_is_recent(&at(NOW - 3_600_001), NOW, MAX_AGE));
        assert!(event_is_recent(&at(NOW + 30_000), NOW, MAX_AGE)); // within clock skew
        assert!(!event_is_recent(&at(NOW + 600_000), NOW, MAX_AGE));
        for bad in ["", "soon", "-5", "1.5", "99999999999999999999"] {
            assert!(
                !event_is_recent(&string_struct(&[("timestamp_ms", bad)]), NOW, MAX_AGE),
                "{bad}"
            );
        }
        assert!(!event_is_recent(
            &string_struct(&[("gate_id", "0x1")]),
            NOW,
            MAX_AGE
        ));
        assert!(!event_is_recent(&[], NOW, MAX_AGE));
    }

    #[test]
    fn a_consume_older_than_the_bound_is_refused() {
        let old = string_struct(&[
            ("gate_id", GATE),
            ("timestamp_ms", &(NOW - 7_200_000).to_string()),
        ]);
        let mut ev = ProtoWriter::new();
        ev.string_field(3, OWNER);
        ev.string_field(4, CONSUMED);
        ev.bytes_field(6, &old);
        let resp = tx_response(&[ev.into_bytes()]);
        assert!(!response_has_consume(
            &resp,
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        ));
        assert!(response_has_consume(
            &resp,
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            10_000
        ));
    }

    /// An `AccessNFT` json: `data { gate_id, variant { "@variant", uses_remaining? } }`.
    fn nft_json(variant: &[(&str, &str)]) -> Vec<u8> {
        let data = struct_of(&[
            ("gate_id", string_value(GATE)),
            ("variant", string_struct(variant)),
        ]);
        struct_of(&[("data", data)])
    }

    #[test]
    fn only_usable_passes_count() {
        assert!(pass_is_usable(&nft_json(&[("@variant", "UnlimitedPass")])));
        assert!(pass_is_usable(&nft_json(&[
            ("@variant", "SingleUse"),
            ("uses_remaining", "8")
        ])));
        assert!(!pass_is_usable(&nft_json(&[
            ("@variant", "SingleUse"),
            ("uses_remaining", "0")
        ])));
        for bad in [
            nft_json(&[("@variant", "Mystery")]),
            nft_json(&[("@variant", "SingleUse")]),
            nft_json(&[("@variant", "SingleUse"), ("uses_remaining", "lots")]),
            nft_json(&[("@variant", "SingleUse"), ("uses_remaining", "-1")]),
            nft_json(&[("variant", "UnlimitedPass")]),
            Vec::new(),
        ] {
            assert!(!pass_is_usable(&bad));
        }
    }

    #[test]
    fn an_exhausted_receipt_is_not_ownership() {
        let owned = |variant: &[(&str, &str)]| {
            let mut obj = ProtoWriter::new();
            obj.bytes_field(OBJECT_JSON, &nft_json(variant));
            let mut resp = ProtoWriter::new();
            resp.bytes_field(LOO_OBJECTS, &obj.into_bytes());
            resp.into_bytes()
        };
        assert!(response_has_owned(
            &owned(&[("@variant", "SingleUse"), ("uses_remaining", "2")]),
            Some(GATE)
        ));
        assert!(!response_has_owned(
            &owned(&[("@variant", "SingleUse"), ("uses_remaining", "0")]),
            Some(GATE)
        ));
        assert!(!response_has_owned(
            &owned(&[("@variant", "Mystery")]),
            None
        ));
    }

    // ── optional live checks against a real full node ──────────────────────────────────────────
    // Ignored by default (network): `cargo test -- --ignored live_`. The hermetic fixtures above
    // already pin the wire format in CI; these confirm the field numbers against a real node.
    //
    // `live_gate_and_ownership_requests_are_accepted` needs no fixture: the current testnet relay
    // gate is a long-lived shared object. `live_consume_tx_valid` replays a recent
    // `access_gate::consume`; public fullnodes prune old checkpoints within about a week, so it
    // takes the transaction from the environment instead of a fixed digest (audit F45):
    //   NFT_GATE_LIVE_DIGEST   digest of a recent consume (listEvents on the AccessConsumedEvent
    //                          type, descending, on the same network)
    //   NFT_GATE_LIVE_SENDER   the consume's sender address
    //   NFT_GATE_LIVE_GATE     the gate id the consume was for
    //   NFT_GATE_LIVE_PACKAGE  the access_gate package (original id) that emitted the event
    //   NFT_GATE_LIVE_RPC      full-node URL (default https://fullnode.testnet.sui.io:443)
    // Unset DIGEST: the test says so and returns without asserting.

    fn live_rpc() -> SuiRpc {
        new_sui_rpc(
            HttpClient::new().unwrap(),
            std::env::var("NFT_GATE_LIVE_RPC")
                .unwrap_or_else(|_| "https://fullnode.testnet.sui.io:443".to_string()),
            0,
            None,
            Duration::from_secs(15),
        )
    }

    #[tokio::test]
    #[ignore = "hits a Sui full node; run with --ignored"]
    async fn live_gate_and_ownership_requests_are_accepted() {
        use crate::verify::ChainQuery;
        // The testnet relay gate published 2026-10-09 (see gateway-workers/wrangler.toml).
        let gate = std::env::var("NFT_GATE_LIVE_GATE").unwrap_or_else(|_| {
            "0x316f1bf9764db352e925bb598aff44ea77be4ab652f0bd2eb3fdcc0a378faddc".to_string()
        });
        let pkg = std::env::var("NFT_GATE_LIVE_PACKAGE").unwrap_or_else(|_| {
            "0xd7ddaa94b74330979b2b618fc81206d160a264f1c9ca148a77fa2144301388c9".to_string()
        });
        let rpc = live_rpc();
        // GetObject field numbers and the Gate JSON shape: a node that rejected either would error.
        rpc.gate_access_blocked(&gate).await.unwrap();
        // ListOwnedObjects field numbers: an address that owns no pass is a clean `false`.
        assert!(!rpc
            .owns_nft(
                "0x0000000000000000000000000000000000000000000000000000000000000001",
                &format!("{pkg}::access_gate::SoulboundAccessNFT"),
                Some(&gate),
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    #[ignore = "hits a Sui full node; run with --ignored"]
    async fn live_consume_tx_valid() {
        use crate::verify::{consumed_event_type, ChainQuery};
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let Some(digest) = env("NFT_GATE_LIVE_DIGEST") else {
            eprintln!("live_consume_tx_valid: NFT_GATE_LIVE_DIGEST is not set; nothing to check");
            return;
        };
        let (Some(addr), Some(gate), Some(pkg)) = (
            env("NFT_GATE_LIVE_SENDER"),
            env("NFT_GATE_LIVE_GATE"),
            env("NFT_GATE_LIVE_PACKAGE"),
        ) else {
            panic!("set NFT_GATE_LIVE_SENDER, NFT_GATE_LIVE_GATE and NFT_GATE_LIVE_PACKAGE too");
        };
        let rpc = live_rpc();
        let consumed = consumed_event_type(&format!("{pkg}::access_gate::SoulboundAccessNFT"));
        let ten_years = 315_360_000;
        assert!(rpc
            .consume_tx_valid(&digest, &addr, &consumed, Some(&gate), ten_years)
            .await
            .unwrap());
        assert!(!rpc
            .consume_tx_valid(&digest, "0x01", &consumed, Some(&gate), ten_years)
            .await
            .unwrap());
        assert!(!rpc
            .consume_tx_valid(&digest, &addr, &consumed, Some("0xdead"), ten_years)
            .await
            .unwrap());
        // A look-alike package's event type never matches.
        assert!(!rpc
            .consume_tx_valid(
                &digest,
                &addr,
                "0xbad::access_gate::AccessConsumedEvent",
                Some(&gate),
                ten_years
            )
            .await
            .unwrap());
    }

    // ── gate_blocks_access ──────────────────────────────────────────────────────────────────

    #[test]
    fn gate_blocks_only_when_paused_and_policy_opts_in() {
        assert!(gate_blocks_access(&gate_json(true, Some(true))).unwrap());
        assert!(!gate_blocks_access(&gate_json(false, Some(true))).unwrap());
        assert!(!gate_blocks_access(&gate_json(true, Some(false))).unwrap());
        // A gate without a policy is not a shape this version understands: fail closed.
        assert!(gate_blocks_access(&gate_json(true, None)).is_err());
    }

    #[test]
    fn unrecognised_gate_json_is_an_error_not_unpaused() {
        let not_bool = struct_of(&[("paused", Vec::new())]);
        for bad in [Vec::new(), not_bool] {
            assert!(gate_blocks_access(&bad).is_err());
        }
    }

    #[test]
    fn get_object_response_without_object_fails_closed() {
        assert!(response_gate_blocks_access(&[]).is_err());
        let mut obj = ProtoWriter::new();
        obj.bytes_field(OBJECT_JSON, &gate_json(true, Some(true)));
        let mut resp = ProtoWriter::new();
        resp.bytes_field(GO_OBJECT, &obj.into_bytes());
        assert!(response_gate_blocks_access(&resp.into_bytes()).unwrap());
    }
}
