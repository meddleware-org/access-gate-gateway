//! Sui gRPC [`ChainQuery`] over any [`Transport`] — the pure core of `gateway-rust/src/sui_rpc.rs`.
//! Everything that was hyper/tokio specific is behind [`Transport`] (POST, sleep, clock); the pinned
//! field numbers, request builders and response parsers are moved unchanged.

use crate::decision::ChainQuery;
use crate::grpc::{
    field_bytes, field_str, value_as_bool, value_field, value_find_string, Field, GrpcStatus,
    GrpcWeb, ProtoReader, ProtoWriter, Transport, GRPC_NOT_FOUND,
};
use crate::sig::{normalize_address, normalize_move_type};
use std::collections::HashMap;
use std::sync::Mutex;

// ── pinned sui.rpc.v2 field numbers (validated against live responses) ───────────────────────
/// The gRPC-web method that reads one transaction by digest.
pub const LEDGER_GET_TRANSACTION: &str = "sui.rpc.v2.LedgerService/GetTransaction";
/// The gRPC-web method that lists the objects an address owns.
pub const STATE_LIST_OWNED_OBJECTS: &str = "sui.rpc.v2.StateService/ListOwnedObjects";
/// The gRPC-web method that reads one object.
pub const LEDGER_GET_OBJECT: &str = "sui.rpc.v2.LedgerService/GetObject";

// GetObjectRequest { object_id = 1; version = 2; FieldMask read_mask = 3 }
/// `GetObjectRequest.object_id` (field 1).
pub const GO_OBJECT_ID: u32 = 1;
/// `GetObjectRequest.read_mask` (field 3).
pub const GO_READ_MASK: u32 = 3;
// GetObjectResponse { Object object = 1 }
/// `GetObjectResponse.object` (field 1).
pub const GO_OBJECT: u32 = 1;

// GetTransactionRequest { digest = 1; FieldMask read_mask = 2 { repeated string paths = 1 } }
/// `GetTransactionRequest.digest` (field 1).
pub const REQ_DIGEST: u32 = 1;
/// `GetTransactionRequest.read_mask` (field 2).
pub const REQ_READ_MASK: u32 = 2;
/// `FieldMask.paths` (field 1).
pub const FIELDMASK_PATHS: u32 = 1;
// GetTransactionResponse { ExecutedTransaction transaction = 1 }
/// `GetTransactionResponse.transaction` (field 1).
pub const RESP_TRANSACTION: u32 = 1;
// ExecutedTransaction { ... TransactionEffects effects = 4; TransactionEvents events = 5 }
/// `ExecutedTransaction.effects` (field 4).
pub const EXECUTED_EFFECTS: u32 = 4;
/// `ExecutedTransaction.events` (field 5).
pub const EXECUTED_EVENTS: u32 = 5;
// TransactionEffects { ... ExecutionStatus status = 4 }; ExecutionStatus { optional bool success = 1 }
/// `TransactionEffects.status` (field 4).
pub const EFFECTS_STATUS: u32 = 4;
/// `ExecutionStatus.success` (field 1).
pub const STATUS_SUCCESS: u32 = 1;
// TransactionEvents { ... repeated Event events = 3 }
/// `TransactionEvents.events` (field 3).
pub const EVENTS_EVENTS: u32 = 3;
// Event { package_id=1; module=2; sender=3; event_type=4; Bcs contents=5; Value json=6 }
/// `Event.sender` (field 3).
pub const EVENT_SENDER: u32 = 3;
/// `Event.event_type` (field 4).
pub const EVENT_TYPE: u32 = 4;
/// `Event.json` (field 6): the node's JSON rendering of the event.
pub const EVENT_JSON: u32 = 6;

// ListOwnedObjectsRequest { owner=1; uint32 page_size=2; bytes page_token=3; FieldMask read_mask=4;
// object_type=5 }
/// `ListOwnedObjectsRequest.owner` (field 1).
pub const LOO_OWNER: u32 = 1;
/// `ListOwnedObjectsRequest.page_size` (field 2).
pub const LOO_PAGE_SIZE: u32 = 2;
/// `ListOwnedObjectsRequest.page_token` (field 3).
pub const LOO_PAGE_TOKEN: u32 = 3;
/// `ListOwnedObjectsRequest.read_mask` (field 4).
pub const LOO_READ_MASK: u32 = 4;
/// `ListOwnedObjectsRequest.object_type` (field 5).
pub const LOO_OBJECT_TYPE: u32 = 5;
// ListOwnedObjectsResponse { repeated Object objects = 1; bytes next_page_token = 2 }
/// `ListOwnedObjectsResponse.objects` (field 1).
pub const LOO_OBJECTS: u32 = 1;
/// `ListOwnedObjectsResponse.next_page_token` (field 2).
pub const LOO_NEXT_PAGE_TOKEN: u32 = 2;
// Object { ... Value json = 100 }
/// `Object.json` (field 100): the node's JSON rendering of the object.
pub const OBJECT_JSON: u32 = 100;

/// Objects requested per `ListOwnedObjects` page.
pub const OWNED_PAGE_SIZE: u64 = 50;
/// Pages read before the ownership list is judged too long to decide (the Workers gateway's
/// `MAX_OWNED_PAGES`: the same pass is admitted or refused by both). With 50 per page, 5,000 objects
/// of the pass type; past it the check errors (→ 502, denied) instead of guessing.
pub const MAX_OWNED_PAGES: usize = 100;
/// `GetTransaction` attempts while the node still reports the digest as unknown (indexing lag).
pub const TX_FETCH_ATTEMPTS: u32 = 4;
/// Entries kept by the ownership cache; the oldest is dropped past it.
pub const MAX_CACHE_ENTRIES: usize = 10_000;
/// Clock skew tolerated between a consume event's timestamp and this host's clock.
pub const CLOCK_SKEW_MS: u64 = 60_000;

/// Delay between `GetTransaction` attempts (ms).
pub const TX_FETCH_RETRY_MS: u64 = 500;

/// One cached answer to "does this address own a pass of this type": the answer and when it stops being used.
pub struct CacheEntry {
    /// Whether the address owned a matching pass when it was asked.
    owns: bool,
    /// When the entry stops being used, in epoch milliseconds.
    expiry_ms: u64,
}

/// Production [`ChainQuery`] backed by the Sui gRPC API (gRPC-web), generic over the transport.
pub struct SuiRpc<T: Transport> {
    /// The gRPC-web client over the transport.
    grpc: GrpcWeb<T>,
    /// Deadline for one gated ownership check (all of its pages), checked between pages.
    timeout_ms: u64,
    /// How long an ownership answer is reused.
    cache_ttl_ms: u64,
    /// Recent answers by address, pass type and gate.
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl<T: Transport> SuiRpc<T> {
    /// Build a client for one full node.
    pub fn new(transport: T, rpc_url: String, cache_ttl_ms: u64, timeout_ms: u64) -> Self {
        Self {
            grpc: GrpcWeb::new(transport, rpc_url),
            timeout_ms,
            cache_ttl_ms,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The cache key: address, pass type and gate (or `-`), so a gate-bound pass never answers for another gate.
    fn cache_key(address: &str, nft_type: &str, gate_id: Option<&str>) -> String {
        format!("{address}|{nft_type}|{}", gate_id.unwrap_or("-"))
    }

    /// Uncached ownership query, bounded by one deadline for all pages (checked between pages; the
    /// transport enforces the per-request deadline).
    async fn scan_owned(
        &self,
        address: &str,
        nft_type: &str,
        gate_id: Option<&str>,
    ) -> anyhow::Result<bool> {
        // The clock starts before the first page, so the deadline covers all of them.
        let started = self.grpc.transport().now_ms();
        // `None` asks for the first page; each answer carries the token for the next.
        let mut page_token: Option<Vec<u8>> = None;
        // A hard page limit: an address with an endless list cannot hold a request open.
        for _ in 0..MAX_OWNED_PAGES {
            if self.grpc.transport().now_ms().saturating_sub(started) > self.timeout_ms {
                anyhow::bail!("ownership check timed out");
            }
            let resp = self
                .grpc
                .call(
                    STATE_LIST_OWNED_OBJECTS,
                    build_list_owned(address, nft_type, page_token.as_deref()),
                )
                .await?;
            // Stop at the first usable pass: no need to read the rest of the list.
            if response_has_owned(&resp, gate_id) {
                return Ok(true);
            }
            // An empty or missing token means this was the last page.
            match field_bytes(&resp, LOO_NEXT_PAGE_TOKEN).filter(|t| !t.is_empty()) {
                Some(token) => page_token = Some(token.to_vec()),
                None => return Ok(false),
            }
        }
        anyhow::bail!(
            "owned-object list exceeds {MAX_OWNED_PAGES} pages; refusing to decide ownership"
        )
    }
}

/// Build one `ListOwnedObjectsRequest` page for `address`, continuing from `page_token`.
pub fn build_list_owned(address: &str, nft_type: &str, page_token: Option<&[u8]>) -> Vec<u8> {
    let mut mask = ProtoWriter::new();
    // Ask the node only for the two fields that are read, which keeps each page small.
    mask.string_field(FIELDMASK_PATHS, "object_type");
    mask.string_field(FIELDMASK_PATHS, "json");
    let mut req = ProtoWriter::new();
    req.string_field(LOO_OWNER, address);
    // A fixed page size, so the page limit means a fixed number of objects.
    req.uint_field(LOO_PAGE_SIZE, OWNED_PAGE_SIZE);
    if let Some(token) = page_token {
        req.bytes_field(LOO_PAGE_TOKEN, token);
    }
    req.bytes_field(LOO_READ_MASK, &mask.into_bytes());
    // The node filters by type, so every returned object is already a pass.
    req.string_field(LOO_OBJECT_TYPE, nft_type);
    req.into_bytes()
}

/// True if a `Gate`'s JSON (`google.protobuf.Value`) is paused AND its `policy` has
/// `pause_blocks_access`. Fails closed: JSON without a boolean `paused` and a `policy` with a boolean
/// `pause_blocks_access` is not understood and is an error (→ deny), never "not paused" — a rendering
/// change must not silently disable an admin's pause.
pub fn gate_blocks_access(json: &[u8]) -> anyhow::Result<bool> {
    // One error for every shape problem: the caller treats it as a denial, never as "not paused".
    let unrecognised = || anyhow::anyhow!("gate JSON has an unrecognised shape");
    let paused = value_field(json, "paused")
        .and_then(value_as_bool)
        .ok_or_else(unrecognised)?;
    let blocks = value_field(json, "policy")
        .and_then(|p| value_field(p, "pause_blocks_access"))
        .and_then(value_as_bool)
        .ok_or_else(unrecognised)?;
    Ok(paused && blocks)
}

/// Parse a `GetObjectResponse` for a gate; errors (fail closed) if the object or its JSON is absent.
pub fn response_gate_blocks_access(resp: &[u8]) -> anyhow::Result<bool> {
    let object =
        field_bytes(resp, GO_OBJECT).ok_or_else(|| anyhow::anyhow!("gate object not found"))?;
    let json = field_bytes(object, OBJECT_JSON)
        .ok_or_else(|| anyhow::anyhow!("gate object has no json"))?;
    gate_blocks_access(json)
}

/// Build the `GetTransactionRequest` for `digest`, requesting only the execution status and events.
pub fn build_get_transaction(digest: &str) -> Vec<u8> {
    let mut mask = ProtoWriter::new();
    // Only the execution status and the events are needed, not the whole transaction.
    mask.string_field(FIELDMASK_PATHS, "effects.status");
    mask.string_field(FIELDMASK_PATHS, "events");
    let mut req = ProtoWriter::new();
    req.string_field(REQ_DIGEST, digest);
    req.bytes_field(REQ_READ_MASK, &mask.into_bytes());
    req.into_bytes()
}

/// True if the event's `timestamp_ms` is at most `max_age_secs` old and not in the future (beyond
/// clock skew). A missing or malformed timestamp is not recent: fail closed. The age bound keeps a
/// consume from becoming redeemable again once the redemption store has forgotten it.
pub fn event_is_recent(event_json: &[u8], now_ms: u64, max_age_secs: u64) -> bool {
    let Some(ts) = value_find_string(event_json, "timestamp_ms")
        // Digits only and at most 16 of them, so the parse cannot overflow and a malformed value is not a recent one.
        .filter(|t| !t.is_empty() && t.len() <= 16 && t.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|t| t.parse::<u64>().ok())
    else {
        return false;
    };
    // An event from the future is accepted only within the clock skew allowance.
    ts <= now_ms.saturating_add(CLOCK_SKEW_MS)
        && now_ms.saturating_sub(ts) <= max_age_secs.saturating_mul(1000)
}

/// True if an access NFT's JSON describes a usable pass: an unlimited pass, or a single-use pass
/// with uses left. The variant is read as a full node renders the `AccessVariant` enum
/// (`{ "@variant": "SingleUse", "uses_remaining": "8" }`); an unknown tag or a missing or non-u64
/// count is not usable (fail closed), so an exhausted receipt never grants access.
pub fn pass_is_usable(nft_json: &[u8]) -> bool {
    match value_find_string(nft_json, "@variant").as_deref() {
        // An unlimited pass is always usable.
        Some("UnlimitedPass") => true,
        // A single-use pass is usable only while it has uses left.
        Some("SingleUse") => value_find_string(nft_json, "uses_remaining")
            .filter(|n| !n.is_empty() && n.len() <= 20 && n.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|n| n.parse::<u64>().ok())
            .is_some_and(|n| n > 0),
        _ => false,
    }
}

/// True if `a` and `b` name the same address (normalised form).
pub fn same_address(a: Option<&str>, b: &str) -> bool {
    a.is_some_and(|a| normalize_address(a) == normalize_address(b))
}

/// True if the executed transaction's effects report success. The status is decided from the
/// effects, as the Workers gateway does (`status.success`), not inferred from the presence of
/// events: a missing effects block, status or `success` field, or `success = false`, is a failure.
pub fn effects_succeeded(tx: &[u8]) -> bool {
    field_bytes(tx, EXECUTED_EFFECTS)
        .and_then(|effects| field_bytes(effects, EFFECTS_STATUS))
        .is_some_and(|status| {
            ProtoReader::new(status).any(|f| matches!(f, Field::Varint(STATUS_SUCCESS, 1)))
        })
}

/// True if a `GetTransactionResponse` is a SUCCESSFUL transaction (effects status) containing an
/// event of exactly `consumed_type` sent by `address` for `gate_id` (when constrained).
pub fn response_has_consume(
    resp: &[u8],
    address: &str,
    consumed_type: &str,
    gate_id: Option<&str>,
    now_ms: u64,
    max_age_secs: u64,
) -> bool {
    // Compare types in their normalised form (`normalize_move_type`), so two spellings of one type match.
    let want_type = normalize_move_type(consumed_type);
    let Some(tx) = field_bytes(resp, RESP_TRANSACTION) else {
        return false;
    };
    // A transaction that aborted never consumed anything, even if it emitted events.
    if !effects_succeeded(tx) {
        return false;
    }
    let Some(events) = field_bytes(tx, EXECUTED_EVENTS) else {
        return false;
    };
    for f in ProtoReader::new(events) {
        let Field::Len(EVENTS_EVENTS, ev) = f else {
            continue;
        };
        // The event must be of exactly the consumed type, from the presenting address, for this gate, and recent.
        let is_consume =
            field_str(ev, EVENT_TYPE).is_some_and(|t| normalize_move_type(t) == want_type);
        if !is_consume || !same_address(field_str(ev, EVENT_SENDER), address) {
            continue;
        }
        let json = field_bytes(ev, EVENT_JSON).unwrap_or(&[]);
        if !event_is_recent(json, now_ms, max_age_secs) {
            continue;
        }
        match gate_id {
            None => return true,
            Some(g) => {
                if same_address(value_find_string(json, "gate_id").as_deref(), g) {
                    return true;
                }
            }
        }
    }
    false
}

/// True if a `ListOwnedObjectsResponse` contains a USABLE owned pass (see [`pass_is_usable`])
/// matching `gate_id` (when constrained). The object type is already constrained by the request's
/// `object_type` filter.
pub fn response_has_owned(resp: &[u8], gate_id: Option<&str>) -> bool {
    for f in ProtoReader::new(resp) {
        let Field::Len(LOO_OBJECTS, obj) = f else {
            continue;
        };
        let json = field_bytes(obj, OBJECT_JSON).unwrap_or(&[]);
        if !pass_is_usable(json) {
            continue;
        }
        match gate_id {
            None => return true,
            Some(g) => {
                if same_address(value_find_string(json, "gate_id").as_deref(), g) {
                    return true;
                }
            }
        }
    }
    false
}

impl<T: Transport> ChainQuery for SuiRpc<T> {
    /// Whether `address` holds a usable access pass of `nft_type` (for `gate_id` when given), answered from a short-lived cache when one is configured.
    async fn owns_nft(
        &self,
        address: &str,
        nft_type: &str,
        gate_id: Option<&str>,
    ) -> anyhow::Result<bool> {
        // A TTL of zero turns the cache off, which tests and strict deployments use to see every change at once.
        if self.cache_ttl_ms != 0 {
            let key = Self::cache_key(address, nft_type, gate_id);
            let now = self.grpc.transport().now_ms();
            // A hit that has not expired answers without a chain call.
            if let Some(e) = self.cache.lock().unwrap().get(&key) {
                if e.expiry_ms > now {
                    return Ok(e.owns);
                }
            }
            let owns = self.scan_owned(address, nft_type, gate_id).await?;
            let now = self.grpc.transport().now_ms();
            let mut cache = self.cache.lock().unwrap();
            // Drop expired entries first so the size bound below only evicts live ones when it must.
            cache.retain(|_, e| e.expiry_ms > now);
            // Bound memory: when full, evict the entry that would expire soonest.
            if cache.len() >= MAX_CACHE_ENTRIES {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, e)| e.expiry_ms)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest);
                }
            }
            cache.insert(
                key,
                CacheEntry {
                    owns,
                    expiry_ms: now + self.cache_ttl_ms,
                },
            );
            return Ok(owns);
        }
        self.scan_owned(address, nft_type, gate_id).await
    }

    /// Whether the gate is paused with `pause_blocks_access` (read from the gate object's JSON).
    async fn gate_access_blocked(&self, gate_id: &str) -> anyhow::Result<bool> {
        let mut mask = ProtoWriter::new();
        mask.string_field(FIELDMASK_PATHS, "json");
        let mut req = ProtoWriter::new();
        req.string_field(GO_OBJECT_ID, gate_id);
        req.bytes_field(GO_READ_MASK, &mask.into_bytes());
        let resp = self.grpc.call(LEDGER_GET_OBJECT, req.into_bytes()).await?;
        response_gate_blocks_access(&resp)
    }

    /// Whether the transaction `consume_digest` is a recent, successful consume by `address` that emitted the expected event for this gate.
    async fn consume_tx_valid(
        &self,
        consume_digest: &str,
        address: &str,
        consumed_event_type: &str,
        gate_id: Option<&str>,
        max_age_secs: u64,
    ) -> anyhow::Result<bool> {
        // A just-submitted transaction may not be indexed yet; retry a "not found" a few times before refusing.
        let mut attempt = 1;
        let resp = loop {
            match self
                .grpc
                .call(
                    LEDGER_GET_TRANSACTION,
                    build_get_transaction(consume_digest),
                )
                .await
            {
                Ok(resp) => break resp,
                Err(e)
                    if e.downcast_ref::<GrpcStatus>()
                        .is_some_and(|s| s.0 == GRPC_NOT_FOUND) =>
                {
                    // Out of attempts: the consume does not exist (as far as the node knows), so it is not valid.
                    if attempt >= TX_FETCH_ATTEMPTS {
                        return Ok(false);
                    }
                    self.grpc.transport().sleep_ms(TX_FETCH_RETRY_MS).await;
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        };
        Ok(response_has_consume(
            &resp,
            address,
            consumed_event_type,
            gate_id,
            self.grpc.transport().now_ms(),
            max_age_secs,
        ))
    }
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::ProtoWriter;
    use crate::testkit::string_struct;

    /// The pretend current time (epoch milliseconds) the fake chain data is built around.
    const NOW: u64 = 1_800_000_000_000;
    /// How old a consume event may be in these tests, in seconds.
    const MAX_AGE: u64 = 3600;

    /// An event / NFT json with a gate id (and, for events, a recent timestamp).
    fn json_gate(gate: &str) -> Vec<u8> {
        string_struct(&[
            ("gate_id", gate),
            ("timestamp_ms", &(NOW - 1000).to_string()),
        ])
    }

    /// One transaction event with the given type, sender and gate id, encoded as the node returns it.
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

    /// The fully written event type a consume emits.
    const CONSUMED: &str = "0xabc::access_gate::AccessConsumedEvent";
    /// A short owner address for readable assertions.
    const OWNER: &str = "0xa11ce";
    /// A short gate id for readable assertions.
    const GATE: &str = "0x6a7e";

    /// Matches a valid consume for sender and gate.
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

    /// Rejects wrong sender gate or event type.
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

    /// Rejects a look alike package consume event.
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

    /// Compares types and ids in normalised form.
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

    /// Rejects when no events.
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

    /// Owned response matches gate.
    #[test]
    fn owned_response_matches_gate() {
        // ListOwnedObjectsResponse { objects: [ Object { json } ] }
        let mut obj = ProtoWriter::new();
        obj.bytes_field(
            OBJECT_JSON,
            &crate::testkit::nft_json(GATE, &[("@variant", "UnlimitedPass")]),
        );
        let mut resp = ProtoWriter::new();
        resp.bytes_field(LOO_OBJECTS, &obj.into_bytes());
        let bytes = resp.into_bytes();
        assert!(response_has_owned(&bytes, Some(GATE)));
        assert!(response_has_owned(&bytes, None));
        assert!(!response_has_owned(&bytes, Some("0x07e4")));
        assert!(!response_has_owned(&[], Some(GATE)));
    }

    /// Build get transaction encodes digest and mask.
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

    /// Only a successful transaction can be a consume.
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

    /// Build list owned encodes the page token only when continuing.
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
}
