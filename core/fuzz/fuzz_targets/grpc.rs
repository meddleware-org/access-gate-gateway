//! Fuzz target `grpc`: the hand-rolled gRPC-web framing (`grpc::unframe` / `frame`), the protobuf reader and the
//! `google.protobuf.Value` lookups, and the Sui response parsers in `chain` that sit on top of them. Every input is
//! attacker-shaped data from a fullnode, so nothing here may panic and the stated bounds must hold.
#![no_main]

use access_gate_gateway_core::chain::{
    effects_succeeded, event_is_recent, gate_blocks_access, pass_is_usable,
    response_gate_blocks_access, response_has_consume, response_has_owned,
};
use access_gate_gateway_core::grpc::{
    field_bytes, field_str, frame, unframe, value_as_bool, value_field, value_find_string, Field,
    ProtoReader, MAX_GRPC_MESSAGE_BYTES,
};
use libfuzzer_sys::fuzz_target;

const TYPE: &str = "0x0000000000000000000000000000000000000000000000000000000000000001::access_gate::AccessConsumedEvent";
const ADDRESS: &str = "0x0000000000000000000000000000000000000000000000000000000000000002";
const GATE: &str = "0x0000000000000000000000000000000000000000000000000000000000000003";

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };

    // 1. gRPC-web framing. `sel` picks the HTTP-header status (the trailers-only case) so both the header and the
    //    trailer-frame paths run.
    let status = match sel & 3 {
        0 => None,
        1 => Some("0"),
        2 => Some("5"),
        _ => Some("not-a-number"),
    };
    if let Ok(msg) = unframe(status, body) {
        assert!(msg.len() <= MAX_GRPC_MESSAGE_BYTES);
        assert!(msg.len() <= body.len());
    }
    // A framed message always comes back unchanged (the client sends exactly one frame).
    let framed = frame(body);
    assert_eq!(
        unframe(Some("0"), &framed)
            .expect("a framed message unframes")
            .as_slice(),
        body
    );

    // 2. protobuf reader: every yielded field lies inside the message.
    for f in ProtoReader::new(body) {
        if let Field::Len(_, b) = f {
            assert!(b.len() <= body.len());
        }
    }
    for n in [1u32, 2, 3, 4, 5, 6, 100] {
        let _ = field_bytes(body, n);
        let _ = field_str(body, n);
    }
    let _ = value_find_string(body, "gate_id");
    let _ = value_find_string(body, "timestamp_ms");
    let _ = value_field(body, "paused").and_then(value_as_bool);
    let _ = value_as_bool(body);

    // 3. the Sui parsers built on the decoder.
    let _ = gate_blocks_access(body);
    let _ = response_gate_blocks_access(body);
    let _ = pass_is_usable(body);
    let _ = effects_succeeded(body);
    let _ = event_is_recent(body, 1_700_000_000_000, 432_000);
    let _ = response_has_consume(body, ADDRESS, TYPE, Some(GATE), 1_700_000_000_000, 432_000);
    let _ = response_has_owned(body, Some(GATE));
});
