//! Pure protobuf Value builders for tests (moved from `gateway-rust/src/testkit.rs`).
use crate::grpc::ProtoWriter;

// value = 2 } }.

/// A `Value` holding a string.
pub fn string_value(s: &str) -> Vec<u8> {
    let mut v = ProtoWriter::new();
    v.string_field(3, s);
    v.into_bytes()
}

/// A `Value` holding a bool.
pub fn bool_value(b: bool) -> Vec<u8> {
    let mut v = ProtoWriter::new();
    v.uint_field(4, u64::from(b));
    v.into_bytes()
}

/// A struct `Value` from (key, `Value`-bytes) entries.
pub fn struct_of(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut s = ProtoWriter::new();
    for (k, v) in entries {
        let mut entry = ProtoWriter::new();
        entry.string_field(1, k);
        entry.bytes_field(2, v);
        s.bytes_field(1, &entry.into_bytes());
    }
    let mut value = ProtoWriter::new();
    value.bytes_field(5, &s.into_bytes());
    value.into_bytes()
}

/// A struct `Value` of string fields.
pub fn string_struct(fields: &[(&str, &str)]) -> Vec<u8> {
    let entries: Vec<(&str, Vec<u8>)> = fields.iter().map(|(k, v)| (*k, string_value(v))).collect();
    struct_of(&entries)
}

/// A `Gate` object's JSON.
pub fn gate_json(paused: bool, policy_blocks_access: Option<bool>) -> Vec<u8> {
    let mut entries = vec![("paused", bool_value(paused))];
    if let Some(blocks) = policy_blocks_access {
        entries.push((
            "policy",
            struct_of(&[
                ("pause_blocks_decryption", bool_value(false)),
                ("pause_blocks_access", bool_value(blocks)),
            ]),
        ));
    }
    struct_of(&entries)
}

// ── scripted local HTTP server ───────────────────────────────────────────────────────────────

/// An `AccessNFT` json: `data { gate_id, variant { "@variant", uses_remaining? } }`.
pub fn nft_json(gate: &str, variant: &[(&str, &str)]) -> Vec<u8> {
    let data = struct_of(&[
        ("gate_id", string_value(gate)),
        ("variant", string_struct(variant)),
    ]);
    struct_of(&[("data", data)])
}
