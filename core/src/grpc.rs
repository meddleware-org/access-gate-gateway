//! Minimal hand-rolled gRPC-web client for the Sui full-node gRPC API (`sui.rpc.v2`), layered on
//! a [`Transport`] (hyper on native, `fetch` on Workers) — with **no** `tonic`/`prost`/`sui-rpc` dependency, preserving
//! this crate's deliberately lightweight build (see CLAUDE.md).
//!
//! Public Sui JSON-RPC is deprecated and GraphQL is unavailable, so the gateway speaks gRPC-web
//! (`application/grpc-web+proto`, HTTP/1.1) with hand-written protobuf encode/decode of just the two
//! messages it needs (`GetTransaction`, `ListOwnedObjects`). Only the fields actually read are
//! decoded; all others are skipped. Field numbers are pinned from the `MystenLabs/sui-apis` protos
//! and validated against live responses.

/// Largest decoded gRPC message the gateway accepts (the HTTP body is capped at the same size).
pub const MAX_GRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
/// Deepest `google.protobuf.Value` nesting [`value_find_string`] descends into. Move structs in
/// the responses the gateway reads are a few levels deep; the cap bounds hostile input.
const MAX_VALUE_DEPTH: usize = 32;

// ── protobuf wire codec (varint + length-delimited + skipped fixed) ──────────────────────────

/// A minimal protobuf message writer (only the wire types the gateway emits).
#[derive(Default)]
pub struct ProtoWriter {
    buf: Vec<u8>,
}

impl ProtoWriter {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn varint(&mut self, mut n: u64) {
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            if n != 0 {
                self.buf.push(b | 0x80);
            } else {
                self.buf.push(b);
                break;
            }
        }
    }

    fn tag(&mut self, field: u32, wire: u8) {
        self.varint(((field as u64) << 3) | wire as u64);
    }

    /// Write a length-delimited (wire type 2) field: string / bytes / embedded message.
    pub fn bytes_field(&mut self, field: u32, val: &[u8]) {
        self.tag(field, 2);
        self.varint(val.len() as u64);
        self.buf.extend_from_slice(val);
    }

    /// Write a string (length-delimited) field.
    pub fn string_field(&mut self, field: u32, val: &str) {
        self.bytes_field(field, val.as_bytes());
    }

    /// Write a varint (wire type 0) field.
    pub fn uint_field(&mut self, field: u32, val: u64) {
        self.tag(field, 0);
        self.varint(val);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// A borrowed protobuf field parsed from a message. Fixed-width fields are surfaced only so the
/// cursor advances past them; their numbers/values are never read by the gateway.
// A general-purpose codec surface: the gateway's two callers only read `Len` fields, but the other
// variants complete the reader (and are exercised by tests), so unread payloads are expected.
#[allow(dead_code)]
pub enum Field<'a> {
    Varint(u32, u64),
    Len(u32, &'a [u8]),
    Fixed64,
    Fixed32,
}

/// A cursor that yields a message's top-level fields in order (a repeated field appears multiple
/// times). Malformed input simply ends iteration, so callers fail closed.
pub struct ProtoReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_varint(&mut self) -> Option<u64> {
        let mut shift = 0u32;
        let mut out = 0u64;
        loop {
            let b = *self.buf.get(self.pos)?;
            self.pos += 1;
            out |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Some(out);
            }
            shift += 7;
            if shift >= 64 {
                return None;
            }
        }
    }
}

impl<'a> Iterator for ProtoReader<'a> {
    type Item = Field<'a>;

    fn next(&mut self) -> Option<Field<'a>> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let key = self.read_varint()?;
        let field = (key >> 3) as u32;
        match (key & 7) as u8 {
            0 => {
                let v = self.read_varint()?;
                Some(Field::Varint(field, v))
            }
            2 => {
                // `try_from`, not `as`: on wasm32 `usize` is 32 bits and `as` would truncate a length of 2^32 + n to n
                // (audit F60); a length that does not fit is a length the buffer cannot hold.
                let len = usize::try_from(self.read_varint()?).ok()?;
                let start = self.pos;
                let end = start.checked_add(len)?;
                if end > self.buf.len() {
                    return None;
                }
                self.pos = end;
                Some(Field::Len(field, &self.buf[start..end]))
            }
            1 => {
                self.pos = self.pos.checked_add(8)?;
                if self.pos > self.buf.len() {
                    return None;
                }
                Some(Field::Fixed64)
            }
            5 => {
                self.pos = self.pos.checked_add(4)?;
                if self.pos > self.buf.len() {
                    return None;
                }
                Some(Field::Fixed32)
            }
            _ => None,
        }
    }
}

/// The bytes of the first length-delimited field `field` in `msg`.
pub fn field_bytes(msg: &[u8], field: u32) -> Option<&[u8]> {
    ProtoReader::new(msg).find_map(|f| match f {
        Field::Len(n, b) if n == field => Some(b),
        _ => None,
    })
}

/// The UTF-8 string of the first length-delimited field `field` in `msg`.
pub fn field_str(msg: &[u8], field: u32) -> Option<&str> {
    field_bytes(msg, field).and_then(|b| std::str::from_utf8(b).ok())
}

// ── google.protobuf.Value / Struct recursive lookup ──────────────────────────────────────────
// Value: string_value = 3, struct_value = 5, list_value = 6.
// Struct: fields = 1 (repeated map entry { key = 1 string, value = 2 Value }).
// ListValue: values = 1 (repeated Value).
// This finds the first `string_value` for a field named `key` at any depth — handling both a
// top-level `gate_id` (the event json) and one nested under `data` (the NFT json), order- and
// depth-independent, so it never assumes BCS field order.

const VALUE_STRING: u32 = 3;
const VALUE_BOOL: u32 = 4;
const VALUE_STRUCT: u32 = 5;
const VALUE_LIST: u32 = 6;
const STRUCT_FIELDS: u32 = 1;
const ENTRY_KEY: u32 = 1;
const ENTRY_VALUE: u32 = 2;
const LIST_VALUES: u32 = 1;

/// Find the `string_value` of the first field named `key` anywhere within a `google.protobuf.Value`
/// (at most [`MAX_VALUE_DEPTH`] levels deep; deeper input is not searched).
pub fn value_find_string(value: &[u8], key: &str) -> Option<String> {
    value_find_string_at(value, key, 0)
}

fn value_find_string_at(value: &[u8], key: &str, depth: usize) -> Option<String> {
    if depth >= MAX_VALUE_DEPTH {
        return None;
    }
    for f in ProtoReader::new(value) {
        match f {
            Field::Len(VALUE_STRUCT, s) => {
                if let Some(v) = struct_find_string(s, key, depth + 1) {
                    return Some(v);
                }
            }
            Field::Len(VALUE_LIST, l) => {
                for lf in ProtoReader::new(l) {
                    if let Field::Len(LIST_VALUES, item) = lf {
                        if let Some(v) = value_find_string_at(item, key, depth + 1) {
                            return Some(v);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    None
}

fn struct_find_string(s: &[u8], key: &str, depth: usize) -> Option<String> {
    for f in ProtoReader::new(s) {
        if let Field::Len(STRUCT_FIELDS, entry) = f {
            let entry_key = field_str(entry, ENTRY_KEY);
            let entry_val = field_bytes(entry, ENTRY_VALUE);
            if let (Some(k), Some(v)) = (entry_key, entry_val) {
                if k == key {
                    if let Some(sv) = field_str(v, VALUE_STRING) {
                        return Some(sv.to_string());
                    }
                }
                // Recurse to reach a key nested deeper (e.g. an NFT's `data.gate_id`).
                if let Some(found) = value_find_string_at(v, key, depth) {
                    return Some(found);
                }
            }
        }
    }
    None
}

/// The `Value` of the top-level field `key` of a Struct-valued `google.protobuf.Value` (no
/// recursion — for reading a known object's own fields, e.g. a `Gate`'s `paused` / `policy`).
pub fn value_field<'a>(value: &'a [u8], key: &str) -> Option<&'a [u8]> {
    let s = field_bytes(value, VALUE_STRUCT)?;
    ProtoReader::new(s).find_map(|f| match f {
        Field::Len(STRUCT_FIELDS, entry) if field_str(entry, ENTRY_KEY) == Some(key) => {
            field_bytes(entry, ENTRY_VALUE)
        }
        _ => None,
    })
}

/// The `bool_value` of a `google.protobuf.Value`, if it holds one.
pub fn value_as_bool(value: &[u8]) -> Option<bool> {
    ProtoReader::new(value).find_map(|f| match f {
        Field::Varint(VALUE_BOOL, v) => Some(v != 0),
        _ => None,
    })
}

// ── gRPC-web framing + transport ─────────────────────────────────────────────────────────────

/// Frame a protobuf message as a single uncompressed gRPC-web data frame.
pub fn frame(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + msg.len());
    out.push(0x00); // compression flag: uncompressed
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// The trailer line that carries the status (compared case-insensitively).
const GRPC_STATUS_PREFIX: &str = "grpc-status:";

/// Parse a `grpc-status` value.
fn parse_status(v: &str) -> Option<i64> {
    v.trim().parse::<i64>().ok()
}

/// The protobuf message inside a single gRPC-web request frame (tests read what the client sent).
#[doc(hidden)]
pub fn unframe_request_for_test(body: &[u8]) -> Vec<u8> {
    assert_eq!(body[0], 0, "uncompressed data frame");
    let len = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    assert_eq!(body.len(), 5 + len, "exactly one frame");
    body[5..].to_vec()
}

/// Unframe a gRPC-web response: concatenate data frames (high bit of the flag clear) into the
/// response message and read `grpc-status` from the trailer frame (high bit set) or, for a
/// trailers-only response (how full nodes answer errors such as NOT_FOUND), from the HTTP headers.
/// Fails closed on a non-zero status, a missing status, trailing garbage, malformed framing, or a
/// message over [`MAX_GRPC_MESSAGE_BYTES`].
pub fn unframe(grpc_status_header: Option<&str>, body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut msg = Vec::new();
    let mut grpc_status: Option<i64> = grpc_status_header.and_then(parse_status);
    let mut i = 0usize;
    while i + 5 <= body.len() {
        let flag = body[i];
        let len = u32::from_be_bytes([body[i + 1], body[i + 2], body[i + 3], body[i + 4]]) as usize;
        i += 5;
        let end = i
            .checked_add(len)
            .filter(|e| *e <= body.len())
            .ok_or_else(|| anyhow::anyhow!("gRPC-web frame overruns body"))?;
        let frame = &body[i..end];
        i = end;
        if flag & 0x80 != 0 {
            // Trailer frame: an HTTP-header block, e.g. "grpc-status:0\r\ngrpc-message:...".
            for line in String::from_utf8_lossy(frame).split("\r\n") {
                // `get`, not slicing: lossy decoding yields multi-byte replacement characters, and byte 12 of a
                // hostile trailer may fall inside one (a `str` slice there panics: audit F58).
                let line = line.trim();
                if let Some(value) = line
                    .get(..GRPC_STATUS_PREFIX.len())
                    .filter(|p| p.eq_ignore_ascii_case(GRPC_STATUS_PREFIX))
                    .and_then(|_| line.get(GRPC_STATUS_PREFIX.len()..))
                {
                    grpc_status = parse_status(value);
                }
            }
        } else {
            if flag != 0 {
                anyhow::bail!("compressed gRPC-web frames are not supported");
            }
            if msg.len() + frame.len() > MAX_GRPC_MESSAGE_BYTES {
                anyhow::bail!("gRPC message exceeds {MAX_GRPC_MESSAGE_BYTES} bytes");
            }
            msg.extend_from_slice(frame);
        }
    }
    if i != body.len() {
        anyhow::bail!("gRPC-web body has a truncated frame header");
    }
    match grpc_status {
        Some(0) => Ok(msg),
        Some(code) => Err(anyhow::Error::new(GrpcStatus(code))),
        None => anyhow::bail!("gRPC-web response carries no grpc-status"),
    }
}

/// A non-zero gRPC status from the node, kept typed so callers can react to one code (a missing
/// transaction is `NOT_FOUND`, the only failure worth retrying) instead of matching message text.
#[derive(Debug)]
pub struct GrpcStatus(pub i64);

/// gRPC `NOT_FOUND`.
pub const GRPC_NOT_FOUND: i64 = 5;

impl std::fmt::Display for GrpcStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "gRPC status {}", self.0)
    }
}

impl std::error::Error for GrpcStatus {}

/// The one thing the gRPC-web client needs from the platform: POST framed bytes, get back the
/// response `grpc-status` HTTP header (trailers-only responses) and the full body. The native gateway
/// implements it over hyper-rustls, the Worker over `fetch`. `sleep` is here too because neither
/// `tokio::time` nor `std::time` exists in a Worker isolate.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// POST `body` (already gRPC-web framed) to `url`. Returns `(grpc-status header, body)`; a
    /// non-2xx HTTP status or a body over [`MAX_GRPC_MESSAGE_BYTES`] must be an `Err`.
    async fn post_grpc_web(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> anyhow::Result<(Option<String>, Vec<u8>)>;
    /// Suspend for `ms` milliseconds (retry back-off).
    async fn sleep_ms(&self, ms: u64);
    /// Milliseconds since the Unix epoch (`SystemTime::now` panics on wasm32-unknown-unknown).
    fn now_ms(&self) -> u64;
}

/// gRPC-web client bound to one Sui full-node base URL, generic over the platform [`Transport`].
pub struct GrpcWeb<T: Transport> {
    transport: T,
    base_url: String,
}

impl<T: Transport> GrpcWeb<T> {
    pub fn new(transport: T, base_url: String) -> Self {
        Self {
            transport,
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Invoke `sui.rpc.v2.<service_method>` with a protobuf `request` message; returns the decoded
    /// (unframed) response message bytes.
    pub async fn call(&self, service_method: &str, request: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let url = format!("{}/{}", self.base_url, service_method);
        let (status, body) = self.transport.post_grpc_web(&url, frame(&request)).await?;
        unframe(status.as_deref(), &body)
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Arbitrary bytes never panic the readers, and every yielded field stays in bounds.
        #[test]
        fn proto_reader_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..512)) {
            for f in ProtoReader::new(&buf) {
                if let Field::Len(_, b) = f {
                    prop_assert!(b.len() <= buf.len());
                }
            }
        }

        #[test]
        fn value_lookup_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = value_find_string(&buf, "gate_id");
            let _ = value_field(&buf, "paused").and_then(value_as_bool);
        }

        // Trailer frames with arbitrary text (including multi-byte and invalid UTF-8) never panic (audit F58).
        #[test]
        fn trailer_frames_never_panic(
            payload in proptest::collection::vec(any::<u8>(), 0..64),
            tail in proptest::collection::vec(any::<u8>(), 0..16),
        ) {
            let mut body = vec![0x80];
            body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            body.extend_from_slice(&payload);
            body.extend_from_slice(&tail);
            let _ = unframe(None, &body);
            let text: String = String::from_utf8_lossy(&payload).into_owned();
            let mut body = vec![0x80];
            body.extend_from_slice(&(text.len() as u32).to_be_bytes());
            body.extend_from_slice(text.as_bytes());
            let _ = unframe(None, &body);
        }

        #[test]
        fn unframe_never_panics_and_respects_the_cap(buf in proptest::collection::vec(any::<u8>(), 0..512)) {
            if let Ok(msg) = unframe(None, &buf) {
                prop_assert!(msg.len() <= MAX_GRPC_MESSAGE_BYTES);
                prop_assert!(msg.len() <= buf.len());
            }
        }

        // Anything the writer produces reads back identically.
        #[test]
        fn writer_reader_round_trip_any(field in 1u32..536_870_911, data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let mut w = ProtoWriter::new();
            w.bytes_field(field, &data);
            let bytes = w.into_bytes();
            prop_assert_eq!(field_bytes(&bytes, field), Some(&data[..]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_reader_round_trip() {
        let mut w = ProtoWriter::new();
        w.string_field(1, "hello");
        w.uint_field(2, 300);
        w.bytes_field(3, &[9, 8, 7]);
        let bytes = w.into_bytes();

        assert_eq!(field_str(&bytes, 1), Some("hello"));
        assert_eq!(field_bytes(&bytes, 3), Some(&[9u8, 8, 7][..]));
        let v = ProtoReader::new(&bytes).find_map(|f| match f {
            Field::Varint(2, v) => Some(v),
            _ => None,
        });
        assert_eq!(v, Some(300));
    }

    #[test]
    fn frame_unframe_round_trip() {
        let msg = b"\x08\x96\x01"; // arbitrary protobuf bytes
        let framed = frame(msg);
        assert_eq!(framed[0], 0x00);
        // Append a trailer frame carrying grpc-status:0.
        let trailer = b"grpc-status:0\r\n";
        let mut body = framed.clone();
        body.push(0x80);
        body.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
        body.extend_from_slice(trailer);
        assert_eq!(unframe(None, &body).unwrap(), msg);
    }

    #[test]
    fn unframe_fails_closed_without_a_status() {
        // A data frame with no trailer and no grpc-status header is not a complete response.
        assert!(unframe(None, &frame(b"msg")).is_err());
    }

    fn trailer_frame(payload: &[u8]) -> Vec<u8> {
        let mut body = vec![0x80];
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(payload);
        body
    }

    /// Audit F58: byte 12 of a trailer line fell inside a multi-byte character (a lossy-decoding replacement
    /// character, or a real one) and `line[..12]` panicked. Found by the `grpc` fuzz target; this is its minimised input.
    #[test]
    fn a_trailer_line_with_a_multibyte_character_at_byte_12_is_not_a_panic() {
        // The fuzzer's minimised input after the selector byte: 0x80, length 15, then invalid UTF-8 that decodes to
        // U+FFFD (3 bytes each), so bytes 10..13 of the line are one character.
        let fuzz = [
            128u8, 0, 0, 0, 15, 255, 0, 231, 231, 231, 231, 231, 231, 231, 0, 231, 231, 231, 231,
            255,
        ];
        assert!(unframe(None, &fuzz).is_err());
        // With a status in the HTTP headers the unreadable trailer changes nothing.
        assert_eq!(unframe(Some("0"), &fuzz).unwrap(), Vec::<u8>::new());
        // The same with valid UTF-8: "grpc-status" is 11 bytes, then a two-byte character covers bytes 11..13.
        for line in [
            "grpc-status\u{e9}:0",
            "grpc-statu\u{20ac}0",
            "\u{1f600}\u{1f600}\u{1f600}\u{1f600}",
        ] {
            assert!(
                unframe(None, &trailer_frame(line.as_bytes())).is_err(),
                "{line:?}"
            );
        }
        // A well-formed status after such a line is still read, and the prefix is case-insensitive.
        let mut payload = "grpc-status\u{e9}:9\r\nGRPC-Status: 0\r\n"
            .as_bytes()
            .to_vec();
        assert_eq!(
            unframe(None, &trailer_frame(&payload)).unwrap(),
            Vec::<u8>::new()
        );
        payload.extend_from_slice(b"grpc-status:5\r\n");
        assert!(unframe(None, &trailer_frame(&payload)).is_err()); // the last status wins: NOT_FOUND
    }

    /// Audit F60: the length of a length-delimited field is converted with `try_from`, so a length that does not fit
    /// `usize` (on wasm32: anything at or above 2^32) can never be read as a shorter one.
    #[test]
    fn a_field_length_above_u32_max_is_never_truncated() {
        // field 1, wire type 2, length 2^32 + 3 (varint), then three bytes that a truncated length would accept.
        let mut msg = vec![0x0a];
        let mut n: u64 = (1u64 << 32) + 3;
        while n >= 0x80 {
            msg.push((n & 0x7f) as u8 | 0x80);
            n >>= 7;
        }
        msg.push(n as u8);
        msg.extend_from_slice(b"abc");
        assert!(field_bytes(&msg, 1).is_none());
        assert_eq!(ProtoReader::new(&msg).count(), 0);
        assert_eq!(
            usize::try_from(u64::from(u32::MAX) + 1).is_ok(),
            usize::BITS > 32
        );
    }

    #[test]
    fn unframe_reads_trailers_only_status_from_headers() {
        assert!(unframe(Some("5"), &[]).is_err()); // NOT_FOUND, empty body
        assert_eq!(unframe(Some("0"), &[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn unframe_rejects_truncated_and_compressed_frames() {
        let ok_status = Some("0");
        let mut body = frame(b"msg");
        body.extend_from_slice(&[0x00, 0x00]); // stray partial header
        assert!(unframe(ok_status, &body).is_err());
        let mut compressed = frame(b"msg");
        compressed[0] = 0x01;
        assert!(unframe(ok_status, &compressed).is_err());
    }

    #[test]
    fn value_find_string_stops_at_the_depth_limit() {
        // Wrap a {gate_id} struct in 40 list levels: deeper than MAX_VALUE_DEPTH, so not found.
        let mut v = struct_value(&[("gate_id", "0xGATE")]);
        for _ in 0..40 {
            let mut list = ProtoWriter::new();
            list.bytes_field(LIST_VALUES, &v);
            let mut value = ProtoWriter::new();
            value.bytes_field(VALUE_LIST, &list.into_bytes());
            v = value.into_bytes();
        }
        assert_eq!(value_find_string(&v, "gate_id"), None);
    }

    #[test]
    fn unframe_rejects_nonzero_status() {
        let mut body = frame(b"partial");
        let trailer = b"grpc-status:7\r\ngrpc-message:denied";
        body.push(0x80);
        body.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
        body.extend_from_slice(trailer);
        assert!(unframe(None, &body).is_err());
    }

    /// Build a `google.protobuf.Value` wrapping a Struct with the given (key, string) entries.
    fn struct_value(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut s = ProtoWriter::new();
        for (k, v) in entries {
            let mut val = ProtoWriter::new();
            val.string_field(VALUE_STRING, v);
            let mut entry = ProtoWriter::new();
            entry.string_field(ENTRY_KEY, k);
            entry.bytes_field(ENTRY_VALUE, &val.into_bytes());
            s.bytes_field(STRUCT_FIELDS, &entry.into_bytes());
        }
        let mut value = ProtoWriter::new();
        value.bytes_field(VALUE_STRUCT, &s.into_bytes());
        value.into_bytes()
    }

    #[test]
    fn value_find_string_top_level() {
        let v = struct_value(&[("gate_id", "0xGATE"), ("nft_id", "0xNFT")]);
        assert_eq!(value_find_string(&v, "gate_id").as_deref(), Some("0xGATE"));
        assert_eq!(value_find_string(&v, "missing"), None);
    }

    #[test]
    fn value_find_string_nested_under_data() {
        // Outer struct: { data: { gate_id: "0xGATE" } } — mirrors the NFT json shape.
        let inner = struct_value(&[("gate_id", "0xGATE")]);
        let mut entry = ProtoWriter::new();
        entry.string_field(ENTRY_KEY, "data");
        entry.bytes_field(ENTRY_VALUE, &inner);
        let mut s = ProtoWriter::new();
        s.bytes_field(STRUCT_FIELDS, &entry.into_bytes());
        let mut outer = ProtoWriter::new();
        outer.bytes_field(VALUE_STRUCT, &s.into_bytes());
        assert_eq!(
            value_find_string(&outer.into_bytes(), "gate_id").as_deref(),
            Some("0xGATE")
        );
    }
}
