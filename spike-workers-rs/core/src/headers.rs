//! Header policy that does not depend on an HTTP library: the lists and predicates. Each platform
//! applies them to its own header map (`http::HeaderMap` natively, `web_sys::Headers` in a Worker).
//! Lists are the ones in `gateway-rust/src/headers.rs` and `gateway-workers/src/headers.ts`.

/// Fields that are hop-by-hop by definition.
pub const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// The `Via` entry this gateway adds to every upstream request (audit F43).
pub const VIA_TOKEN: &str = "1.1 nft-gate";

/// True if a `Via` header value (all `Via` fields joined with `,`) already carries this gateway's own
/// received-by name `nft-gate` (case-insensitive). Foreign names pass.
pub fn via_is_looped(via: &str) -> bool {
    via.split(',').any(|entry| {
        entry
            .split_whitespace()
            .nth(1)
            .is_some_and(|by| by.eq_ignore_ascii_case("nft-gate"))
    })
}

/// Client-supplied request fields never forwarded.
pub const REQUEST_STRIP: [&str; 11] = [
    "host",
    "authorization",
    "x-access-proof",
    "content-length",
    "cookie",
    "forwarded",
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
];

/// Upstream response fields never returned.
pub const RESPONSE_STRIP: [&str; 4] = ["content-length", "set-cookie", "set-cookie2", "alt-svc"];

/// Names listed in a `Connection` header (lower-cased) — also hop-by-hop for that message.
pub fn connection_named(connection: &str) -> Vec<String> {
    connection
        .split(',')
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// True if `path` is safe to append to the upstream URL: no encoded separators, NUL, backslash,
/// control characters, dot-dot segments or empty segments. This is the gateway-rust rule; the
/// Worker (`isSafePath`) currently lacks the literal `..` segment check (the Workers URL parser
/// normalises dot segments first, so it is not exploitable there — see FINDINGS.md).
pub fn is_safe_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    !(lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
        || lower.contains("%2e%2e")
        || path.contains('\\')
        || path.contains("//")
        || path.split('/').any(|seg| seg == "..")
        || path.bytes().any(|b| b < 0x20 || b == 0x7f))
}

/// Should the request header `name` (lower-case) be dropped before forwarding? `connection_named`
/// is [`connection_named`] of the request's `Connection` header. One predicate for every platform.
pub fn drop_request_header(name: &str, connection_named: &[String]) -> bool {
    HOP_BY_HOP.contains(&name)
        || connection_named.iter().any(|n| n == name)
        || REQUEST_STRIP.contains(&name)
        || name.starts_with("cf-access-")
}

/// Should the upstream response header `name` (lower-case) be dropped before returning it?
pub fn drop_response_header(name: &str, connection_named: &[String]) -> bool {
    HOP_BY_HOP.contains(&name)
        || connection_named.iter().any(|n| n == name)
        || RESPONSE_STRIP.contains(&name)
        || name.starts_with("access-control-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn via_loop_matches_only_our_received_by_name() {
        assert!(via_is_looped("1.1 nft-gate"));
        assert!(via_is_looped("1.1 google, 1.1 NFT-GATE (comment)"));
        assert!(!via_is_looped("1.1 google"));
        assert!(!via_is_looped("1.1 nft-gate-other"));
        assert!(!via_is_looped(""));
    }

    #[test]
    fn drop_predicates() {
        let named = connection_named("X-Hop, keep-alive");
        assert!(drop_request_header("x-hop", &named));
        assert!(drop_request_header("cf-access-client-secret", &[]));
        assert!(drop_request_header("via", &[]));
        assert!(!drop_request_header("content-type", &named));
        assert!(drop_response_header("access-control-allow-origin", &[]));
        assert!(drop_response_header("set-cookie", &[]));
        assert!(!drop_response_header("etag", &[]));
    }

    #[test]
    fn safe_path() {
        assert!(is_safe_path("/v1/tip-config"));
        assert!(!is_safe_path("/a/../b"));
        assert!(!is_safe_path("/a//b"));
        assert!(!is_safe_path("/a%2Fb"));
        assert!(!is_safe_path("/a\\b"));
    }
}
