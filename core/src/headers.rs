//! Header policy that does not depend on an HTTP library: the lists and predicates. Each platform
//! applies them to its own header map (`http::HeaderMap` natively, `web_sys::Headers` in a Worker),
//! so the policy exists once. The rules follow RFC 9110 §7.6.1: hop-by-hop fields describe one
//! connection, not the message, so they are removed in both directions (the fixed set plus every
//! field the `Connection` header names). Credentials, cookies and spoofable forwarding fields are
//! removed from the request, and upstream cookies and CORS fields from the response (the gateway
//! emits its own CORS from `ALLOWED_ORIGINS`).

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

/// The `Via` entry (RFC 9110 §7.6.3) this gateway adds to every upstream request. A request that
/// arrives already carrying it has looped back to the gateway (audit F43), whichever hostname it took.
pub const VIA_TOKEN: &str = "1.1 nft-gate";

/// True if a `Via` header value (all `Via` fields joined with `,`) already carries this gateway's own
/// received-by name `nft-gate` (case-insensitive). Each comma-separated entry is
/// `protocol received-by [comment]`; a comment is not examined, so `1.1 google (nft-gate)` is foreign.
/// Foreign names (a CDN's `1.1 google`) pass.
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

/// Names listed in a `Connection` header (lower-cased): also hop-by-hop for that message.
pub fn connection_named(connection: &str) -> Vec<String> {
    connection
        .split(',')
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// True if `path` is safe to append to the upstream URL: no encoded separators, NUL, backslash,
/// control characters, `..` segments or empty segments.
///
/// A literal `..` segment is refused (decided 2026-10-19, one rule for every platform). The Cloudflare
/// URL parser already resolves dot segments before a Worker sees the path, so the rule was never
/// exploitable there; the retiring TypeScript Worker (`isSafePath`) lacks the check, the single
/// implementation has it.
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
/// is [`connection_named`] of the request's `Connection` header. The upstream's own access
/// credentials (`cf-access-*`) are the gateway's alone, so anything the client sent in that namespace
/// goes too (the configured ones are added by the platform).
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

/// Extract the base64 access-proof token from the request. Prefers `Authorization: Bearer <token>`
/// (scheme case-insensitive, any whitespace after it: the Workers gateway's `^Bearer\s+(.+)$`); falls
/// back to the `X-Access-Proof` header. This order is canonical for every platform and the client.
pub fn extract_proof_token(
    authorization: Option<&str>,
    x_access_proof: Option<&str>,
) -> Option<String> {
    if let Some((scheme, rest)) = authorization.and_then(|s| s.split_once(char::is_whitespace)) {
        let token = rest.trim();
        if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
            return Some(token.to_string());
        }
    }
    x_access_proof.map(|s| s.trim().to_string())
}

/// Grants every response carries: the same set on every platform and in the Workers gateway (`cors.ts`).
pub const CORS_GRANTS: [(&str, &str); 4] = [
    (
        "access-control-allow-methods",
        "GET, POST, PUT, HEAD, OPTIONS",
    ),
    (
        "access-control-allow-headers",
        "authorization, content-type, x-access-proof",
    ),
    ("access-control-expose-headers", "location, upload-offset"),
    ("access-control-max-age", "86400"),
];

/// The request `Origin` to reflect in `Access-Control-Allow-Origin`: only an exact `ALLOWED_ORIGINS`
/// match, otherwise none (a response then carries no grant at all). Every response also carries
/// `Vary: Origin`, and a preflight is answered before rate limits and auth.
pub fn cors_allowed_origin<'a>(origin: Option<&'a str>, allowed: &[String]) -> Option<&'a str> {
    origin.filter(|o| allowed.iter().any(|a| a == o))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Loop detection table (F43). Identical in the Workers gateway (`test/proxy.test.ts`,
    /// `VIA_TABLE`) until it retires: the same inputs must give the same answers.
    const VIA_TABLE: [(&str, bool); 14] = [
        ("", false),
        ("", false),
        ("1.1 nft-gate", true),
        ("1.1 NFT-GATE", true),
        ("HTTP/1.1 nft-gate (gateway)", true),
        ("1.1 google, 1.1 nft-gate", true),
        ("1.1 nft-gate, 1.1 google", true),
        ("1.1 google", false),
        ("1.1 varnish (Varnish/6.0)", false),
        ("1.1 google (nft-gate)", false),
        ("1.1 nft-gateway", false),
        ("1.1 my-nft-gate", false),
        ("nft-gate", false),
        ("1.1 registry-auth-proxy", false),
    ];

    #[test]
    fn via_loop_table() {
        for (via, looped) in VIA_TABLE {
            assert_eq!(via_is_looped(via), looped, "{via:?}");
        }
        // Several Via fields are read as one list (the platform joins them with a comma).
        assert!(via_is_looped("1.1 google,1.1 nft-gate"));
    }

    #[test]
    fn the_marker_the_gateway_adds_is_the_one_it_refuses() {
        assert!(via_is_looped(VIA_TOKEN));
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
    fn every_listed_request_and_hop_field_is_dropped() {
        let named = connection_named("x-secret-hop, close");
        for gone in HOP_BY_HOP
            .iter()
            .chain(REQUEST_STRIP.iter())
            .chain(["x-secret-hop", "cf-access-client-secret"].iter())
        {
            assert!(drop_request_header(gone, &named), "{gone}");
        }
        for kept in ["x-keep-me", "content-type", "accept"] {
            assert!(!drop_request_header(kept, &named), "{kept}");
        }
        for gone in HOP_BY_HOP
            .iter()
            .chain(RESPONSE_STRIP.iter())
            .chain(["access-control-allow-credentials"].iter())
        {
            assert!(drop_response_header(gone, &[]), "{gone}");
        }
        assert!(!drop_response_header("x-relay", &[]));
    }

    #[test]
    fn unsafe_paths_are_refused() {
        for bad in [
            "/a%2fb",
            "/a%2Fb",
            "/a%5cb",
            "/a%00",
            "/a//b",
            "/a/../b",
            "/..",
            "/a/..",
            "/a\\b",
            "/a%2e%2e/b",
            "/a\u{1}b",
            "/a\u{7f}",
        ] {
            assert!(!is_safe_path(bad), "{bad}");
        }
        for ok in [
            "/v1/blob-upload-relay",
            "/v1/tip-config",
            "/",
            "/a..b",
            "/..a/b",
        ] {
            assert!(is_safe_path(ok), "{ok}");
        }
    }

    #[test]
    fn bearer_token_extraction_matches_the_workers_gateway() {
        for (auth, want) in [
            ("Bearer abc", Some("abc")),
            ("bearer abc", Some("abc")),
            ("BEARER   abc", Some("abc")),
            ("Bearer\tabc", Some("abc")),
            ("Bearer ", None),
            ("Basic abc", None),
            ("abc", None),
        ] {
            assert_eq!(
                extract_proof_token(Some(auth), None).as_deref(),
                want,
                "{auth:?}"
            );
        }
        // Bearer wins over X-Access-Proof; the header is the fallback.
        assert_eq!(
            extract_proof_token(Some("Bearer abc"), Some("zzz")).as_deref(),
            Some("abc")
        );
        assert_eq!(
            extract_proof_token(None, Some(" zzz ")).as_deref(),
            Some("zzz")
        );
        assert_eq!(
            extract_proof_token(Some("Basic abc"), Some("zzz")).as_deref(),
            Some("zzz")
        );
        assert_eq!(extract_proof_token(None, None), None);
    }

    #[test]
    fn cors_reflects_only_an_exact_allowed_origin() {
        let allowed = vec!["https://app.example".to_string()];
        assert_eq!(
            cors_allowed_origin(Some("https://app.example"), &allowed),
            Some("https://app.example")
        );
        for origin in [
            Some("https://evil.example"),
            Some("https://app.example.evil"),
            Some("https://app.example/"),
            None,
        ] {
            assert_eq!(cors_allowed_origin(origin, &allowed), None, "{origin:?}");
        }
        assert_eq!(cors_allowed_origin(Some("https://app.example"), &[]), None);
    }
}
