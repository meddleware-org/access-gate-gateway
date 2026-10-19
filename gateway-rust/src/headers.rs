//! Header policy for a forwarding hop (RFC 9110 §7.6.1): the same lists as the Workers gateway
//! (`headers.ts`). Hop-by-hop fields describe one connection, not the message, so they are removed
//! in both directions: the fixed set plus every field the `Connection` header names. Credentials,
//! cookies and spoofable forwarding fields are removed from the request, and upstream cookies and
//! CORS fields from the response (the gateway emits its own CORS from `ALLOWED_ORIGINS`).

use axum::http::{header, HeaderMap, HeaderName, HeaderValue};

/// Fields that are hop-by-hop by definition.
const HOP_BY_HOP: [&str; 9] = [
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
/// arrives already carrying it has looped back to the gateway (F43), whichever hostname it took.
pub const VIA_TOKEN: &str = "1.1 nft-gate";

/// True if `headers` already carry this gateway's own `Via` entry. Only the received-by name
/// `nft-gate` matches: any other value (e.g. a CDN's `1.1 google`) is foreign and passes. Each
/// comma-separated entry is `protocol received-by [comment]`; a comment is not examined.
pub fn is_looped(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::VIA)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|entry| {
            entry
                .split_whitespace()
                .nth(1)
                .is_some_and(|by| by.eq_ignore_ascii_case("nft-gate"))
        })
}

/// Client-supplied fields the gateway never forwards.
const REQUEST_STRIP: [&str; 11] = [
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

/// Upstream fields the gateway never returns (CORS is handled separately by prefix).
const RESPONSE_STRIP: [&str; 4] = ["content-length", "set-cookie", "set-cookie2", "alt-svc"];

/// Remove the hop-by-hop fields, including those named in `Connection`, from `headers`.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<String> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    for name in HOP_BY_HOP.iter().map(|n| n.to_string()).chain(named) {
        if let Ok(n) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(n);
        }
    }
}

fn remove_prefixed(headers: &mut HeaderMap, prefix: &str) {
    let doomed: Vec<HeaderName> = headers
        .keys()
        .filter(|k| k.as_str().starts_with(prefix))
        .cloned()
        .collect();
    for k in doomed {
        headers.remove(k);
    }
}

/// The headers to send upstream: the client's, minus hop-by-hop, credentials and spoofable fields.
/// The upstream's own access credentials (`cf-access-*`) are the gateway's alone, so anything the
/// client sent in that namespace is dropped (the configured ones are added by the HTTP client).
pub fn upstream_request_headers(incoming: &HeaderMap) -> HeaderMap {
    let mut headers = incoming.clone();
    strip_hop_by_hop(&mut headers);
    for name in REQUEST_STRIP {
        headers.remove(name);
    }
    remove_prefixed(&mut headers, "cf-access-");
    // The gateway's own hop marker, set after the client's `via` was dropped (F43).
    headers.insert(header::VIA, HeaderValue::from_static(VIA_TOKEN));
    headers
}

/// The headers to return to the client: the upstream's, minus hop-by-hop, cookies and CORS fields.
pub fn client_response_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut headers = upstream.clone();
    strip_hop_by_hop(&mut headers);
    for name in RESPONSE_STRIP {
        headers.remove(name);
    }
    remove_prefixed(&mut headers, "access-control-");
    headers
}

/// True if `path` is safe to append to the upstream URL: no encoded separators, NUL, backslash,
/// control characters, dot-dot segments or empty segments.
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn request_strips_hop_by_hop_connection_named_credentials_and_spoofable_fields() {
        let out = upstream_request_headers(&map(&[
            ("connection", "x-secret-hop, close"),
            ("x-secret-hop", "v"),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("upgrade", "websocket"),
            ("proxy-authorization", "Basic abc"),
            ("authorization", "Bearer proof"),
            ("x-access-proof", "proof"),
            ("cookie", "session=1"),
            ("forwarded", "for=1.2.3.4"),
            ("x-forwarded-for", "1.2.3.4"),
            ("via", "1.1 evil"),
            ("cf-access-client-secret", "client-supplied"),
            ("x-keep-me", "yes"),
        ]));
        for gone in [
            "connection",
            "x-secret-hop",
            "keep-alive",
            "te",
            "upgrade",
            "proxy-authorization",
            "authorization",
            "x-access-proof",
            "cookie",
            "forwarded",
            "x-forwarded-for",
            "cf-access-client-secret",
        ] {
            assert!(!out.contains_key(gone), "{gone}");
        }
        // The client's `via` is dropped and replaced by the gateway's own hop marker (F43).
        assert_eq!(out["via"], VIA_TOKEN);
        assert_eq!(out.get_all("via").iter().count(), 1);
        assert_eq!(out["x-keep-me"], "yes");
    }

    /// Loop detection table (F43). Identical in the Workers gateway (`test/proxy.test.ts`,
    /// `VIA_TABLE`): the same inputs must give the same answers.
    const VIA_TABLE: [(Option<&str>, bool); 14] = [
        (None, false),
        (Some(""), false),
        (Some("1.1 nft-gate"), true),
        (Some("1.1 NFT-GATE"), true),
        (Some("HTTP/1.1 nft-gate (gateway)"), true),
        (Some("1.1 google, 1.1 nft-gate"), true),
        (Some("1.1 nft-gate, 1.1 google"), true),
        (Some("1.1 google"), false),
        (Some("1.1 varnish (Varnish/6.0)"), false),
        (Some("1.1 google (nft-gate)"), false),
        (Some("1.1 nft-gateway"), false),
        (Some("1.1 my-nft-gate"), false),
        (Some("nft-gate"), false),
        (Some("1.1 registry-auth-proxy"), false),
    ];

    #[test]
    fn via_loop_table() {
        for (via, looped) in VIA_TABLE {
            let h = match via {
                Some(v) => map(&[("via", v)]),
                None => HeaderMap::new(),
            };
            assert_eq!(is_looped(&h), looped, "{via:?}");
        }
        // Several Via fields are read as one list.
        let mut h = map(&[("via", "1.1 google")]);
        h.append("via", HeaderValue::from_static("1.1 nft-gate"));
        assert!(is_looped(&h));
    }

    #[test]
    fn the_marker_the_gateway_adds_is_the_one_it_refuses() {
        assert!(is_looped(&upstream_request_headers(&map(&[(
            "via",
            "1.1 google"
        )]))));
    }

    #[test]
    fn response_strips_hop_by_hop_cookies_and_upstream_cors() {
        let out = client_response_headers(&map(&[
            ("keep-alive", "timeout=5"),
            ("set-cookie", "a=b"),
            ("access-control-allow-origin", "*"),
            ("access-control-allow-credentials", "true"),
            ("x-relay", "kept"),
        ]));
        for gone in [
            "keep-alive",
            "set-cookie",
            "access-control-allow-origin",
            "access-control-allow-credentials",
        ] {
            assert!(!out.contains_key(gone), "{gone}");
        }
        assert_eq!(out["x-relay"], "kept");
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
            "/a\\b",
            "/a%2e%2e/b",
        ] {
            assert!(!is_safe_path(bad), "{bad}");
        }
        for ok in ["/v1/blob-upload-relay", "/v1/tip-config", "/"] {
            assert!(is_safe_path(ok), "{ok}");
        }
    }
}
