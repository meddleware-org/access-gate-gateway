//! Header policy for a forwarding hop, applied to `http::HeaderMap`. The policy itself (which fields
//! go, the `Via` loop marker, the safe-path rule) is `access_gate_gateway_core::headers`, shared with the
//! Cloudflare Worker; this module only walks a native header map with it.

use access_gate_gateway_core::headers::{
    connection_named, drop_request_header, drop_response_header, VIA_TOKEN,
};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue};

/// The values of `Connection`, joined: the fields it names are hop-by-hop for this message.
fn named_by_connection(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(connection_named)
        .collect()
}

fn retain(headers: &HeaderMap, drop: impl Fn(&str, &[String]) -> bool) -> HeaderMap {
    let named = named_by_connection(headers);
    let doomed: Vec<HeaderName> = headers
        .keys()
        .filter(|k| drop(k.as_str(), &named))
        .cloned()
        .collect();
    let mut out = headers.clone();
    for k in doomed {
        out.remove(k);
    }
    out
}

/// The headers to send upstream: the client's, minus hop-by-hop, credentials and spoofable fields.
/// The upstream's own access credentials (`cf-access-*`) are the gateway's alone, so anything the
/// client sent in that namespace is dropped (the configured ones are added by the HTTP client).
pub fn upstream_request_headers(incoming: &HeaderMap) -> HeaderMap {
    let mut headers = retain(incoming, drop_request_header);
    // The gateway's own hop marker, set after the client's `via` was dropped (F43).
    headers.insert(header::VIA, HeaderValue::from_static(VIA_TOKEN));
    headers
}

/// The headers to return to the client: the upstream's, minus hop-by-hop, cookies and CORS fields.
pub fn client_response_headers(upstream: &HeaderMap) -> HeaderMap {
    retain(upstream, drop_response_header)
}

/// All `Via` field values joined with `,` (what `access_gate_gateway_core::headers::via_is_looped` reads).
pub fn joined(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<&str> = headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    (!values.is_empty()).then(|| values.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use access_gate_gateway_core::headers::via_is_looped;

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

    /// Several `Via` fields are read as one list.
    #[test]
    fn via_fields_are_joined_and_the_marker_is_the_one_the_gateway_refuses() {
        let mut h = map(&[("via", "1.1 google")]);
        h.append("via", HeaderValue::from_static("1.1 nft-gate"));
        assert_eq!(
            joined(&h, "via").as_deref(),
            Some("1.1 google,1.1 nft-gate")
        );
        assert!(via_is_looped(&joined(&h, "via").unwrap()));
        assert_eq!(joined(&HeaderMap::new(), "via"), None);
        assert!(via_is_looped(
            &joined(
                &upstream_request_headers(&map(&[("via", "1.1 google")])),
                "via"
            )
            .unwrap()
        ));
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
}
