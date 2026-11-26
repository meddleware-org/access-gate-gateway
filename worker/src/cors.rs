//! CORS policy (parity with `gateway-workers/src/cors.ts`): only an exact `ALLOWED_ORIGINS` match is
//! reflected, the same four grants and `Vary: Origin` ride on every response (errors included), and a
//! preflight is answered before any other work. The lists live in `access_gate_gateway_core::headers`.

use access_gate_gateway_core::headers::CORS_GRANTS;

/// The grants every response carries (name, value).
pub fn grants() -> &'static [(&'static str, &'static str)] {
    // The core owns the list, so the Worker and the native server cannot disagree.
    &CORS_GRANTS
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;
    use access_gate_gateway_core::headers::cors_allowed_origin;

    /// Only an exact allow list match is reflected.
    #[test]
    fn only_an_exact_allow_list_match_is_reflected() {
        // One allowed origin.
        let allowed = vec!["https://a.example".to_string()];
        assert_eq!(
            cors_allowed_origin(Some("https://a.example"), &allowed),
            Some("https://a.example")
        );
        assert_eq!(
            // An origin not on the list gets no grant.
            cors_allowed_origin(Some("https://evil.example"), &allowed),
            None
        );
        assert_eq!(
            // A trailing slash makes it a different string, so it does not match: the comparison is exact.
            cors_allowed_origin(Some("https://a.example/"), &allowed),
            None
        );
        assert_eq!(cors_allowed_origin(None, &allowed), None);
        assert_eq!(cors_allowed_origin(Some("https://a.example"), &[]), None);
    }

    /// The four grants match the typescript worker.
    #[test]
    fn the_four_grants_match_the_typescript_worker() {
        let g = grants();
        // Four grants, no more: an extra one would widen what a browser may do.
        assert_eq!(g.len(), 4);
        assert!(g.contains(&(
            "access-control-allow-methods",
            "GET, POST, PUT, HEAD, OPTIONS"
        )));
        assert!(g.contains(&(
            "access-control-allow-headers",
            "authorization, content-type, x-access-proof"
        )));
        assert!(g.contains(&("access-control-expose-headers", "location, upload-offset")));
        assert!(g.contains(&("access-control-max-age", "86400")));
    }
}
